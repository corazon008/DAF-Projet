"""Experiment 2 — Leave-One-Attack-Out (LOADO).

H2: generalisation to an unseen family depends strongly on which family is
held out.

Protocol per rotation:

1. Purge the held-out family from the *whole concatenated dataset*.  This is
   essential because the 17 source files are not pure: ``UDPLag-training``
   contains Syn and UDP, ``LDAP-training`` contains NetBIOS, etc.  Purging only
   the file named after the family would leave same-family rows in training and
   make the "unseen" claim false.
2. Re-split the remaining rows with the same seed, so only the family changes.
3. Train a binary Benign/DDoS detector on the remaining families.
4. Test on held-out family rows plus a matched Benign sample drawn only from
   the known test fold.  The test set is balanced 1:1 (or the largest possible
   balanced sample for very large families).
5. Fit a lighter multiclass "known-family" model on the same training rows and
   predict the held-out rows.  This fills ``confusion_to_matrix``: which known
   family does the unseen attack resemble?
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier

from ..data import BENIGN, build_pipeline, purge_family, split, subsample
from ..metrics import confusion_matrix, confusion_to_matrix
from .common import (
    DISPLAY_NAMES,
    RESULTS_DIR,
    ensure_dirs,
    fit_and_score,
    load_deduped,
    make_models,
    metrics_row,
)

CLASSES = [0, 1]


def _balanced_test(held_X, held_y, X_known_test, y_known_test, seed: int):
    """Held-out family rows + matched Benign rows from the known test fold."""
    benign_index = y_known_test.index[y_known_test == BENIGN].to_numpy()
    n = min(len(held_X), len(benign_index))
    if n == 0:
        raise ValueError("no held-out or benign rows available")

    rng = np.random.default_rng(seed)
    if len(held_X) > n:
        held_positions = rng.choice(len(held_X), size=n, replace=False)
    else:
        held_positions = np.arange(len(held_X))
    if len(benign_index) > n:
        benign_positions = rng.choice(benign_index, size=n, replace=False)
    else:
        benign_positions = benign_index

    X_attack = held_X.iloc[held_positions].reset_index(drop=True).copy()
    X_benign = X_known_test.loc[benign_positions].reset_index(drop=True).copy()
    # pandas compares .attrs on concat; our audit attrs contain arrays, so clear
    # them before mixing the two frames.
    X_attack.attrs = {}
    X_benign.attrs = {}
    X_eval = pd.concat([X_attack, X_benign], ignore_index=True)
    y_eval = np.concatenate(
        [np.ones(len(X_attack), dtype=np.int8), np.zeros(len(X_benign), dtype=np.int8)]
    )
    return X_eval, y_eval, X_attack, held_y.iloc[held_positions].reset_index(drop=True)


def _known_family_attribution(
    X_train,
    y_train,
    X_attack,
    family: str,
    known_classes: list[str],
    seed: int,
) -> pd.DataFrame:
    """Light multiclass model used only to attribute unseen attacks."""
    diag_train = subsample(X_train, y_train, cap=5_000, seed=seed)
    clf = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        n_jobs=-1,
        random_state=seed,
    )
    pipeline = build_pipeline(clf)
    pipeline.fit(*diag_train)
    predicted = pipeline.predict(X_attack)
    matrix = confusion_to_matrix(
        [family] * len(predicted),
        predicted,
        known_classes,
        held_out_families=[family],
    )
    return matrix.stack().rename("count").reset_index()


def main(args: argparse.Namespace) -> int:
    ensure_dirs()
    X, y_family, _, meta = load_deduped(args.data_dir)
    counts = y_family.value_counts()
    families = sorted(
        label
        for label in counts.index
        if label != BENIGN and counts[label] >= args.min_rows
    )
    if not families:
        raise ValueError("no attack families above the minimum row count")

    print(f"{len(families)} held-out families (>= {args.min_rows} rows after dedupe):")
    for family in families:
        print(f"  {family:16s} {counts[family]:7,}")

    audit = (
        meta.loc[meta["label"].isin(families)]
        .groupby(["label", "src_file"], observed=True)
        .size()
        .reset_index(name="rows")
        .rename(columns={"label": "family"})
    )
    audit.to_csv(RESULTS_DIR / "exp2_purge_audit.csv", index=False)

    rows = []
    per_class_rows = []
    confusion_to_rows = []
    diagnostic_seed = args.seeds[0]

    for seed in args.seeds:
        print(f"\n===== seed {seed} =====")
        for family in families:
            X_pool, y_pool, held_X, held_y = purge_family(X, y_family, family)
            X_known_train, X_known_test, y_known_train, y_known_test = split(
                X_pool, y_pool, seed=seed
            )
            if args.cap:
                X_known_train, y_known_train = subsample(
                    X_known_train, y_known_train, cap=args.cap, seed=seed
                )
            y_binary_train = (y_known_train != BENIGN).astype("int8")
            X_eval, y_eval, X_attack, _ = _balanced_test(
                held_X, held_y, X_known_test, y_known_test, seed
            )

            for name, pipeline in make_models(
                seed=seed, names=args.models
            ).items():
                result = fit_and_score(
                    pipeline, X_known_train, y_binary_train, X_eval, y_eval
                )
                metrics = result["metrics"]
                rows.append(
                    metrics_row(
                        metrics,
                        family=family,
                        seed=seed,
                        model=name,
                        model_display=DISPLAY_NAMES[name],
                        sklearn_version=sklearn.__version__,
                        n_family_available=int(len(held_X)),
                        n_test_heldout=int(y_eval.sum()),
                        n_test_benign=int((y_eval == 0).sum()),
                        n_train=result["n_train"],
                        n_features_effective=result["n_features_effective"],
                        fit_seconds=result["fit_seconds"],
                        predict_seconds=result["predict_seconds"],
                        recall_family=float(metrics["per_class"].loc[1, "recall"]),
                        fpr=float(metrics["fpr"]),
                    )
                )
                per_class = metrics["per_class"].copy()
                per_class.insert(0, "family", family)
                per_class.insert(1, "model", name)
                per_class.insert(2, "seed", seed)
                per_class_rows.append(per_class)
                confusion_matrix(y_eval, result["y_pred"], CLASSES).to_csv(
                    RESULTS_DIR / f"exp2_confusion_{family}_{name}_s{seed}.csv"
                )
                print(
                    f"  {family:16s} {name:14s} macro-F1={metrics['macro_f1']:.3f} "
                    f"recall_F={metrics['per_class'].loc[1, 'recall']:.3f} "
                    f"FPR={metrics['fpr']:.3f}"
                )

            if seed == diagnostic_seed:
                known_classes = sorted(y_known_train.unique().tolist())
                table = _known_family_attribution(
                    X_known_train,
                    y_known_train,
                    X_attack,
                    family,
                    known_classes,
                    seed,
                )
                table.insert(0, "seed", seed)
                confusion_to_rows.append(table)
                print(f"  {family:16s} attribution matrix filled")

    results = pd.DataFrame(rows)
    results.to_csv(RESULTS_DIR / "exp2.csv", index=False)
    pd.concat(per_class_rows, ignore_index=True).to_csv(
        RESULTS_DIR / "exp2_per_class.csv", index=False
    )
    if confusion_to_rows:
        pd.concat(confusion_to_rows, ignore_index=True).to_csv(
            RESULTS_DIR / "exp2_confusion_to.csv", index=False
        )

    summary = (
        results.groupby(["family", "model"], observed=True)["macro_f1"]
        .agg(["mean", "std"])
        .reset_index()
    )
    print("\nMacro-F1 by held-out family (mean over seeds):")
    print(summary.pivot(index="family", columns="model", values="mean").round(3).to_string())
    print(f"\nwrote {RESULTS_DIR / 'exp2.csv'} ({len(results)} fits)")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    parser.add_argument("--cap", type=int, default=None)
    parser.add_argument("--min-rows", type=int, default=1_000)
    parser.add_argument("--models", nargs="+", default=None)
    raise SystemExit(main(parser.parse_args()))
