"""Experiment 3 — feature reduction, performance and inference latency.

H3: a fraction of the 77 features retains most of the performance.

Selection is fitted *inside* the training fold.  ``mutual_info_classif`` is the
primary method; random-forest impurity importance is the cross-check.  Five
variants are compared: all features, ~75 %, ~50 %, ~25 % and Top-10.  Inference
latency is measured on a 1,000-row batch, median of five repetitions, because
Q4 is about real-time use, not only accuracy.
"""

from __future__ import annotations

import argparse
from functools import partial

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ..data import BENIGN, DropConstantFeatures, group_attack_families, split, subsample
from ..metrics import confusion_matrix
from .common import (
    RESULTS_DIR,
    ensure_dirs,
    fit_and_score,
    load_deduped,
    median_latency_ms,
    metrics_row,
)

LATENCY_BATCH = 1_000
REPEATS = 5
VARIANTS = {
    "all": None,
    "75pct": 58,
    "50pct": 39,
    "25pct": 20,
    "top10": 10,
}


def _make_pipeline(k: int | None, seed: int):
    steps = [("drop_dead_features", DropConstantFeatures())]
    if k is not None:
        steps.append(
            (
                "select",
                SelectKBest(
                    score_func=partial(mutual_info_classif, random_state=seed),
                    k=k,
                ),
            )
        )
    steps.extend(
        [
            ("scale", StandardScaler()),
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=300,
                    class_weight="balanced",
                    n_jobs=-1,
                    random_state=seed,
                ),
            ),
        ]
    )
    return Pipeline(steps)


def _effective_features(pipeline, n_input: int) -> int:
    drop = pipeline.named_steps["drop_dead_features"]
    count = int(getattr(drop, "support_", np.ones(n_input, dtype=bool)).sum())
    if "select" in pipeline.named_steps:
        count = int(pipeline.named_steps["select"].get_support().sum())
    return count


def _ranking_rows(X_train, y_train, seed: int, task: str) -> tuple[pd.DataFrame, pd.Series]:
    mi = mutual_info_classif(
        X_train, y_train, discrete_features=False, random_state=seed
    )
    mi = pd.Series(mi, index=X_train.columns, name="mutual_info")
    rf = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        n_jobs=-1,
        random_state=seed,
    )
    rf.fit(X_train, y_train)
    importance = pd.Series(rf.feature_importances_, index=X_train.columns, name="rf_importance")
    table = pd.concat([mi, importance], axis=1)
    table["mi_rank"] = table["mutual_info"].rank(ascending=False, method="min").astype(int)
    table["rf_rank"] = table["rf_importance"].rank(ascending=False, method="min").astype(int)
    table.insert(0, "task", task)
    table.insert(0, "seed", seed)
    table = table.reset_index().rename(columns={"index": "feature"})
    return table, mi.sort_values(ascending=False)


def main(args: argparse.Namespace) -> int:
    ensure_dirs()
    X, y_family, _, _ = load_deduped(args.data_dir)

    ranking_tables = []
    selected_rows = []
    rows = []
    for seed in args.seeds:
        print(f"\n===== seed {seed} =====")
        X_train, X_test, y_family_train, y_family_test = split(
            X, y_family, seed=seed
        )
        if args.cap:
            X_train, y_family_train = subsample(
                X_train, y_family_train, cap=args.cap, seed=seed
            )

        tasks = {
            "binary": (
                (y_family_train != BENIGN).astype("int8"),
                (y_family_test != BENIGN).astype("int8"),
                [0, 1],
            ),
            "multiclass": (
                group_attack_families(y_family_train),
                group_attack_families(y_family_test),
                sorted(group_attack_families(y_family_train).unique()),
            ),
        }

        for task, (y_train, y_test, classes) in tasks.items():
            ranking, mi_sorted = _ranking_rows(X_train, y_train, seed, task)
            ranking_tables.append(ranking)
            if seed == args.seeds[0]:
                print(f"\n== {task}: top 10 by mutual information ==")
                print(mi_sorted.head(10).round(4).to_string())

            for variant, k in VARIANTS.items():
                pipeline = _make_pipeline(k, seed)
                result = fit_and_score(pipeline, X_train, y_train, X_test, y_test)
                metrics = result["metrics"]
                latency = median_latency_ms(
                    pipeline, X_test.iloc[:LATENCY_BATCH], repeats=REPEATS
                )
                n_effective = _effective_features(pipeline, X_train.shape[1])

                if k is not None:
                    selector = pipeline.named_steps["select"]
                    drop_support = pipeline.named_steps[
                        "drop_dead_features"
                    ].support_
                    kept_names = X_train.columns[drop_support]
                    chosen = kept_names[selector.get_support()]
                    selected_rows.extend(
                        {
                            "task": task,
                            "variant": variant,
                            "seed": seed,
                            "feature": feature,
                            "rank": rank,
                        }
                        for rank, feature in enumerate(chosen, start=1)
                    )

                rows.append(
                    metrics_row(
                        metrics,
                        task=task,
                        variant=variant,
                        k_requested=k,
                        model="random_forest",
                        seed=seed,
                        sklearn_version=sklearn.__version__,
                        n_train=result["n_train"],
                        n_features_in=result["n_features_in"],
                        n_features_effective=n_effective,
                        fit_seconds=result["fit_seconds"],
                        predict_seconds=result["predict_seconds"],
                        latency_ms_1000=latency,
                        throughput_flows_s=1_000.0 / (latency / 1000.0),
                    )
                )
                confusion_matrix(y_test, result["y_pred"], classes).to_csv(
                    RESULTS_DIR / f"exp3_confusion_{task}_{variant}_s{seed}.csv"
                )
                print(
                    f"{task:10s} {variant:6s} k={n_effective:3d} "
                    f"macro-F1={metrics['macro_f1']:.4f} "
                    f"latency={latency:.2f} ms/1k"
                )

    results = pd.DataFrame(rows)
    results.to_csv(RESULTS_DIR / "exp3.csv", index=False)
    pd.concat(ranking_tables, ignore_index=True).to_csv(
        RESULTS_DIR / "exp3_feature_ranking.csv", index=False
    )
    if selected_rows:
        pd.DataFrame(selected_rows).to_csv(
            RESULTS_DIR / "exp3_selected_features.csv", index=False
        )

    print("\nMacro-F1 by variant/task (mean over seeds):")
    print(
        results.pivot_table(
            index="variant", columns="task", values="macro_f1", aggfunc="mean"
        )
        .round(4)
        .to_string()
    )
    print("\nLatency ms/1k by variant/task (median over seeds):")
    print(
        results.pivot_table(
            index="variant", columns="task", values="latency_ms_1000", aggfunc="median"
        )
        .round(2)
        .to_string()
    )
    print(f"\nwrote {RESULTS_DIR / 'exp3.csv'}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    parser.add_argument("--cap", type=int, default=20_000)
    raise SystemExit(main(parser.parse_args()))
