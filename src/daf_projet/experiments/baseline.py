"""Phase 2 — binary Benign/DDoS baselines.

The floor is a stratified dummy.  Logistic regression and a random forest are
the two reference models used again in Experiments 1--3.  No test row is used to
tune anything: the split is fixed by seed before the first fit.
"""

from __future__ import annotations

import argparse

import numpy as np
import pandas as pd
import sklearn

from ..data import split, subsample
from ..metrics import confusion_matrix
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
CLASS_NAMES = {0: "Benign", 1: "DDoS"}


def main(args: argparse.Namespace) -> int:
    ensure_dirs()
    seed = args.seed
    X, y_family, y_binary, _ = load_deduped(args.data_dir)
    # One canonical split on the fine-grained family target, reused by every
    # experiment.  The binary target is derived from the same rows, so binary
    # and multiclass results are not compared on different test sets.
    X_train, X_test, y_family_train, y_family_test = split(X, y_family, seed=seed)
    y_train = (y_family_train != "Benign").astype("int8")
    y_test = (y_family_test != "Benign").astype("int8")
    if args.cap:
        X_train, y_train = subsample(X_train, y_train, cap=args.cap, seed=seed)

    rows = []
    per_class_rows = []
    for name, pipeline in make_models(seed=seed).items():
        result = fit_and_score(pipeline, X_train, y_train, X_test, y_test)
        metrics = result["metrics"]
        rows.append(
            metrics_row(
                metrics,
                model=name,
                model_display=DISPLAY_NAMES[name],
                seed=seed,
                sklearn_version=sklearn.__version__,
                fit_seconds=result["fit_seconds"],
                predict_seconds=result["predict_seconds"],
                n_train=result["n_train"],
                n_features_effective=result["n_features_effective"],
            )
        )

        per_class = metrics["per_class"].copy()
        per_class.insert(0, "model", name)
        per_class.insert(1, "seed", seed)
        per_class_rows.append(per_class)

        matrix = confusion_matrix(y_test, result["y_pred"], CLASSES)
        matrix.to_csv(RESULTS_DIR / f"baseline_confusion_{name}.csv")
        print(
            f"{name:14s} macro-F1={metrics['macro_f1']:.4f} "
            f"recall_DDoS={metrics['per_class'].loc[1, 'recall']:.4f} "
            f"FPR={metrics['fpr']:.4f} "
            f"({result['fit_seconds']:.1f}s fit)"
        )

    results = pd.DataFrame(rows)
    results.to_csv(RESULTS_DIR / "baseline_binary.csv", index=False)
    pd.concat(per_class_rows, ignore_index=True).to_csv(
        RESULTS_DIR / "baseline_binary_per_class.csv", index=False
    )

    dummy = results.loc[results["model"] == "dummy", "macro_f1"]
    if len(dummy):
        print(f"\nDummy macro-F1 = {dummy.iloc[0]:.4f} (binary floor, not 1/13)")
    print(f"wrote {RESULTS_DIR / 'baseline_binary.csv'}")
    return 0


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cap", type=int, default=None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    add_arguments(parser)
    raise SystemExit(main(parser.parse_args()))
