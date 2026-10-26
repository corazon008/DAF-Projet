"""Experiment 1 — binary Benign/DDoS vs 13-class attack-family classification.

H1: the multiclass task is harder than the binary task.

The split is created once, on the fine-grained family target, and reused for
all three tasks.  That is what makes the comparison "only the target changes".
The third task removes ``Protocol``: protocol is almost family-deterministic
(Syn 99.8 % TCP, MSSQL/UDP ~100 % UDP), so the delta measures how much of the
multiclass score is a protocol lookup rather than flow-shape recognition.
"""

from __future__ import annotations

import argparse

import pandas as pd
import sklearn

from ..data import group_attack_families, split, subsample
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


def _prepare_tasks(X_train, X_test, y_family_train, y_family_test):
    y_binary_train = (y_family_train != "Benign").astype("int8")
    y_binary_test = (y_family_test != "Benign").astype("int8")
    y_group_train = group_attack_families(y_family_train)
    y_group_test = group_attack_families(y_family_test)
    classes = sorted(y_group_train.unique())

    return [
        {
            "task": "binary",
            "label": "Benign / DDoS",
            "X_train": X_train,
            "X_test": X_test,
            "y_train": y_binary_train,
            "y_test": y_binary_test,
            "classes": [0, 1],
        },
        {
            "task": "multiclass",
            "label": "13-class (12 attack types + Benign)",
            "X_train": X_train,
            "X_test": X_test,
            "y_train": y_group_train,
            "y_test": y_group_test,
            "classes": classes,
        },
        {
            "task": "multiclass_no_protocol",
            "label": "13-class without Protocol",
            "X_train": X_train.drop(columns=["Protocol"]),
            "X_test": X_test.drop(columns=["Protocol"]),
            "y_train": y_group_train,
            "y_test": y_group_test,
            "classes": classes,
        },
    ]


def main(args: argparse.Namespace) -> int:
    ensure_dirs()
    seed = args.seed
    X, y_family, _, _ = load_deduped(args.data_dir)
    X_train, X_test, y_family_train, y_family_test = split(X, y_family, seed=seed)
    if args.cap:
        X_train, y_family_train = subsample(
            X_train, y_family_train, cap=args.cap, seed=seed
        )
        y_family_test = y_family_test  # test stays complete

    tasks = _prepare_tasks(X_train, X_test, y_family_train, y_family_test)

    rows = []
    per_class_rows = []
    for task in tasks:
        print(f"\n== {task['task']} ({task['label']}) ==")
        for name, pipeline in make_models(seed=seed).items():
            result = fit_and_score(
                pipeline,
                task["X_train"],
                task["y_train"],
                task["X_test"],
                task["y_test"],
            )
            metrics = result["metrics"]
            rows.append(
                metrics_row(
                    metrics,
                    task=task["task"],
                    task_label=task["label"],
                    model=name,
                    model_display=DISPLAY_NAMES[name],
                    seed=seed,
                    sklearn_version=sklearn.__version__,
                    fit_seconds=result["fit_seconds"],
                    predict_seconds=result["predict_seconds"],
                    n_train=result["n_train"],
                    n_features_in=result["n_features_in"],
                    n_features_effective=result["n_features_effective"],
                )
            )
            per_class = metrics["per_class"].copy()
            per_class.insert(0, "task", task["task"])
            per_class.insert(1, "model", name)
            per_class.insert(2, "seed", seed)
            per_class_rows.append(per_class)
            confusion_matrix(
                task["y_test"], result["y_pred"], task["classes"]
            ).to_csv(RESULTS_DIR / f"exp1_confusion_{task['task']}_{name}.csv")
            print(
                f"{name:14s} macro-F1={metrics['macro_f1']:.4f} "
                f"weighted-F1={metrics['weighted_f1']:.4f} "
                f"acc={metrics['accuracy']:.4f} "
                f"({result['fit_seconds']:.1f}s)"
            )

    results = pd.DataFrame(rows)
    results.to_csv(RESULTS_DIR / "exp1.csv", index=False)
    pd.concat(per_class_rows, ignore_index=True).to_csv(
        RESULTS_DIR / "exp1_per_class.csv", index=False
    )

    pivot = results.pivot(index="task", columns="model", values="macro_f1")
    print("\nMacro-F1 by task/model:")
    print(pivot.round(4).to_string())
    print(f"\nwrote {RESULTS_DIR / 'exp1.csv'}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cap", type=int, default=None)
    raise SystemExit(main(parser.parse_args()))
