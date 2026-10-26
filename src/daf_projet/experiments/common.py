"""Shared experiment plumbing: prepared data, model zoo, timing."""

from __future__ import annotations

import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from ..data import BENIGN, build_pipeline, dedupe, load_dataset
from ..metrics import evaluate

PROJECT_ROOT = Path(__file__).resolve().parents[3]
RESULTS_DIR = PROJECT_ROOT / "results"
FIGURES_DIR = PROJECT_ROOT / "figures"

DISPLAY_NAMES = {
    "dummy": "Dummy (stratified)",
    "logreg": "Logistic regression",
    "random_forest": "Random forest",
}


def load_deduped(data_dir: str | Path | None = None):
    """Load, dedupe and re-align the audit frame.

    The binary target is derived *after* dedupe from the family label, so the
    majority-label rule can never assign a row a binary target that disagrees
    with its family target.
    """
    X, y_family, _, meta = load_dataset(data_dir)
    X, y_family = dedupe(X, y_family)
    kept = X.attrs["kept_positions"]
    meta = meta.iloc[kept].reset_index(drop=True)
    # Keep only simple attrs: pandas concat compares .attrs and chokes on the
    # numpy arrays stored by the audit.
    X.attrs = {"feature_names": list(X.columns)}
    y_binary = (y_family != BENIGN).astype("int8").rename("binary")
    return X, y_family, y_binary, meta


def make_models(
    seed: int = 42,
    names: list[str] | None = None,
    *,
    n_estimators: int = 300,
) -> dict[str, object]:
    """Three comparable pipelines, all with the same preprocessing."""
    available = {
        "dummy": DummyClassifier(strategy="stratified", random_state=seed),
        "logreg": LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=seed,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=n_estimators,
            class_weight="balanced",
            n_jobs=-1,
            random_state=seed,
        ),
    }
    names = names or list(available)
    missing = set(names) - set(available)
    if missing:
        raise ValueError(f"unknown models: {sorted(missing)}")
    return {name: build_pipeline(available[name]) for name in names}


def fit_and_score(
    pipeline,
    X_train,
    y_train,
    X_test,
    y_test,
    *,
    target_tpr: float = 0.95,
) -> dict:
    """Fit once, then collect metrics, predictions and wall-clock timings."""
    start = time.perf_counter()
    pipeline.fit(X_train, y_train)
    fit_seconds = time.perf_counter() - start

    start = time.perf_counter()
    y_pred = pipeline.predict(X_test)
    predict_seconds = time.perf_counter() - start
    y_proba = pipeline.predict_proba(X_test)

    classes = list(pipeline.named_steps["clf"].classes_)
    metrics = evaluate(
        y_test,
        y_pred,
        y_proba,
        classes,
        target_tpr=target_tpr,
    )
    return {
        "metrics": metrics,
        "y_pred": np.asarray(y_pred),
        "y_proba": np.asarray(y_proba),
        "classes": classes,
        "fit_seconds": float(fit_seconds),
        "predict_seconds": float(predict_seconds),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "n_features_in": int(X_train.shape[1]),
        "n_features_effective": int(
            getattr(pipeline.named_steps["drop_dead_features"], "support_", np.ones(X_train.shape[1])).sum()
        ),
    }


def metrics_row(metrics: dict, **extra) -> dict:
    """Flatten the scalar part of an :func:`evaluate` result."""
    row = {
        "n_test": metrics["n_test"],
        "n_classes": metrics["n_classes"],
        "macro_f1": metrics["macro_f1"],
        "weighted_f1": metrics["weighted_f1"],
        "accuracy": metrics["accuracy"],
        "pr_auc": metrics["pr_auc"],
        "roc_auc": metrics["roc_auc"],
        "fpr": metrics["fpr"],
        "fpr_at_tpr95": metrics["fpr_at_tpr95"],
    }
    row.update(extra)
    return row


def ensure_dirs() -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    FIGURES_DIR.mkdir(exist_ok=True)


def median_latency_ms(pipeline, X_batch, repeats: int = 5) -> float:
    """Median wall-clock milliseconds for one batch prediction.

    One warm-up call is excluded; the median is robust to a noisy laptop.
    """
    pipeline.predict(X_batch)
    timings = []
    for _ in range(repeats):
        start = time.perf_counter()
        pipeline.predict(X_batch)
        timings.append((time.perf_counter() - start) * 1000.0)
    return float(np.median(timings))
