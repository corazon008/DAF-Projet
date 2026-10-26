"""Metrics that survive class imbalance and never hide behind accuracy.

Accuracy is returned for completeness but is not used to conclude anything:
with 13--17 classes and a 45 % Benign share it is easy to look good while
missing every rare attack.  Macro-F1, per-class recall, PR-AUC, ROC-AUC and
FPR at 95 % recall are the decision metrics.
"""

from __future__ import annotations

from typing import Iterable, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix as sklearn_confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)

TARGET_TPR = 0.95


def _proba_matrix(y_proba, classes: Sequence) -> np.ndarray:
    """Return an (n_samples, n_classes) score matrix in ``classes`` order."""
    classes = list(classes)
    if isinstance(y_proba, pd.DataFrame):
        missing = set(classes) - set(y_proba.columns)
        if missing:
            raise ValueError(f"probability frame is missing classes: {sorted(missing)}")
        array = y_proba.loc[:, classes].to_numpy(dtype=float)
    else:
        array = np.asarray(y_proba, dtype=float)

    if array.ndim == 1:
        if len(classes) != 2:
            raise ValueError(
                "a 1-D score vector is only valid for binary classification"
            )
        array = np.column_stack([1.0 - array, array])
    if array.ndim != 2 or array.shape[1] != len(classes):
        raise ValueError(
            f"expected scores with {len(classes)} columns, got shape {array.shape}"
        )
    return array


def _fpr_at_tpr(tpr_target: float, y_true_binary: np.ndarray, scores: np.ndarray) -> float:
    fpr, tpr, _ = roc_curve(y_true_binary, scores)
    # roc_curve returns a monotone tpr; interpolate the smallest FPR reaching
    # the target recall.  Both classes must be present for this to be defined.
    return float(np.interp(tpr_target, tpr, fpr))


def evaluate(
    y_true,
    y_pred,
    y_proba,
    classes: Iterable,
    *,
    target_tpr: float = TARGET_TPR,
) -> dict:
    """Compute the full metric bundle.

    Parameters
    ----------
    y_true, y_pred : array-like
    y_proba : array-like or DataFrame
        Scores.  For binary, either a 1-D vector of positive-class scores or a
        two-column matrix.  For multiclass, one column per class in ``classes``
        order.
    classes : iterable
        Explicit class order.  This is what stops label ordering from drifting
        between notebooks and result files.
    """
    classes = list(classes)
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    scores = _proba_matrix(y_proba, classes)

    macro_f1 = f1_score(
        y_true, y_pred, labels=classes, average="macro", zero_division=0
    )
    weighted_f1 = f1_score(
        y_true, y_pred, labels=classes, average="weighted", zero_division=0
    )
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=classes, average=None, zero_division=0
    )

    per_class_rows = []
    for index, label in enumerate(classes):
        binary_true = (y_true == label).astype(int)
        binary_pred = (y_pred == label).astype(int)
        tp = int(((binary_true == 1) & (binary_pred == 1)).sum())
        fp = int(((binary_true == 0) & (binary_pred == 1)).sum())
        tn = int(((binary_true == 0) & (binary_pred == 0)).sum())
        fn = int(((binary_true == 1) & (binary_pred == 0)).sum())
        row = {
            "class": label,
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
            "support": int(support[index]),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "fpr": float(fp / (fp + tn)) if (fp + tn) else np.nan,
            "specificity": float(tn / (tn + fp)) if (tn + fp) else np.nan,
            "pr_auc": np.nan,
            "roc_auc": np.nan,
            "fpr_at_tpr95": np.nan,
        }
        if row["support"] > 0 and 0 < binary_true.sum() < len(binary_true):
            row["pr_auc"] = float(
                average_precision_score(binary_true, scores[:, index])
            )
            row["roc_auc"] = float(roc_auc_score(binary_true, scores[:, index]))
            row["fpr_at_tpr95"] = _fpr_at_tpr(
                target_tpr, binary_true, scores[:, index]
            )
        per_class_rows.append(row)

    per_class = pd.DataFrame(per_class_rows).set_index("class", drop=False)
    per_class.index.name = None

    def _nanmean(column: str) -> float:
        values = per_class[column].to_numpy(dtype=float)
        return float(np.nanmean(values)) if np.isfinite(values).any() else float("nan")

    # For binary, the headline PR/ROC-AUC are those of the attack class; the
    # macro value would average in the easy Benign class.
    binary = len(classes) == 2
    if binary:
        positive = per_class.iloc[1]
        pr_auc = float(positive["pr_auc"])
        roc_auc = float(positive["roc_auc"])
        fpr_at_tpr95 = float(positive["fpr_at_tpr95"])
        fpr = float(positive["fpr"])
    else:
        pr_auc = _nanmean("pr_auc")
        roc_auc = _nanmean("roc_auc")
        fpr_at_tpr95 = _nanmean("fpr_at_tpr95")
        fpr = _nanmean("fpr")

    return {
        "n_test": int(len(y_true)),
        "n_classes": len(classes),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "fpr": fpr,
        "fpr_at_tpr95": fpr_at_tpr95,
        "per_class": per_class,
    }


def confusion_matrix(y_true, y_pred, labels: Iterable) -> pd.DataFrame:
    """Confusion matrix as a labelled DataFrame, order fixed by ``labels``."""
    labels = list(labels)
    matrix = sklearn_confusion_matrix(y_true, y_pred, labels=labels)
    return pd.DataFrame(
        matrix,
        index=pd.Index(labels, name="true"),
        columns=pd.Index(labels, name="pred"),
    )


def confusion_to_matrix(
    y_true_family,
    y_pred_known,
    known_families: Iterable,
    held_out_families: Iterable | None = None,
    *,
    normalize: str | None = None,
) -> pd.DataFrame:
    """Rows = unseen family, columns = known family it was mistaken for.

    This is the headline artefact of Experiment 2.  A binary detector can only
    say "attack"; to learn *which known family* an unseen attack resembles, run
    the unseen rows through a multiclass model trained on the remaining
    families and tabulate its predictions here.

    ``normalize="row"`` turns counts into a row-wise rate, which is easier to
    compare across families with very different support.
    """
    y_true_family = pd.Series(np.asarray(y_true_family), name="held_out")
    y_pred_known = pd.Series(np.asarray(y_pred_known), name="predicted")
    if held_out_families is None:
        index = sorted(y_true_family.unique())
    else:
        index = list(held_out_families)
    columns = list(known_families)

    table = pd.crosstab(y_true_family, y_pred_known)
    table = table.reindex(index=index, columns=columns, fill_value=0)
    table.index.name = "held_out_family"
    table.columns.name = "predicted_known_family"

    if normalize is None:
        return table.astype(int)
    if normalize == "row":
        row_sums = table.sum(axis=1).replace(0, np.nan)
        return table.div(row_sums, axis=0).fillna(0.0)
    raise ValueError("normalize must be None or 'row'")


__all__ = ["TARGET_TPR", "confusion_matrix", "confusion_to_matrix", "evaluate"]
