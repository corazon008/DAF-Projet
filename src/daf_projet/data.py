"""Dataset loading, leak-free deduplication and split utilities.

The CIC-DDoS2019 parquet files are *not* a random sample of DDoS traffic.  They
were released as a ``-training`` / ``-testing`` pair that partitions attack
mechanisms, and many rows are exact duplicates (including duplicates with
conflicting labels).  Everything in this module exists to make those two facts
explicit and neutralise them before any model is fitted.

Contract
--------
``load_dataset`` returns ``(X, y_family, y_binary, meta)``:

* ``X``          -- 77 numeric flow features, float64.
* ``y_family``   -- fine-grained label, 17 classes (12+ attack families plus
  Benign).  ``DrDoS_*`` labels are kept separate: a reflection attack and its
  exploitation counterpart are different mechanisms even when they share a
  packet template.
* ``y_binary``   -- 0 = Benign, 1 = DDoS.
* ``meta``       -- audit columns only (source file, original row id, raw
  label).  Never pass this to a model.

``dedupe`` hashes the 77 features and keeps one row per hash.  When a hash has
conflicting labels (5,289 groups in this dataset) the majority label wins;
ties are broken lexicographically.  This is deterministic and, unlike keeping
the first row, independent of file ordering.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.validation import check_is_fitted

BENIGN = "Benign"
BINARY_LABELS = (0, 1)
N_FILES = 17
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = PROJECT_ROOT / "dataset"
AUDIT_COLUMNS = ("__src_file", "__row_id", "__raw_label")


class DropConstantFeatures(BaseEstimator, TransformerMixin):
    """Drop columns that are constant on the training fold.

    This must be the first pipeline step, never a preprocessing step applied to
    the full frame: a column that is constant in train may vary in test, and
    using test to decide which columns to drop is leakage.

    The published CIC-DDoS2019 feature set contains 12 globally constant
    columns, not the 18 claimed in PLAN.md.  The transformer learns the actual
    list from the data, so the discrepancy cannot silently corrupt a run.
    """

    def __init__(self, threshold: int = 1) -> None:
        self.threshold = threshold

    def fit(self, X, y=None):  # noqa: N803 - sklearn API
        values = X if isinstance(X, pd.DataFrame) else pd.DataFrame(X)
        self.n_features_in_ = values.shape[1]
        if isinstance(X, pd.DataFrame):
            self.feature_names_in_ = np.asarray(X.columns, dtype=object)
        else:
            self.feature_names_in_ = np.asarray(
                [f"x{i}" for i in range(values.shape[1])], dtype=object
            )

        nunique = values.nunique(dropna=False)
        self.support_ = (nunique > self.threshold).to_numpy()
        self.constant_features_ = list(self.feature_names_in_[~self.support_])
        return self

    def transform(self, X):  # noqa: N803 - sklearn API
        check_is_fitted(self, "support_")
        if isinstance(X, pd.DataFrame):
            if X.shape[1] != len(self.support_):
                raise ValueError(
                    f"X has {X.shape[1]} columns, transformer was fitted on "
                    f"{len(self.support_)}"
                )
            return X.loc[:, self.support_].copy()
        return np.asarray(X)[:, self.support_]

    def get_feature_names_out(self, input_features: Iterable[str] | None = None):
        check_is_fitted(self, "support_")
        if input_features is None:
            names = self.feature_names_in_
        else:
            names = np.asarray(list(input_features), dtype=object)
        return names[self.support_]


def _as_series(y, index: pd.Index) -> pd.Series:
    if isinstance(y, pd.Series):
        if not y.index.equals(index):
            y = y.reindex(index)
        return y
    return pd.Series(np.asarray(y), index=index)


def _majority_label(values: pd.Series):
    """Most frequent label, ties broken lexicographically."""
    counts = values.value_counts(dropna=False)
    top = counts[counts == counts.max()].index
    if len(top) == 1:
        return top[0]
    return sorted(top, key=lambda value: str(value))[0]


def load_dataset(data_dir: str | Path | None = None):
    """Load the 17 parquet files and return X, y_family, y_binary, meta.

    The file partition is deliberately *not* returned as a split.  It is only
    kept in ``meta["src_file"]`` so the audit can show why using it would be a
    shortcut: it is organised by attack mechanism, not by random sampling.
    """
    data_dir = Path(data_dir) if data_dir is not None else DEFAULT_DATA_DIR
    files = sorted(data_dir.glob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"no parquet files found in {data_dir}")
    if len(files) != N_FILES:
        raise ValueError(
            f"expected {N_FILES} parquet files in {data_dir}, found {len(files)}"
        )

    frames: list[pd.DataFrame] = []
    for path in files:
        frame = pd.read_parquet(path)
        frame.columns = [str(column).strip() for column in frame.columns]
        frame[AUDIT_COLUMNS[0]] = path.name
        frame[AUDIT_COLUMNS[1]] = np.arange(len(frame), dtype=np.int64)
        frame[AUDIT_COLUMNS[2]] = frame["Label"]
        frames.append(frame)

    raw = pd.concat(frames, ignore_index=True)
    if "Label" not in raw.columns:
        raise ValueError("dataset has no Label column")

    raw["Label"] = raw["Label"].astype(str).str.strip()
    raw["Label"] = raw["Label"].replace({"UDP-lag": "UDPLag"})

    feature_names = [c for c in raw.columns if c not in (*AUDIT_COLUMNS, "Label")]
    if len(feature_names) != 77:
        raise ValueError(f"expected 77 features, found {len(feature_names)}")

    X = raw[feature_names].astype("float64")
    if not np.isfinite(X.to_numpy()).all():
        raise ValueError("features contain NaN or infinity")

    y_family = raw["Label"].astype("string").rename("family")
    y_binary = (y_family != BENIGN).astype("int8").rename("binary")

    meta = pd.DataFrame(
        {
            "src_file": raw["__src_file"].astype("string"),
            "row_id": raw["__row_id"].astype("int64"),
            "label_original": raw["__raw_label"].astype(str).str.strip(),
            "label": y_family.to_numpy(),
        },
        index=X.index,
    )

    counts = y_family.value_counts()
    X.attrs["feature_names"] = feature_names
    X.attrs["n_files"] = len(files)
    X.attrs["family_counts"] = counts.to_dict()
    X.attrs["n_rows"] = len(X)
    return X, y_family, y_binary, meta


def group_attack_families(y) -> pd.Series:
    """Collapse ``DrDoS_X`` onto ``X`` for the 12-attack-type multiclass task.

    ``load_dataset`` keeps reflection (``DrDoS_*``) and exploitation families
    separate because that separation is what Experiment 2 tests.  Experiment 1
    needs the conventional 12 CIC-DDoS2019 attack types, so it calls this
    helper.  ``Benign`` is unchanged, yielding 13 classes.
    """
    y = _as_series(y, pd.RangeIndex(len(y)) if not isinstance(y, pd.Series) else y.index)
    grouped = y.astype(str).str.replace(r"^DrDoS_", "", regex=True)
    return pd.Series(grouped.to_numpy(), index=y.index, name="family_grouped").astype(
        "string"
    )


def dedupe(X, y):
    """Collapse exact duplicate feature vectors to one labelled row.

    Returns ``(X_deduped, y_deduped)``.  Statistics are attached to
    ``X_deduped.attrs["dedupe"]`` for the audit notebook.
    """
    if not isinstance(X, pd.DataFrame):
        raise TypeError("X must be a pandas DataFrame so feature hashes are stable")
    y = _as_series(y, X.index)

    key = pd.Series(
        pd.util.hash_pandas_object(X, index=False), index=X.index, name="__hash"
    )
    grouped = y.groupby(key, sort=False)
    labels = grouped.first()
    n_labels = grouped.nunique(dropna=False)
    conflicts = n_labels[n_labels > 1].index

    if len(conflicts):
        subset = pd.DataFrame(
            {"__hash": key[key.isin(conflicts)], "y": y[key.isin(conflicts)]}
        )
        majority = subset.groupby("__hash", sort=False)["y"].agg(_majority_label)
        labels.loc[conflicts] = majority.reindex(conflicts)

    keep = ~key.duplicated(keep="first")
    X_out = X.loc[keep].reset_index(drop=True)
    y_out = pd.Series(
        labels.reindex(key.loc[keep]).to_numpy(),
        index=X_out.index,
        name=y.name,
    )

    X_out.attrs["feature_names"] = X.attrs.get(
        "feature_names", list(X.columns)
    )
    X_out.attrs["kept_positions"] = np.flatnonzero(keep.to_numpy())
    X_out.attrs["dedupe"] = {
        "rows_in": int(len(X)),
        "rows_out": int(len(X_out)),
        "rows_removed": int(len(X) - len(X_out)),
        "rows_in_duplicate_groups": int(key.duplicated(keep=False).sum()),
        "conflicting_hashes": int(len(conflicts)),
    }
    return X_out, y_out


def split(X, y, seed: int = 42, test_size: float = 0.2):
    """Stratified train/test split.  Call only after :func:`dedupe`."""
    y = _as_series(y, X.index)
    counts = y.value_counts()
    if (counts < 2).any():
        raise ValueError(
            "every class needs at least 2 rows for a stratified split; "
            f"smallest class has {int(counts.min())}"
        )
    return train_test_split(
        X,
        y,
        test_size=test_size,
        stratify=y,
        random_state=seed,
        shuffle=True,
    )


def subsample(X, y, cap: int = 20_000, seed: int = 42):
    """Stratified per-class cap, mainly for fast baseline/EDA runs."""
    y = _as_series(y, X.index)
    rng = np.random.default_rng(seed)
    picks: list[np.ndarray] = []
    for _, index in y.groupby(y, sort=False).groups.items():
        index = np.asarray(index)
        if len(index) > cap:
            index = rng.choice(index, size=cap, replace=False)
        picks.append(index)
    chosen = np.concatenate(picks)
    rng.shuffle(chosen)
    X_out = X.loc[chosen].reset_index(drop=True)
    y_out = y.loc[chosen].reset_index(drop=True)
    return X_out, y_out


def purge_family(X, y, family: str):
    """Remove every row belonging to ``family`` from a training frame.

    The dataset is already concatenated across all 17 files, so this purges
    the family from every file at once.  Deduplication guarantees one row per
    feature hash, which also removes exact feature-vector leakage across
    labels.
    """
    y = _as_series(y, X.index)
    held = y == family
    if not held.any():
        raise ValueError(f"family {family!r} not present")
    keep = ~held
    return (
        X.loc[keep].reset_index(drop=True),
        y.loc[keep].reset_index(drop=True),
        X.loc[held].reset_index(drop=True),
        y.loc[held].reset_index(drop=True),
    )


def build_pipeline(clf) -> Pipeline:
    """Drop constants, scale and classify -- all fitted on train only."""
    return Pipeline(
        [
            ("drop_dead_features", DropConstantFeatures()),
            ("scale", StandardScaler()),
            ("clf", clf),
        ]
    )


__all__ = [
    "BENIGN",
    "BINARY_LABELS",
    "DEFAULT_DATA_DIR",
    "DropConstantFeatures",
    "build_pipeline",
    "dedupe",
    "group_attack_families",
    "load_dataset",
    "purge_family",
    "split",
    "subsample",
]
