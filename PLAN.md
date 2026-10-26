# PLAN — DAF-Projet

Step-by-step build order. Each step lists what to do, how to check it worked, and what it
unblocks. Spec = `Projet.pdf` (4 pages). Data facts were measured on `dataset/*.parquet`.

Status legend: `[ ]` todo · `[~]` in progress · `[x]` done

---

## Step 0 — Environment

- [ ~ ] `uv add scikit-learn matplotlib seaborn`
- [x] `uv remove kaggle` (installed, unused — data is local)
- [ ] append to `.gitignore`: `dataset/*.zip`, `dataset/*.csv` (parquet is the source of truth)
- [ ] confirm versions: `uv pip list | grep -Ei "sklearn|scikit|matplotlib|numpy|pandas"`

Check: `scikit-learn 1.9.x`, `matplotlib 3.11.x`, `numpy 2.5.x`, `pandas 3.0.x` on Python 3.14.

Why: sklearn/matplotlib are **not installed** yet; everything downstream needs them.

---

## Step 1 — Data module

Create `src/daf_projet/data.py`. Five functions, in this order — the order matters.

- [ ] **`load_dataset()`** — read the 17 parquet, `Label.str.strip()`,
      map `UDP-lag` → `UDPLag`, keep `DrDoS_*` as its own family, keep `src_file` as a
      column for the audit only. Return `(X, y_family, y_binary, meta)`.
- [ ] **`dedupe(X, y)`** — hash the 77 features, drop duplicate rows.
- [ ] **`split(X, y, seed)`** — stratified 80/20 on the **deduped** frame.
- [ ] **`subsample(X, y, cap=20_000, seed)`** — stratified per-class cap.
- [ ] **`build_pipeline(clf)`** — `Pipeline([("scale", StandardScaler()), ("clf", clf)])`,
      plus `drop_dead_features` as a fit-on-train transformer.

Three non-negotiable rules encoded here, from spec §11:

1. **`dedupe` runs before `split`.** 21,347 rows are in exact-duplicate groups and 8,626
   feature-hashes appear in more than one file. Skip this and test data leaks into training.
2. **The `-training` / `-testing` file split is discarded.** It partitions by attack
   *mechanism*, not randomly: all 7 `DrDoS_*` (reflection) families appear **only** in
   `-testing` files; LDAP, MSSQL, NetBIOS, Portmap, UDP **only** in `-training` files.
   Only Benign, Syn, UDPLag straddle both. Using it measures mechanism, not generalisation.
3. **Scaling and selection never see test.** Everything lives inside the `Pipeline`.

Also in this step:

- [ ] drop the 18 constant features (9 flag counts + 6 bulk-rate + `Fwd/Bwd PSH/URG Flags`)
- [ ] `src/daf_projet/__init__.py` — replace the uv stub (`main()` printing a greeting)
      with the CLI runner
- [ ] smoke test: `python -c "from daf_projet.data import load_dataset; ..."`

Check: shapes and class counts print, no NaN, no inf, `src_file` present but unused.

---

## Step 2 — Metrics module

Create `src/daf_projet/metrics.py`.

- [ ] `evaluate(y_true, y_pred, y_proba, classes)` → Macro-F1, Weighted-F1,
      per-class Precision/Recall/F1, PR-AUC, ROC-AUC, FPR@TPR=0.95
- [ ] `confusion_matrix(...)` with explicit `labels=` so ordering never drifts between runs
- [ ] `confusion_to_matrix(...)` — rows = held-out family, cols = the known family it was
      mistaken for. **This is the headline output of Step 6.** Write it now, use it later.

Check: on a deliberately shuffled `y_pred` all scores collapse to chance.

Rule: accuracy is computed and displayed, but never used to conclude (spec §11).

---

## Step 3 — Phase 1 · EDA notebook

`notebooks/01_eda.ipynb`, ~2 h.

- [ ] state the research question and H1/H2/H3 **before** running anything (spec §10)
- [ ] family counts table + imbalance chart
- [ ] family × `Protocol` crosstab — shows Syn 99.8 % TCP, MSSQL/UDP 100 % UDP
- [ ] the file-partition-vs-mechanism table from Step 1 rule 2, as a figure
- [ ] duplicate/leakage audit numbers (21,347 / 8,626)
- [ ] per-family distributions for the 6 most discriminative features

Output: `figures/01_eda_*.png`. This notebook is also the evidence that you found and
neutralised the file-split shortcut — worth a slide.

---

## Step 4 — Phase 2 · Baselines

`notebooks/02_baseline.ipynb`, ~2 h.

- [ ] `DummyClassifier(strategy="stratified")` — the floor
- [ ] `LogisticRegression(max_iter=2000, class_weight="balanced")`
- [ ] `RandomForestClassifier(n_estimators=300, class_weight="balanced", n_jobs=-1)`
- [ ] binary target first, full metric bundle, confusion matrix
- [ ] seed 42, record `sklearn.__version__`

Check: Dummy Macro-F1 ≈ 1/13 ≈ 0.077. If it doesn't, the labels are misaligned.

---

## Step 5 — Phase 3 · Experiment 1 (H1, answers Q2)

Create `src/daf_projet/experiments/exp1_binary_vs_multi.py` + `notebooks/03_*.ipynb`, ~3 h.

- [ ] same split, same seed, same 3 models — only the target changes
- [ ] binary `Benign`/`DDoS` vs 12-way multiclass
- [ ] **rerun multiclass without `Protocol`** — it is near-family-deterministic, so this
      ablation measures how much accuracy is protocol lookup
- [ ] results → `results/exp1.csv`

Figures: Macro-F1/Weighted-F1 bar pair, per-class Recall, 2 confusion matrices, ablation delta.

---

## Step 6 — Phase 4 · Experiment 2, Leave-One-Attack-Out (H2, answers Q1)

The most important step. `src/daf_projet/experiments/exp2_loado.py`, ~4 h.

- [ ] loop over the **11 families with ≥1,000 rows** (skip WebDDoS, 51 rows — justify it)
- [ ] **purge the held-out family from all 17 files**, not just the file named after it.
      Necessary: `UDPLag-training` contains 5,538 Syn + 3,298 UDP, `LDAP-training` contains
      246 NetBIOS, `MSSQL-training` 22 LDAP, `UDP-training` 145 MSSQL.
      Spec §11 forbids calling an attack "unknown" if its family was in training.
- [ ] re-split with the **same seed** each rotation so only the family changes
- [ ] train binary on the remaining families
- [ ] test on the held-out family's rows + matched Benign → Macro-F1, Recall_F, FPR
- [ ] fill `confusion_to_matrix` — which known family each unseen one gets mistaken for
- [ ] 3 seeds: 42, 43, 44. 11 × 3 × 3 = **99 fits**
- [ ] results → `results/exp2.csv`

Figures: family × model heatmap, confusion-to heatmap, error analysis.

---

## Step 7 — Phase 5 · Experiment 3, feature reduction (H3, answers Q3+Q4)

`src/daf_projet/experiments/exp3_features.py`, ~4 h.

- [ ] selection fitted on **train fold only**
- [ ] variants: all 77 → ~75 % / 50 % / 25 % → Top-10
- [ ] method: `mutual_info_classif`, cross-checked against RF `feature_importances_`
- [ ] for each variant record Macro-F1 **and** inference latency:
      `time.perf_counter`, batch of 1000, 5 repeats, report the median
- [ ] results → `results/exp3.csv`

Figures: performance-vs-n_features and latency-vs-n_features, knee annotated.
Q4 needs latency, not just accuracy — that is the real-time angle.

---

## Step 8 — Phase 6 · XAI + error analysis

`notebooks/06_xai.ipynb`, ~3 h.

- [ ] `permutation_importance` on the **test** fold, not the train fold
- [ ] rerun for the E1 and E2 best models
- [ ] optional SHAP — only if it installs cleanly on Python 3.14. Permutation importance
      alone already satisfies spec §5, so treat SHAP as a bonus, not a blocker
- [ ] FP/FN galleries with real flow values — what an analyst would actually see
- [ ] tag every claim: **Observation** / **Interprétation ML** / **Interprétation cyber** /
      **Limite** (spec §10 requires all four be distinguished)

---

## Step 9 — Phase 7 · Deliverables

~3 h. Spec §9.

- [ ] `README.md` — repro steps, seeds, `pip freeze` output, expected runtimes
- [ ] `rapport/` — 10–15 pages excl. annexes, structured per spec §10
- [ ] `rapport/` — 10–15 slides
- [ ] soutenance script, 15 min + 5 min Q&A
- [ ] "Utilisation de l'IA" section (spec §7)

---

## Open questions for the group

- [ ] **Report language** — FR or EN? Affects notebooks + slides, cheaper to settle now.
- [ ] **Who does what** — 4 people, all examinable on any part. Suggested split:
      Steps 1–4 · Steps 5–6 · Steps 7–8 · Step 9. Whoever owns Step 1 must be able to
      explain the dedupe and purge logic cold, since that is the likeliest probing question.