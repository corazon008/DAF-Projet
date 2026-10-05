# DAF-Projet — Détection DDoS et généralisation à des attaques non observées

Implementation plan. Source of truth: `Projet.pdf` (spec, 4 pages, extracted via
`pdftotext -layout`). Data facts below were **measured** on `dataset/*.parquet`, not assumed.

---

## 1. Research framing

**Central question.** Does a model trained on some DDoS families recognise a strategy it has
never seen?

**Hypotheses** (stated before any run, per spec §10):

- **H1** — Multiclass (12 families) is harder than binary (Benign/DDoS).
- **H2** — Generalisation to a held-out family depends strongly on *which* family is excluded.
- **H3** — A fraction of the features retains most of the performance.

**Mandatory analysis questions** (spec §6): Q1 which families generalise best; Q2 is a strong
binary model necessarily useful for attack typing; Q3 how many features are truly needed;
Q4 which results matter for real-time use.

---

## 2. Data audit — measured findings

17 parquet files, **431,371 rows × 78 cols** (77 features + `Label`), 0 NaN, 0 inf.
`Protocol` values ∈ {0, 6, 17}. Only object column is `Label`.

### 2.1 Three traps that break naive pipelines

**(a) Filename ≠ family.** Training files contain foreign families:

| File | Contaminating labels |
|---|---|
| `UDPLag-training` | Syn 5,538 · UDP 3,298 |
| `LDAP-training` | NetBIOS 246 |
| `MSSQL-training` | LDAP 22 |
| `UDP-training` | MSSQL 145 |

Family must be derived from `Label`. LOADO must purge a family **across all 17 files**,
not just the file named after it.

**(b) The provided train/test files partition by attack *mechanism*, not randomly.**

| | `-training` files | `-testing` files |
|---|---|---|
| families | LDAP, MSSQL, NetBIOS, Portmap, UDP, Syn, UDPLag | DrDoS_* (all 7), TFTP, WebDDoS, Syn, UDPLag |

Only Benign, Syn, UDPLag straddle both sides. All 7 reflection (`DrDoS_*`) families exist
**only** in `-testing` files; all 5 bare direct families **only** in `-training` files.

→ **The file split must be discarded.** Scoring with it measures mechanism discrimination,
not generalisation. Reported as a leakage risk found and neutralised — a strong point for
the soutenance.

**(c) Leakage.** 21,347 rows sit in exact-duplicate groups; 8,626 feature-hashes appear in
**more than one file** (e.g. 1,682 hashes in both MSSQL-training and MSSQL-testing).
Random split before dedup ⇒ test rows seen in training. Dedupe first.

### 2.2 Taxonomy (decision: keep `DrDoS_*` separate)

`DrDoS_` = reflection/amplification (spoofed-source UDP, small request → huge reply).
Bare name = direct/volumetric flood. Same victim protocol, opposite mechanism and defence.

Keeping them separate makes LOADO test *"can the model recognise an attack mechanism it has
never seen"*, not merely *"a new port number"*. Merging would destroy the most interesting
axis of variation in the dataset.

13 classes after label cleanup:

| Class | n | Class | n |
|---|---|---|---|
| DrDoS_NTP | 121,368 | DrDoS_MSSQL | 6,212 |
| TFTP | 98,917 | DrDoS_DNS | 3,669 |
| Benign | 97,831 | LDAP | 1,906 |
| Syn | 49,373 | DrDoS_LDAP | 1,440 |
| UDP | 18,090 | DrDoS_SNMP | 2,717 |
| DrDoS_UDP | 10,420 | NetBIOS | 644 |
| UDPLag | 8,927 | DrDoS_NetBIOS | 598 |
| MSSQL | 8,523 | Portmap | 685 |
| WebDDoS | 51 | | |

- **`UDP-lag` (8,872) + `UDPLag` (55) = one attack split by a typo.** Merge → 8,927.
  They straddle both file partitions, so unmerged they would silently corrupt the split.
- **WebDDoS (51 rows)** — below any sane support floor. Excluded from LOADO rotations,
  kept in E1 with an explicit caveat that it cannot carry Macro-F1.

### 2.3 Shortcut feature

`Protocol` is near-family-deterministic: Syn 99.8 % proto 6; MSSQL / UDP / UDP-lag 100 % proto 17;
WebDDoS 100 % proto 6; every `DrDoS_*` ≈ 99.7–100 % proto 17.

**Decision: keep, but ablate in E1.** Quantifies how much multiclass accuracy is protocol
lookup. Better material than silently dropping a legitimately-available real-time feature.

### 2.4 Dead features

18 constant / near-constant, all 9 flag counts (`FIN`…`ECE`) and all 6 bulk-rate columns,
plus `Fwd/Bwd PSH/URG Flags`. Must be dropped **inside** the pipeline, fit-on-train — never
before the split (spec §11).

### 2.5 Imbalance

NTP 121 k and TFTP 99 k vs Portmap 685 and WebDDoS 51. **Decision: stratified cap at
20,000 rows per class + `class_weight='balanced'`.** Caps logged and declared as a stated
limitation in the report.

---

## 3. Environment

Installed: pandas 3.0.6, pyarrow 25.0.1, numpy 2.5.3, jupytext, kaggle (unused).

**Gaps:** `scikit-learn`, `matplotlib`, `seaborn` **not installed**. Python 3.14 —
verified sklearn 1.9.1 / matplotlib 3.11.2 resolve cleanly.

Changes:
- add `scikit-learn`, `matplotlib`, `seaborn` to `pyproject.toml`
- remove unused `kaggle` dependency (data is local)
- do **not** commit `dataset/cicddos2019.zip` (duplicates the parquet) — add to `.gitignore`
- replace the uv template stub in `src/daf_projet/__init__.py` (currently `main()` printing a
  greeting) with the CLI runner

---

## 4. Module layout

```
src/daf_projet/
  __init__.py        # CLI runner (replaces stub)
  data.py            # load, harmonise labels, dedupe, split, subsample
  models.py          # model zoo + seeds
  metrics.py         # metric bundle, confusion-to matrix
  experiments/
    exp1_binary_vs_multi.py
    exp2_loado.py
    exp3_features.py
notebooks/
  01_eda.ipynb  02_baseline.ipynb  03_exp1_binary_vs_multi.ipynb
  04_exp2_loado.ipynb  05_exp3_features.ipynb  06_xai.ipynb
figures/  results/  rapport/  README.md
```

`data.py` contract:

- `load_dataset()` — read 17 parquet, strip `Label`, `UDP-lag`→`UDPLag`, keep `DrDoS_*`
  distinct, record `src_file` **for the audit only**, discard the file partition.
  Returns `X, y_family, y_binary`.
- `dedupe(X, y)` — hash the 77 features, **before any split**.
- `split(X, y, seed)` — stratified 80/20; val carved from train only.
- `subsample(...)` — stratified 20 k cap, applied post-split, per fold.
- `Pipeline(StandardScaler, clf)` — no scaler ever touches test.
- `drop_dead_features` — fit-on-train step.

Experiments write tidy DataFrames to `results/*.csv`; notebooks only plot. Re-runnable,
no hidden state.

Seeds: `RANDOM_STATE = 42`; LOADO rotations = 42, 43, 44.

---

## 5. Phases (21 h)

### Phase 1 · 2 h — Problem + EDA
Research question, H1/H2/H3 written before any run. Family × protocol table, the
file-partition-vs-mechanism table (§2.1b), per-family feature distributions, duplicate/leakage
audit, imbalance chart → `figures/01_eda_*.png`.

### Phase 2 · 2 h — Data prep + baseline
Baselines: `DummyClassifier(stratified)` → `LogisticRegression` → `RandomForest`.
Metrics: Macro-F1, Weighted-F1, per-class Precision/Recall/F1, PR-AUC, ROC-AUC,
FPR@TPR=0.95, confusion matrices. Accuracy computed but never used to conclude (spec §11).

### Phase 3 · 3 h — Exp 1: binary vs multiclass (H1)
Same split, same seed, same 3 models, two targets (`Benign/DDoS` vs 12-way). Plus the
`Protocol`-ablated rerun.
Deliver: Macro-F1/Weighted-F1 bar pair, per-class Recall, two confusion matrices, ablation delta.
**Answers Q2.**

### Phase 4 · 4 h — Exp 2: Leave-One-Attack-Out (H2)
For each of the 11 families with ≥1,000 rows (WebDDoS excluded, justified):
1. purge F from **all 17 files**, re-split with the **same seed**
2. train on remaining families (binary Benign/DDoS)
3. test on F's rows + matched Benign → Macro-F1, Recall_F, FPR
4. build the **confusion-to matrix**: which known family the unseen one is mistaken for

3 seeds (spec requires ≥3 rotations). 11 × 3 × 3 = 99 fits.
Deliver: family × model heatmap + error analysis. The confusion-to matrix is the headline
cyber finding — it says *why* a new variant evades detection.
**Answers Q1.**

### Phase 5 · 4 h — Exp 3: feature reduction (H3)
Selection fitted on train only. Variants: all 77 → ~75 % / 50 % / 25 % → Top-10.
Methods: mutual-information ranking, cross-checked with RandomForest importance.
Track Macro-F1 **and** measured inference cost (ms/flow, batch of 1k, 5 repeats).
Deliver: performance-vs-n_features and latency-vs-n_features curves, knee annotated.
**Answers Q3, Q4.**

### Phase 6 · 3 h — XAI + deep analysis
Permutation importance on the **test** fold (not train) for E1 and E2. Optional SHAP if it
installs cleanly on 3.14. FP/FN galleries with concrete flow values — what an analyst
actually sees. Every claim tagged **Observation** / **Interprétation ML** /
**Interprétation cyber** / **Limite** (spec §10).

### Phase 7 · 3 h — Write-up
`README.md` (repro steps, seeds, library versions), report 10–15 pp excl. annexes,
10–15 slides, 15 min + 5 min soutenance, short "Utilisation de l'IA" section (spec §7).

---

## 6. Runtime budget

| Stage | Estimate |
|---|---|
| E1 (2 targets × 3 models + ablation) | ~10 min |
| E2 LOADO (11 families × 3 seeds × 3 models) | ~2–2.5 h |
| E3 feature reduction | ~40 min |

Fits the 21 h phase budget.

---

## 7. Deliverables (spec §9)

- [ ] Clean, runnable, commented Jupyter/Colab notebook
- [ ] Report 10–15 pages excl. annexes
- [ ] Presentation 10–15 slides
- [ ] Soutenance script, 15 min + 5 min Q&A
- [ ] `README.md` with reproduction steps
- [ ] Short "Utilisation de l'IA" declaration

## 8. Guardrails (spec §11) — non-negotiable

- Never conclude on accuracy alone.
- No feature selection, scaling or resampling on the full data before the split.
- No correlation presented as causation.
- Never call an attack "unknown" if observations of that family were in training
  (→ this is why §2.1a purge-across-all-files matters).
- Never pick the best model on the test set.
- Every conclusion tied to a measured result.

## 9. Open items for the group

1. **Lib versions** — pin and record in README (`pip freeze`).
2. **SHAP on Python 3.14** — unverified; fallback is permutation importance only, which
   already satisfies spec §5.
3. **Report language** — FR or EN? Slides must match.
4. **Group of 4** — split Phase 1/2 (data+baseline), Phase 3/4 (E1+E2), Phase 5 (E3+XAI),
   Phase 7 (write-up). Any member may be questioned on any part, so all four must be able
   to explain the pipeline.