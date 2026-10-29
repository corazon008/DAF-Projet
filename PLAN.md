# PLAN — DAF-Projet

Statut : projet **notebook-only**.  Il n'y a plus de module `src/daf_projet`, de
CLI `daf-projet`, de script de validation ni de script de génération de
notebooks.  Le code d'expérimentation vit dans `notebooks/01`–`06` et dans
`notebooks/notebook_final.ipynb`.

Légende : `[ ]` à faire · `[~]` en cours · `[x]` fait

---

## 1. Structure cible

- [x] modules supprimés (`src/`, `daf_projet/`)
- [x] CLI et `[project.scripts]` supprimés
- [x] `pyproject.toml` limité aux dépendances (`package = false`)
- [x] `scripts/build_report.py` et `scripts/build_slides.py` conservés
- [x] `scripts/validate_results.py`, `run_all.sh`, `parquet_to_csv.py` supprimés
- [x] notebooks `01`–`06` autonomes
- [x] `notebook_final.ipynb` enchaîne les six phases

## 2. Contenu des notebooks

Chaque notebook charge les parquet, dédoublonne par hash de features, construit
le split stratifié et entraîne ses modèles localement.  Les helpers communs
(chargement, dedupe, split, purge, métriques, modèles) sont dupliqués dans le
premier bloc de code de chaque notebook.

- [x] `01_eda` : audit, doublons, familles, colonnes constantes, figures
- [x] `02_baseline` : dummy / logreg / forêt, cible Benign vs DDoS
- [x] `03_exp1` : binaire vs 13 classes, ablation de `Protocol`
- [x] `04_exp2` : LOADO 11 familles × 3 modèles × 3 graines + contrôle sibling
- [x] `05_exp3` : 5 variantes de features × 2 tâches × 3 graines
- [x] `06_xai` : permutation importance E1/E2, galeries FP/FN

## 3. Règles méthodologiques conservées

- [x] dédoublonnage par hash des 77 features avant tout split
- [x] label majoritaire en cas de conflit (égalité : ordre lexicographique)
- [x] split stratifié 80/20 sur la famille fine, une fois par graine
- [x] purge LOADO sur tout le dataset concaténé
- [x] contrôle sibling : purge `X` et `DrDoS_X`
- [x] colonnes constantes retirées sur le train uniquement
- [x] standardisation et sélection de features dans une `Pipeline`

## 4. Garde-fous supprimés

- [x] assertions sur le nombre de fichiers/features
- [x] vérifications NaN/inf
- [x] assertions sur le nombre de classes
- [x] `check_is_fitted`
- [x] validation de transformer personnalisé
- [x] `validate_results.py`
- [x] argparse / CLI

## 5. Reproduction

```bash
uv sync
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/01_eda.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/02_baseline.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/03_exp1_binary_vs_multiclass.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/04_exp2_loado.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/05_exp3_features.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/06_xai.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/notebook_final.ipynb
uv run python scripts/build_report.py
uv run python scripts/build_slides.py
```

## 6. État des résultats

Les résultats baseline, E2 et XAI sont intacts.  Le CSV E3 a été écrasé par un
test réduit (`CAP=1000`, une graine) ; il faut réexécuter entièrement
`notebooks/05_exp3_features.ipynb` avant de reconstruire le rapport ou les
slides.  Les PDF actuels correspondent encore aux résultats complets
précédents.
