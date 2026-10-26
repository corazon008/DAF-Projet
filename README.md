# DAF-Projet — Détection DDoS et généralisation à des attaques non observées

Projet de détection d'anomalies et de fraude avec Python (S9).  Question
centrale : **un modèle entraîné sur certaines attaques DDoS reconnaît-il une
stratégie DDoS jamais rencontrée ?**

## Résultats en un coup d'œil

| Expérience | Question | Résultat principal |
|---|---|---|
| Baseline binaire | Benign / DDoS | Macro-F1 ≈ 0,99 (RF), FPR ≈ 0,03 % (RF) |
| E1 — binaire vs multiclasses | Q2 | Macro-F1 chute à ≈ 0,75 en 13 classes ; l'ablation de `Protocol` ne change presque rien |
| E2 — Leave-One-Attack-Out | Q1 | Dix familles sur onze restent au-dessus de 0,96 ; **Syn** s'effondre avec la RF (0,60) mais pas avec la logreg (0,97) |
| E3 — réduction de features | Q3/Q4 | Une fraction des variables conserve l'essentiel de la performance ; le gain de latence du RF est limité |
| XAI | Interprétation | Features de taille de paquet et de débit dominantes ; SHAP non requis |

Les chiffres exacts sont dans `results/` et dans `rapport/`.

## Données

- 17 fichiers Parquet CIC-DDoS2019 dans `dataset/` (source de vérité).
- 431 371 lignes brutes, 77 features numériques, 17 familles fines
  (`Benign` + 16 familles d'attaque, `DrDoS_*` conservé séparément).
- 21 347 lignes dans des groupes de doublons exacts ; 8 858 empreintes de
  features apparaissent dans plus d'un fichier ; 5 289 empreintes ont des
  labels contradictoires.
- Après dédoublonnage : **418 884 lignes**.

Le split publié `-training` / `-testing` est **volontairement ignoré** : il
partitionne par mécanisme d'attaque, pas au hasard.  Les sept familles
`DrDoS_*` n'apparaissent que dans les fichiers `-testing`, tandis que LDAP,
MSSQL, NetBIOS, Portmap et UDP n'apparaissent que dans les fichiers
`-training`.  L'utiliser mesurerait la reconnaissance d'un mécanisme, pas la
généralisation.

## Choix méthodologiques non négociables

1. **Dédoublonnage avant split.**  On hash les 77 features et on garde une
   ligne par empreinte.  En cas de labels contradictoires, le label majoritaire
   gagne (égalité : ordre lexicographique).  C'est déterministe et indépendant
   de l'ordre des fichiers.
2. **Aucun preprocessing global.**  Suppression des colonnes constantes,
   standardisation et sélection de features vivent dans une `Pipeline` ajustée
   sur le train uniquement.
3. **Split canonique.**  Un split stratifié 80/20 sur la famille fine est créé
   une fois par graine et réutilisé par toutes les expériences ; la cible
   binaire est dérivée des mêmes lignes.
4. **Purge LOADO sur tout le dataset.**  Pour chaque rotation, la famille
   tenue à l'écart est retirée des 17 fichiers concaténés, pas seulement du
   fichier qui porte son nom.  Les paires `DrDoS_X` / `X` restent des labels
   distincts ; la commande `sibling` purge aussi la famille sœur et sert de
   contrôle de robustesse.
5. **Métriques adaptées au déséquilibre.**  Macro-F1, Weighted-F1, précision et
   rappel par classe, PR-AUC, ROC-AUC, FPR à TPR = 95 %.  L'accuracy est
   affichée mais ne sert jamais à conclure.

## Environnement

- Python 3.14
- `scikit-learn 1.9.1`, `pandas 3.0.6`, `numpy 2.5.3`,
  `matplotlib 3.11.2`, `seaborn 0.13.2`, `scipy 1.18.1`
- `uv` 0.13.5
- Versions exactes : `requirements.txt` (export `uv`, à régénérer avec
  `uv export --format requirements-txt --no-hashes -o requirements.txt`).

## Reproduction

```bash
uv sync

# Audit de données (formes, doublons, classes, colonnes constantes)
uv run daf-projet smoke

# Expériences (écrivent results/*.csv)
uv run daf-projet baseline
uv run daf-projet exp1
uv run daf-projet exp2 --cap 20000   # 11 familles × 3 modèles × 3 graines = 99 fits
uv run daf-projet exp3               # 3 graines, cap 20k/classe
uv run daf-projet sibling            # contrôle : purge aussi la famille sœur

# Notebooks (exécution reproductible)
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/01_eda.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/02_baseline.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/03_exp1_binary_vs_multiclass.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/04_exp2_loado.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/05_exp3_features.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/06_xai.ipynb

# Rapport et slides
uv run python scripts/build_report.py
uv run python scripts/build_slides.py
```

Les graines sont **42, 43, 44** pour E2 et E3 ; E1 et la baseline utilisent 42.
Les notebooks d'analyse lisent les CSV produits par les commandes ci-dessus et
ne retrainent pas sur un split différent.

### Temps d'exécution observés

| Commande | Temps |
|---|---|
| `smoke` | ~20 s (lecture + hash) |
| `baseline` | ~1 min (données complètes) |
| `exp1` | ~15–25 min (données complètes, 9 fits) |
| `exp2` | ~30–45 min (99 fits + 11 attributions) |
| `exp3` | ~15–25 min (30 fits, cap 20k/classe) |
| Notebook XAI | ~3–5 min (modèles de diagnostic cap 10k/classe) |

## Arborescence

```
dataset/                 # 17 parquet + zip ignoré
src/daf_projet/
  data.py                # load, dedupe, split, subsample, pipeline
  metrics.py             # metrics bundle, confusion matrices
  experiments/           # baseline, exp1, exp2, exp3, common
notebooks/               # 01 EDA → 06 XAI
results/                 # CSV de résultats (source des tableaux)
figures/                 # PNG des figures
rapport/                 # rapport, slides, script de soutenance
scripts/                 # générateurs de notebooks et de livrables
```

## Limites

- Capture de laboratoire 2019 ; pas de trafic chiffré, pas de dérive, pas
  d'adversaire qui adapte son attaque.
- Le test E2 est équilibré 1:1 pour rendre FPR et rappel comparables ; ce n'est
  pas la prévalence de production.
- Le LOADO principal tient à l'écart un label fin.  Les paires `DrDoS_X` / `X`
  sont des mécanismes proches ; le contrôle `sibling` purge les deux et est
  rapporté séparément.
- Les familles rares (< 1 000 lignes après dédoublonnage) sont exclues des
  rotations LOADO : DrDoS_LDAP (993), Portmap (400), NetBIOS (374),
  DrDoS_NetBIOS (311), WebDDoS (49).
- La latence E3 est mesurée sur un laptop en batch, pas sur un équipement
  réseau.
- Le rapport est rédigé en français ; le code et les notebooks sont en anglais.

## Utilisation de l'IA

Voir la section dédiée dans `rapport/rapport.md`.  L'IA a servi d'assistance à
la structure du code, au débogage et à la rédaction ; les expériences, les
chiffres et les conclusions ont été exécutés et vérifiés dans ce dépôt.
