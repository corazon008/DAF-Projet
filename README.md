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
| XAI | Interprétation | Champs d’en-tête TCP, fenêtres initiales et débit dominants ; SHAP non requis |

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
2. **Aucun preprocessing global.**  Les colonnes constantes sont retirées sur
   le fold d'entraînement ; standardisation et sélection de features vivent
   dans une `Pipeline` ajustée sur le train uniquement.
3. **Split canonique.**  Un split stratifié 80/20 sur la famille fine est créé
   une fois par graine et réutilisé par toutes les expériences ; la cible
   binaire est dérivée des mêmes lignes.
4. **Purge LOADO sur tout le dataset.**  Pour chaque rotation, la famille
   tenue à l'écart est retirée des 17 fichiers concaténés, pas seulement du
   fichier qui porte son nom.  Les paires `DrDoS_X` / `X` restent des labels
   distincts ; la cellule `run_sibling()` purge aussi la famille sœur et sert
   de contrôle de robustesse.
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

Tout le code d'expérimentation est dans les notebooks.  Il n'y a plus de module
Python, de CLI ni de script de validation à lancer avant les notebooks.

```bash
uv sync

# Chaque notebook est autonome : chargement, dédoublonnage, entraînement,
# métriques et figures.  Il écrit ses CSV dans results/.
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/01_eda.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/02_baseline.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/03_exp1_binary_vs_multiclass.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/04_exp2_loado.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/05_exp3_features.ipynb
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/06_xai.ipynb

# Variante tout-en-un
uv run jupyter nbconvert --to notebook --execute --inplace notebooks/notebook_final.ipynb

# Rapport et slides (reconstruits à partir de results/)
uv run python scripts/build_report.py
uv run python scripts/build_slides.py
```

Les graines sont **42, 43, 44** pour E2 et E3 ; E1 et la baseline utilisent 42.
Chaque notebook peut être exécuté seul ; `notebook_final.ipynb` enchaîne les six
phases.

> **État des résultats.**  Les CSV baseline, E2 et XAI sont complets.  Le CSV
> E3 a été écrasé par un test réduit (`CAP=1000`, une seule graine) ; réexécuter
> `05_exp3_features.ipynb` en entier avant de lancer `build_report.py` ou
> `build_slides.py`.  Les PDF actuellement livrés correspondent encore aux
> exécutions complètes précédentes.

### Temps d'exécution observés

| Notebook | Temps indicatif |
|---|---|
| `01_eda` | ~30 s (lecture + hash + figures) |
| `02_baseline` | ~1 min (3 fits, données complètes) |
| `03_exp1` | ~15–25 min (9 fits, données complètes) |
| `04_exp2` | ~40–60 min (99 fits LOADO + 6 fits sibling + attributions) |
| `05_exp3` | ~15–25 min (30 fits, cap 20k/classe) |
| `06_xai` | ~3–5 min (modèles de diagnostic cap 10k/classe) |
| `notebook_final` | ~1 h 30 (toutes les phases) |
| `build_report.py` + `build_slides.py` | ~10–20 s (Pandoc + xelatex) |

## Arborescence

```
dataset/                 # 17 parquet + zip ignoré
notebooks/
  01_eda.ipynb           # audit, doublons, familles
  02_baseline.ipynb      # Benign / DDoS
  03_exp1_binary_vs_multiclass.ipynb
  04_exp2_loado.ipynb    # leave-one-attack-out + sibling
  05_exp3_features.ipynb # réduction de features
  06_xai.ipynb           # importance, FP/FN
  notebook_final.ipynb   # pipeline complet
results/                 # CSV de résultats (source des tableaux)
figures/                 # PNG des figures
rapport/                 # rapport, slides, script de soutenance
scripts/                 # build_report.py, build_slides.py
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
