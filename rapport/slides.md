---
title: "Détection DDoS et généralisation à des attaques non observées"
shorttitle: "DDoS — généralisation"
author: "Corentin CALVEZ et Lubin TERRIEN"
date: "2026"
lang: fr
header-includes: |
  \setbeamertemplate{caption}{}
---

## Une question opérationnelle, pas seulement un score

> Un modèle entraîné sur certaines attaques DDoS reconnaît-il une stratégie
> DDoS jamais rencontrée ?

- Le binaire répond « attaque / pas attaque ».
- Le SOC a besoin de la **famille** pour choisir la contre-mesure.
- Une famille inconnue peut ressembler à du trafic bénin.

## Trois hypothèses à tester

**H1** — le multiclasses est plus difficile que le binaire.

**H2** — la généralisation dépend fortement de la famille laissée de côté.

**H3** — une fraction des variables conserve l'essentiel de la performance.

Plan : données → protocole sans fuite → E1 → E2 → E3 → XAI.

## 431 371 flux, 17 familles très déséquilibrées

- CIC-DDoS2019 : 17 fichiers Parquet, 77 caractéristiques.
- `DrDoS_NTP`, `TFTP` et `Benign` ≈ 74 % des lignes.
- `WebDDoS` : 51 lignes seulement.
- Après dédoublonnage : **418 884 lignes**.

![Répartition des familles](../figures/01_eda_family_imbalance.png){height=5.0cm}

## Deux artefacts rendraient le score trompeur

- 21 347 lignes dans des groupes de doublons exacts.
- 5 289 empreintes avec des étiquettes contradictoires.
- Le split publié partitionne les **mécanismes** :
  `-testing` contient toutes les familles `DrDoS_*`.

Utiliser ce split mesure la reconnaissance d'un fichier, pas la généralisation.
Le split retenu est donc aléatoire, stratifié par famille.

## Protocole : dédoublonner, puis tirer au hasard

1. Une ligne par empreinte de caractéristiques, avant tout split.
2. Split stratifié 80/20 sur la famille fine, une fois par graine.
3. Préprocessing dans une `Pipeline` ajustée sur le train.
4. LOADO : purger la famille des **17 fichiers**, pas du fichier homonyme.
5. Test équilibré : famille inconnue + `Benign` apparié.
6. Métriques : Macro-F1, rappel par classe, PR-AUC, FPR.

## La baseline binaire est presque parfaite

- Dummy stratifié : Macro-F1 = 0,5006.
- Logistic regression : Macro-F1 = 0,9949,
  FPR = 0,0026.
- Random forest : Macro-F1 = 0,9991,
  FPR = 0,0003.

Le binaire est **facile**. Ce n'est pas une preuve de compréhension des types.

![Métriques de la baseline](../figures/02_baseline_metrics.png){height=4.7cm}

## E1 : le multiclasses casse le score

- Binaire, random forest : Macro-F1 = 0,9991.
- 13 classes, random forest : Macro-F1 = 0,7566,
  Weighted-F1 = 0,9816.
- Sans `Protocol` : Macro-F1 = 0,7577
  (Δ = 0,0011).

**H1 soutenue.** Le score binaire ne prouve pas la compréhension des types.

![Macro-F1 et Weighted-F1](../figures/03_exp1_macro_weighted_f1.png){height=4.7cm}

## E1 : les familles rares paient le prix

- `WebDDoS` : rappel 0 sur 10 lignes de test.
- `Portmap` : rappel ≈ 0,46 ; `DNS` : ≈ 0,53.
- Les familles fréquentes restent au-dessus de 0,99.

Le Weighted-F1 reste haut ; le Macro-F1 révèle les familles rares.

![Rappel par classe](../figures/03_exp1_per_class_recall.png){height=5.2cm}

## E2 : tenir une famille entière hors de l'entraînement

- 11 familles avec au moins 1 000 lignes après dédoublonnage.
- Purge dans les 17 fichiers : Syn apparaît aussi dans `UDPLag-training`.
- Test équilibré : famille inconnue + `Benign` apparié.
- 11 × 3 modèles × 3 graines = **99 fits**.
- Exclues : `DrDoS_LDAP` (993), `Portmap` (400), `NetBIOS` (374),
  `DrDoS_NetBIOS` (311), `WebDDoS` (49).

![Lignes purgées par fichier](../figures/04_exp2_purge_audit.png){height=4.8cm}

## E2 : dix familles généralisent, Syn non

- 10 familles sur 11 au-dessus de 0,96 ; 9 au-dessus de 0,99.
- Meilleur score : **DrDoS_MSSQL**, 0,9995 (ex æquo).
- **Syn** : 0,6035 avec la random forest (rappel 0,304).
- La logistic regression atteint 0,9733 sur Syn.
- Le FPR reste bas : c'est le **rappel** qui s'effondre.

**H2 soutenue de façon asymétrique.**

![Macro-F1 LOADO](../figures/04_exp2_family_model_heatmap.png){height=5.0cm}

## E2 : Syn ressemble à du trafic bénin

- Syn prédite `Benign` (0,45) ou `UDPLag` (0,42), pas une famille d'attaque.
- `DrDoS_MSSQL` est prédite `MSSQL` (0,83) ; `MSSQL` est prédite
  `DrDoS_MSSQL` (0,88).
- La matrice indique quelle mitigation l'analyste va tenter en premier.

![Confusion vers les familles connues](../figures/04_exp2_confusion_to.png){height=5.1cm}

## E2 : le contrôle sibling ne change pas la conclusion

- Purger aussi la famille sœur : `LDAP` + `DrDoS_LDAP`, etc.
- Scores : LDAP 0,9985 ; MSSQL 0,9993 ; UDP 0,9996.
- Minimum : 0,9980.

Le résultat ne vient donc pas uniquement de la présence de la famille sœur.

## E3 : 39 variables suffisent pour le multiclasses

- Top-10 : Macro-F1 binaire 0,9928
  contre 0,9989 avec toutes.
- 13 classes : 0,6627 en Top-10,
  0,7658 avec 39 variables,
  0,7708 avec toutes.
- En binaire, 10 variables suffisent presque ; en 13 classes, non.

**H3 partiellement soutenue.**

![Performance vs nombre de variables](../figures/05_exp3_performance.png){height=4.8cm}

## E3 : la latence ne suit pas le nombre de variables

- Binaire : 33,25 ms → 33,60 ms
  pour 1 000 flux.
- 13 classes : 33,99 ms →
  23,31 ms, mais forte dispersion.
- La sélection coûte du temps d'ajustement :
  2,5 s → 23,8 s.
- Le coût dominant reste la traversée des arbres.

![Latence vs nombre de variables](../figures/05_exp3_latency.png){height=4.8cm}

## XAI : en-têtes TCP, fenêtres et débit

- **Init Fwd Win Bytes** : 0,023.
- Puis `Bwd Header Length`, `Init Bwd Win Bytes`, `Flow Bytes/s`.
- Sur Syn : `ACK Flag Count`, `Init Fwd Win Bytes`, `URG Flag Count`.
- Permutation importance calculée sur le **test**, jamais sur le train.

![Permutation importance](../figures/06_xai_permutation_e1.png){height=4.8cm}

## Réponses aux quatre questions

- **Q1** — Les familles qui recouvrent le profil d'en-tête, de fenêtre TCP et de
  débit des familles vues généralisent le mieux ; Syn est l'exception.
- **Q2** — Non : un bon binaire ne dit pas quel type d'attaque est en cours.
- **Q3** — 10 variables en binaire, 39 à 58 en 13 classes.
- **Q4** — Rappel attaque, FPR, latence et débit ; pas l'accuracy.

## Limites

- Capture de laboratoire 2019 : pas de trafic chiffré, pas de dérive.
- Test E2 équilibré 1:1, pas la prévalence de production.
- Cinq familles rares exclues des rotations LOADO.
- Latence mesurée sur un laptop, par lots, avec cache chaud.
- 5 289 empreintes ont des étiquettes contradictoires.
- Baseline et E1 sur une seule graine.

## Conclusion

1. Le binaire est un bon **triage**, pas un produit de classification.
2. La généralisation dépend de la **famille** et du **modèle** : prévoir une
   classe « inconnue » et une revue humaine.
3. La réduction de variables aide, mais le choix du modèle reste décisif pour
   le temps réel.
4. Les métriques de décision sont le rappel par famille, le FPR et la latence.

**Merci — questions.**
