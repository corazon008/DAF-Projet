---
title: "Détection DDoS et généralisation à des attaques non observées"
subtitle: "Projet DAF — détection d'anomalies et de fraude avec Python"
author: "Corentin CALVEZ et Lubin TERRIEN"
date: "2026"
lang: fr
---

# Introduction

Les attaques par déni de service distribué (DDoS) ne se résument pas à une
coupure : elles saturent la bande passante, les tables de connexion ou un
service applicatif pendant que l'opérateur doit décider quoi couper. Un centre
opérationnel de sécurité (SOC) a donc deux questions à traiter, et elles ne se
valent pas. La première est binaire : ce trafic est-il hostile ? La seconde est
l'attribution : de quel mécanisme s'agit-il ? La réponse à la seconde commande
la contre-mesure — filtrer un SYN flood, limiter une amplification DNS,
bloquer un port — alors que la première ne fait qu'ouvrir un dossier.

Le problème devient réellement difficile lorsque la famille attaquante n'a
jamais été vue pendant l'entraînement. Un modèle peut apprendre des signatures
de laboratoire et échouer sur une variante proche, ou au contraire reconnaître
une structure de flux commune à plusieurs mécanismes. C'est l'objet de ce
projet, résumé par la question centrale :

> Un modèle entraîné sur certaines attaques DDoS reconnaît-il une stratégie
> DDoS jamais rencontrée ?

Nous traitons cette question sur CIC-DDoS2019, une capture de laboratoire de
2019 composée de 17 fichiers Parquet, 431 371 flux, 77 caractéristiques
numériques et 17 familles fines. Quatre sous-questions structurent l'analyse :

- **Q1** — Quelles familles DDoS généralisent le mieux vers d'autres familles ?
- **Q2** — Un modèle très performant en binaire est-il nécessairement utile pour
  identifier le type d'attaque ?
- **Q3** — Combien de variables sont réellement nécessaires ?
- **Q4** — Quels résultats sont les plus importants pour une utilisation en
  temps réel ?

Trois hypothèses sont testées :

- **H1** — La classification multiclasses est plus difficile que la
  classification binaire.
- **H2** — La capacité de généralisation dépend fortement de la famille DDoS
  laissée de côté.
- **H3** — Une fraction des variables conserve une grande partie des
  performances, avec un coût d'inférence réduit.

Le jeu de données contient deux artefacts qui rendraient toute évaluation
optimiste : des lignes dupliquées et un découpage publié `-training` /
`-testing` organisé par mécanisme d'attaque. Une partie du travail consiste donc
à construire un protocole qui ne mesure pas la reconnaissance d'un fichier.

Les contributions du projet sont les suivantes.

1. Un protocole sans fuite : dédoublonnage par empreinte de caractéristiques
   avant tout split, split aléatoire stratifié 80/20, et purge complète de la
   famille tenue à l'écart dans les 17 fichiers pour l'expérience LOADO.
2. Une mesure de l'écart binaire/multiclasses à lignes, modèles et graine
   identiques, avec une ablation de `Protocol` pour tester le raccourci du
   protocole de transport.
3. Une expérience Leave-One-Attack-Out sur 11 familles, trois modèles et trois
   graines, complétée par une matrice de confusion vers les familles connues et
   un contrôle qui purge aussi la famille sœur.
4. Une étude de réduction de caractéristiques qui mesure la performance mais
   aussi la latence d'inférence et le temps d'ajustement.
5. Une analyse d'explicabilité par permutation importance sur le pli de test,
   avec des galeries de faux positifs et de faux négatifs.

Le rapport suit l'ordre du pipeline. La section 1 décrit les données et les
artefacts à neutraliser. La section 2 fixe le protocole expérimental. Les
sections 3 à 5 présentent les trois expériences, la section 6 l'explicabilité,
et la section 7 discute les réponses aux questions, les limites et les
recommandations opérationnelles.

# 1. Données et analyse exploratoire

## 1.1 Composition et déséquilibre

Le jeu de données est composé de 17 fichiers Parquet, 431 371 lignes et 77
caractéristiques numériques. Les étiquettes brutes sont ramenées à 17 familles
fines : `Benign` et 16 familles d'attaque, en conservant `DrDoS_*` séparé de sa
contrepartie d'exploitation. Le libellé `UDP-lag` est normalisé en `UDPLag`.

| Famille | Lignes | Part (%) |
|---|---|---|
| DrDoS_NTP | 121 368 | 28,14 |
| TFTP | 98 917 | 22,93 |
| Benign | 97 831 | 22,68 |
| Syn | 49 373 | 11,45 |
| UDP | 18 090 | 4,19 |
| DrDoS_UDP | 10 420 | 2,42 |
| UDPLag | 8 927 | 2,07 |
| MSSQL | 8 523 | 1,98 |
| DrDoS_MSSQL | 6 212 | 1,44 |
| DrDoS_DNS | 3 669 | 0,85 |
| DrDoS_SNMP | 2 717 | 0,63 |
| LDAP | 1 906 | 0,44 |
| DrDoS_LDAP | 1 440 | 0,33 |
| Portmap | 685 | 0,16 |
| NetBIOS | 644 | 0,15 |
| DrDoS_NetBIOS | 598 | 0,14 |
| WebDDoS | 51 | 0,01 |

*Tableau 1 — Répartition des lignes par famille avant dédoublonnage.*

![Répartition des familles en échelle logarithmique : DrDoS_NTP, TFTP et Benign dominent, WebDDoS est très minoritaire.](figures/01_eda_family_imbalance.png)

Le déséquilibre est extrême : `DrDoS_NTP`, `TFTP` et `Benign` représentent
environ 74 % des lignes, tandis que `WebDDoS` ne compte que 51 lignes. Ce
déséquilibre a deux conséquences méthodologiques. D'abord, l'accuracy est
trompeuse : un modèle qui prédit toujours la classe majoritaire obtient déjà un
score élevé. Ensuite, les familles rares sont précisément celles qui portent le
risque opérationnel, car elles sont peu représentées et donc faciles à oublier.
Le projet utilise donc le Macro-F1, le rappel par classe et le taux de faux
positifs, et non l'accuracy seule.

## 1.2 Protocole et structure des fichiers

La crosstabulation famille × `Protocol` montre que `Syn` est TCP à 99,8 %,
tandis que `MSSQL` et `UDP` sont UDP à plus de 99,9 %. `Protocol` est donc un
raccourci potentiel pour la classification multiclasses : un modèle pourrait
apprendre une table de correspondance plutôt que la forme du trafic.
L'expérience 1 le retire dans une ablation pour mesurer cet effet.

Le découpage publié est encore plus structurant. Les sept familles `DrDoS_*`
n'apparaissent que dans les fichiers `-testing`, alors que `LDAP`, `MSSQL`,
`NetBIOS`, `Portmap` et `UDP` n'apparaissent que dans les fichiers
`-training`. Seules `Benign`, `Syn` et `UDPLag` chevauchent les deux. Utiliser
ce split mesurerait la reconnaissance d'un mécanisme, pas la généralisation à
une famille inconnue : un modèle pourrait identifier le fichier source à partir
de quelques indices et obtenir un bon score sans avoir appris la moindre
propriété transférable. Ce split est donc écarté.

![Découpage publié : les familles ne sont pas réparties au hasard entre les fichiers d'entraînement et de test.](figures/01_eda_file_partition.png)

## 1.3 Doublons et bruit d'étiquettes

Avant de parler de modèle, il faut vérifier que la même ligne ne puisse pas se
retrouver dans l'entraînement et dans le test. L'audit porte sur le tableau brut
concaténé, avant tout split.

| Contrôle | Valeur |
|---|---|
| lignes dans des groupes de doublons exacts | 21 347 |
| empreintes de caractéristiques présentes dans >1 fichier source | 8 858 |
| empreintes de caractéristiques avec étiquettes conflictuelles | 5 289 |
| lignes impliquées dans des empreintes de caractéristiques avec étiquettes conflictuelles | 12 957 |
| lignes supprimées par le dédoublonnage | 12 487 |
| lignes après le dédoublonnage | 418 884 |

*Tableau 2 — Audit des fuites avant dédoublonnage.*

- 21 347 lignes appartiennent à des groupes de doublons exacts.
- 8 858 empreintes de caractéristiques apparaissent dans plus d'un fichier
  source.
- 5 289 empreintes ont des étiquettes contradictoires, ce qui implique 12 957
  lignes. Certaines attaques par réflexion et leur contrepartie d'exploitation
  partagent le même vecteur de caractéristiques ; c'est une limite intrinsèque
  du jeu de données.
- Le dédoublonnage retire 12 487 lignes et laisse 418 884 lignes.

![Audit des fuites avant dédoublonnage : doublons, empreintes partagées et étiquettes contradictoires.](figures/01_eda_leakage_audit.png)

La règle retenue est simple et déterministe : une seule ligne par empreinte de
caractéristiques, étiquette majoritaire en cas de conflit, égalité tranchée
lexicographiquement. Elle ne dépend pas de l'ordre des fichiers et peut être
rejouée à l'identique. Le prix à payer est explicite : 5 289 empreintes restent
ambiguës, et aucun modèle ne pourra les séparer puisqu'elles ont exactement les
mêmes valeurs d'entrée. C'est du bruit d'étiquette irréductible, pas un défaut
du classifieur.

## 1.4 Ce que l'EDA impose au protocole

Trois décisions découlent directement de cette analyse.

1. **Dédoublonner avant de séparer.** Sinon, la même ligne peut être vue à
   l'entraînement et au test, et le score mesure la mémorisation.
2. **Tirer le split au hasard, stratifié par famille.** Le split publié
   partitionne les mécanismes ; un split aléatoire est la seule façon de
   simuler une famille absente en tenant les autres fixes.
3. **Lire le rappel par classe autant que le score agrégé.** Le Macro-F1 est la
   métrique de décision ; le Weighted-F1 et l'accuracy servent seulement de
   garde-fou contre une lecture trop favorable.

# 2. Protocole expérimental

## 2.1 Split et cibles

Un split stratifié 80/20 est créé sur la famille fine, une fois par graine, puis
réutilisé par toutes les expériences. La cible binaire est dérivée des mêmes
lignes, ce qui garantit que les comparaisons binaire/multiclasses portent sur
exactement le même test. Les graines sont 42 pour la baseline et l'expérience 1,
puis 42, 43 et 44 pour les expériences 2 et 3. Le jeu de test contient 83 777
lignes et l'entraînement 335 107 lignes.

## 2.2 Pipelines et préprocessing

Tout le préprocessing vit dans une `Pipeline` ajustée sur le pli
d'entraînement :

1. suppression des colonnes constantes (12 colonnes dans ce jeu de données, soit
   65 caractéristiques effectives sur 77) ;
2. standardisation (`StandardScaler`) ;
3. éventuellement sélection de caractéristiques (`SelectKBest` avec
   `mutual_info_classif`) ;
4. classifieur.

Aucune statistique de test n'entre dans le fit. En particulier, la sélection de
caractéristiques de l'expérience 3 est ajustée uniquement sur le pli
d'entraînement ; sinon, le score serait contaminé par les variables les plus
corrélées à la cible dans le test.

## 2.3 Modèles de référence

Trois modèles couvrent un spectre volontairement simple :

- `DummyClassifier(strategy="stratified")` : plancher aléatoire, utile pour
  vérifier l'alignement des étiquettes et le niveau du hasard ;
- `LogisticRegression(max_iter=2000, class_weight="balanced")` : référence
  linéaire, robuste et peu coûteuse ;
- `RandomForestClassifier(n_estimators=300, class_weight="balanced")` :
  référence non linéaire, capable de capturer des interactions entre
  caractéristiques.

Le poids `balanced` compense le déséquilibre des classes à l'entraînement. Il ne
corrige pas la prévalence du test ; c'est pourquoi le rappel par famille reste
la lecture principale.

## 2.4 Métriques et critères de décision

Les métriques reportées sont le Macro-F1, le Weighted-F1, la précision, le
rappel et le F1 par classe, la PR-AUC, la ROC-AUC et le FPR au point de rappel
95 %. L'accuracy est affichée mais n'est jamais utilisée pour conclure.

Deux choix méritent d'être justifiés. Le Macro-F1 donne le même poids à chaque
famille, y compris `WebDDoS` avec ses 51 lignes ; c'est volontaire, car une
famille rare peut être une attaque dangereuse. Le FPR est le taux de trafic
`Benign` classé DDoS : c'est la métrique qui détermine la charge de travail d'un
SOC. Un modèle avec un excellent F1 mais un FPR de 5 % noierait l'analyste sous
les fausses alertes.

# 3. Expérience 1 — binaire vs multiclasses (H1, Q2)

## 3.1 Protocole

Les mêmes lignes, le même split, les mêmes modèles et la même graine sont
utilisés. Seule la cible change :

- `binary` : `Benign` contre DDoS ;
- `multiclass` : `Benign` plus 12 types d'attaque, obtenus en fusionnant
  `DrDoS_X` et `X`, soit 13 classes ;
- `multiclass_no_protocol` : la même cible, avec `Protocol` retiré.

La fusion `DrDoS_X`/`X` est nécessaire pour obtenir une cible multiclasses
stable, mais elle masque la séparabilité des variantes de réflexion et
d'exploitation ; c'est précisément le rôle de l'expérience 2.

## 3.2 Résultats

| Tâche | Modèle | Macro-F1 | Weighted-F1 | Accuracy | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|
| Binaire | Dummy | 0,5006 | 0,6507 | 0,6508 | 0,7741 | 0,5006 |
| Binaire | LogReg | 0,9949 | 0,9964 | 0,9964 | 0,9998 | 0,9994 |
| Binaire | RF | 0,9991 | 0,9994 | 0,9994 | 1,0000 | 1,0000 |
| 13 classes | Dummy | 0,0763 | 0,2080 | 0,2082 | 0,0768 | 0,4996 |
| 13 classes | LogReg | 0,6027 | 0,9440 | 0,9310 | 0,5933 | 0,9886 |
| 13 classes | RF | 0,7566 | 0,9816 | 0,9815 | 0,7786 | 0,9945 |
| Sans Protocol | Dummy | 0,0763 | 0,2080 | 0,2082 | 0,0768 | 0,4996 |
| Sans Protocol | LogReg | 0,6009 | 0,9438 | 0,9307 | 0,5918 | 0,9885 |
| Sans Protocol | RF | 0,7577 | 0,9817 | 0,9816 | 0,7790 | 0,9948 |

*Tableau 3 — Métriques des trois tâches de l'expérience 1.*

![Macro-F1 et Weighted-F1 des trois tâches de l'expérience 1 : le binaire reste presque parfait, le multiclasses chute.](figures/03_exp1_macro_weighted_f1.png)

La random forest passe de 0,9991 en binaire à
0,7566 en 13 classes. Le Weighted-F1 reste à
0,9816 : les familles majoritaires sont encore bien
classées, mais les familles rares tirent le Macro-F1 vers le bas. C'est
exactement le piège qu'une lecture fondée sur l'accuracy ou le Weighted-F1
masquerait.

![Rappel par classe de la random forest en 13 classes : les familles rares sont les plus mal détectées.](figures/03_exp1_per_class_recall.png)

Le rappel par classe rend le phénomène concret : `WebDDoS` reste à
0,0000 sur 10 lignes de test, `Portmap` à
0,4625, `DNS` à
0,5347 et `NetBIOS` à
0,7153. Les familles fréquentes, elles,
restent au-dessus de 0,99. Le problème n'est donc pas uniforme : il est
concentré sur les classes à faible support.

L'ablation de `Protocol` fait passer la Macro-F1 de 0,7566 à
0,7577, soit un écart de
0,0011. Le multiclasses ne repose donc pas
seulement sur une lecture du protocole de transport : les champs d'en-tête TCP
et les débits portent l'essentiel du signal. C'est un point rassurant, car un
modèle qui apprendrait uniquement `Protocol` serait inutile dès qu'une attaque
change de port ou de protocole.

## 3.3 Verdict

**H1 est soutenue.** Un modèle presque parfait en binaire perd beaucoup en
multiclasses, surtout en Macro-F1. **Q2 : non**, un excellent détecteur binaire
n'est pas nécessairement utile pour identifier le type d'attaque.

*Interprétation cyber.* Une alerte binaire est une porte de triage : elle dit
« quelque chose attaque », pas « quelle contre-mesure appliquer ». La confusion
entre familles proches est le vrai risque opérationnel, car l'analyste peut
appliquer la mauvaise mitigation. *Limite.* La fusion `DrDoS_X`/`X` empêche de
conclure sur la séparabilité des variantes ; l'expérience 2 traite ce point.

# 4. Expérience 2 — Leave-One-Attack-Out (H2, Q1)

## 4.1 Protocole et purge

On tient à l'écart chacune des 11 familles fines ayant au moins 1 000 lignes
après dédoublonnage. La famille est purgée des 17 fichiers concaténés, pas
seulement du fichier qui porte son nom. Les familles exclues par le seuil de
support sont `DrDoS_LDAP` (993 lignes), `Portmap` (400), `NetBIOS` (374),
`DrDoS_NetBIOS` (311) et `WebDDoS` (49). Ce sont des contraintes d'estimation,
pas un jugement sur leur importance opérationnelle.

La purge complète est indispensable. L'audit montre qu'une famille peut
apparaître dans plusieurs fichiers : `Syn` est présent dans `Syn-training`,
`Syn-testing` et `UDPLag-training` ; `UDP` dans `UDP-training` et
`UDPLag-training` ; `LDAP` dans `LDAP-training` et `MSSQL-training` ; `NetBIOS`
dans `NetBIOS-training` et `LDAP-training`. Purger uniquement le fichier
homonyme aurait laissé des lignes de la famille en entraînement, et
l'affirmation « famille non vue » serait fausse.

Le test est équilibré : toutes les lignes disponibles de la famille tenue à
l'écart, plus un échantillon apparié de `Benign` issu uniquement du test des
familles connues. Trois graines (42, 43, 44) donnent 11 × 3 × 3 = 99 fits. Le
test équilibré rend le rappel et le FPR comparables entre familles ; il ne
représente pas la prévalence de production, ce qui est assumé dans les limites.

\newpage

## 4.2 Résultats par famille

| Famille tenue à l'écart | RF Macro-F1 | LR Macro-F1 | RF rappel | LR rappel | RF FPR |
|---|---|---|---|---|---|
| DrDoS_MSSQL | 0,9995 | 0,9980 | 0,9997 | 0,9993 | 0,0006 |
| DrDoS_SNMP | 0,9995 | 0,9979 | 1,0000 | 0,9983 | 0,0009 |
| DrDoS_UDP | 0,9995 | 0,9978 | 0,9999 | 0,9994 | 0,0008 |
| MSSQL | 0,9995 | 0,9981 | 0,9998 | 0,9997 | 0,0008 |
| UDP | 0,9993 | 0,9980 | 0,9999 | 0,9999 | 0,0013 |
| TFTP | 0,9992 | 0,9973 | 0,9997 | 0,9989 | 0,0012 |
| DrDoS_NTP | 0,9988 | 0,9808 | 0,9984 | 0,9652 | 0,0009 |
| LDAP | 0,9985 | 0,9963 | 0,9981 | 0,9952 | 0,0010 |
| UDPLag | 0,9956 | 0,9934 | 0,9922 | 0,9912 | 0,0010 |
| DrDoS_DNS | 0,9699 | 0,9664 | 0,9404 | 0,9361 | 0,0006 |
| Syn | 0,6035 | 0,9733 | 0,3041 | 0,9499 | 0,0010 |

*Tableau 4 — Macro-F1, rappel et FPR moyens sur trois graines, par famille
tenue à l'écart.*

![Macro-F1 LOADO par famille tenue à l'écart et par modèle : Syn est la seule famille qui s'effondre avec la random forest.](figures/04_exp2_family_model_heatmap.png)

10 familles sur 11 restent au-dessus de 0,96 et 9
au-dessus de 0,99. Le meilleur score, **DrDoS_MSSQL**, atteint
0,9995 (à égalité avec trois autres familles), avec un rappel
de 0,9997 et un
FPR de 0,0006. La onzième, **Syn**, s'effondre à
0,6035 avec la random forest (rappel
0,3041, FPR 0,0010), alors que la logistic
regression atteint 0,9733 sur la même famille, avec un
rappel de 0,9499 et un FPR de 0,0034.

Le point important est que le FPR reste bas partout : ce n'est pas la fausse
alerte qui explose, c'est le **rappel** qui s'effondre. Autrement dit, des
attaques Syn ne sont pas vues du tout. L'écart est donc concentré sur une
famille et dépend du modèle, pas seulement de la famille. Un F1 agrégé unique
aurait masqué ce comportement ; le tableau par famille et le rappel associé
l'exposent.

## 4.3 Matrice de confusion vers les familles connues

Pour chaque famille inconnue, un modèle multiclasses plus léger, entraîné sur
les familles restantes, prédit la famille connue la plus proche. L'objectif
n'est pas de classifier correctement, mais de comprendre ce que l'attaquant
imite.

![Matrice de confusion vers les familles connues : Syn est prédite Benign ou UDPLag.](figures/04_exp2_confusion_to.png)

| Famille inconnue | Famille(s) connue(s) la plus proche |
|---|---|
| DrDoS_DNS | LDAP (0,25), DrDoS_LDAP (0,24), DrDoS_MSSQL (0,13) |
| DrDoS_MSSQL | MSSQL (0,83), DrDoS_DNS (0,12), DrDoS_SNMP (0,02) |
| DrDoS_NTP | DrDoS_DNS (0,66), UDP (0,18), DrDoS_UDP (0,13) |
| DrDoS_SNMP | DrDoS_DNS (0,35), DrDoS_LDAP (0,31), LDAP (0,18) |
| DrDoS_UDP | UDP (0,95), UDPLag (0,03), DrDoS_DNS (0,01) |
| LDAP | DrDoS_LDAP (0,60), DrDoS_DNS (0,26), DrDoS_SNMP (0,11) |
| MSSQL | DrDoS_MSSQL (0,88), DrDoS_DNS (0,06), DrDoS_SNMP (0,02) |
| Syn | Benign (0,45), UDPLag (0,42), Portmap (0,13) |
| TFTP | DrDoS_MSSQL (0,97), MSSQL (0,02), DrDoS_NTP (0,01) |
| UDP | DrDoS_UDP (0,93), UDPLag (0,05), MSSQL (0,00) |
| UDPLag | Syn (0,67), UDP (0,12), DrDoS_UDP (0,11) |

*Tableau 5 — Trois familles connues les plus proches de chaque famille
inconnue.*

Le cas Syn est cohérent avec l'effondrement du rappel : ses lignes sont
prédites `Benign` ou `UDPLag`, pas une famille d'attaque unique. La random forest a donc appris une frontière qui traite une partie des flux Syn comme
du trafic légitime ou comme une variante de lag UDP. À l'inverse, `DrDoS_MSSQL`
est prédit `MSSQL` à 0,83 et `MSSQL` est prédit `DrDoS_MSSQL` à 0,88 : les
paires réflexion/exploitation partagent bien une structure, ce qui explique
aussi pourquoi leur séparation fine est difficile.

## 4.4 Contrôle de robustesse : purger aussi la famille sœur

Dans le jeu d'étiquettes fines, `LDAP` et `DrDoS_LDAP` sont deux étiquettes mais un
même mécanisme. Le LOADO principal purge seulement l'étiquette tenue à l'écart.
Le contrôle ci-dessous purge aussi l'étiquette sœur (`DrDoS_X` quand `X` est
tenu à l'écart, et inversement) pour les paires qui ont assez de lignes.

| Famille tenue à l'écart | Étiquettes purgées | Macro-F1 | Rappel | FPR |
|---|---|---|---|---|
| LDAP | LDAP, DrDoS_LDAP | 0,9985 | 0,9981 | 0,0010 |
| DrDoS_LDAP | DrDoS_LDAP, LDAP | 0,9980 | 0,9970 | 0,0010 |
| MSSQL | MSSQL, DrDoS_MSSQL | 0,9993 | 0,9998 | 0,0012 |
| DrDoS_MSSQL | DrDoS_MSSQL, MSSQL | 0,9993 | 0,9998 | 0,0012 |
| UDP | UDP, DrDoS_UDP | 0,9996 | 0,9999 | 0,0008 |
| DrDoS_UDP | DrDoS_UDP, UDP | 0,9996 | 0,9999 | 0,0008 |

*Tableau 6 — Contrôle sibling : purge de l'étiquette tenue à l'écart et de sa
contrepartie.*

Le score minimum reste 0,9980. Les résultats principaux ne sont donc
pas uniquement dus à la présence de la famille sœur dans l'entraînement. Ce
contrôle renforce la validité du mot « inconnue », même s'il ne couvre que les
paires qui ont un support suffisant.

## 4.5 Verdict

**H2 est soutenue de façon asymétrique.** La majorité des familles inconnues
restent détectables ; Syn est le cas dur pour la random forest, et la
logistic regression est plus robuste. **Q1 :** les familles qui généralisent
le mieux sont celles dont le profil d'en-tête, de fenêtre TCP et de débit
recouvre celui des familles vues à l'entraînement. Syn, dont le profil recouvre
`Benign` et `UDPLag` pour la RF, est l'exception.

*Interprétation cyber.* La matrice de confusion vers les familles connues est
plus actionnable qu'un F1 global : elle indique à l'analyste quelle famille
connue l'attaque inconnue imite, donc quelle mitigation sera tentée en premier.
Pour un SOC, le cas dangereux n'est pas la mauvaise étiquette de famille mais
l'alerte manquée : un SYN flood non vu peut passer pour du trafic bénin.
*Limite.* Le test équilibré 1:1 n'est pas la prévalence de production, et le
modèle d'attribution est un diagnostic, pas le détecteur principal.

# 5. Expérience 3 — réduction de caractéristiques (H3, Q3, Q4)

## 5.1 Protocole

Cinq variantes sont comparées : toutes les caractéristiques, environ 75 % (58),
50 % (39), 25 % (20) et Top-10. La sélection est ajustée sur le train uniquement
avec `mutual_info_classif` ; l'impurity importance de la random forest
sert de contre-vérification. Les colonnes constantes sont retirées sur le pli
d'entraînement, d'où un nombre effectif de 65 au départ et non 77.

L'entraînement est plafonné à 20 000 lignes par classe pour garder un temps
d'exécution raisonnable, soit 125 007 lignes d'entraînement. Le test reste
complet. Les scores absolus de cette expérience ne sont donc pas directement
comparables à ceux des expériences 1 et 2 ; seules les variations entre
variantes sont interprétées.

La latence est la médiane de cinq appels `predict` sur un lot de 1 000 flux,
prétraitement inclus. Elle est mesurée sur un ordinateur portable, avec un cache
chaud, pas sur un équipement réseau. C'est une comparaison relative, pas un
test de référence pour un déploiement.

## 5.2 Performance

| Variante | Caractéristiques effectives | Macro-F1 binaire | Macro-F1 13 classes |
|---|---|---|---|
| Toutes | 65 | 0,9989 | 0,7708 |
| ≈ 75 % | 58 | 0,9989 | 0,7700 |
| ≈ 50 % | 39 | 0,9982 | 0,7658 |
| ≈ 25 % | 20 | 0,9963 | 0,7421 |
| Top-10 | 10 | 0,9928 | 0,6627 |

*Tableau 7 — Macro-F1 moyen par variante et par tâche, sur trois graines.*

![Macro-F1 en fonction du nombre effectif de caractéristiques : la chute est nette en 13 classes avec 10 variables.](figures/05_exp3_performance.png)

En binaire, la variante Top-10 conserve une Macro-F1 de 0,9928 contre
0,9989 avec toutes les caractéristiques : la réduction est presque
gratuite. En 13 classes, la chute est plus nette — de 0,7708 à
0,6627 — même si 39 caractéristiques maintiennent encore
0,7658. La réduction n'est donc pas gratuite pour les familles rares :
ce sont elles qui perdent leur rappel en premier, et ce sont elles que le
Macro-F1 pénalise.

\newpage

## 5.3 Coût d'inférence et coût d'ajustement

| Variante | Latence binaire (ms/1k) | Latence 13 classes (ms/1k) | Fit binaire (s) | Fit 13 classes (s) |
|---|---|---|---|---|
| Toutes | 33,25 | 33,99 | 1,73 | 2,54 |
| ≈ 75 % | 34,41 | 33,97 | 19,26 | 23,74 |
| ≈ 50 % | 33,69 | 33,95 | 20,21 | 23,85 |
| ≈ 25 % | 34,00 | 33,85 | 19,63 | 23,85 |
| Top-10 | 33,60 | 23,31 | 18,79 | 22,74 |

*Tableau 8 — Latence médiane de prédiction sur 1 000 flux et temps
d'ajustement moyen, par variante.*

![Latence médiane de prédiction pour 1 000 flux en fonction du nombre de caractéristiques.](figures/05_exp3_latency.png)

En binaire, la latence médiane reste plate : 33,25 ms avec toutes
les caractéristiques contre 33,60 ms en Top-10. En 13 classes,
elle baisse de 33,99 ms à 23,31 ms, mais la
dispersion entre graines est du même ordre que l'effet : le résultat est
fragile. Le coût dominant d'une random forest est la traversée des 300 arbres,
pas le nombre de caractéristiques.

Le tableau ajoute une nuance souvent oubliée : la sélection de caractéristiques
coûte du temps d'ajustement. On passe de 2,54 s avec toutes les
caractéristiques à 23,85 s avec 39 variables, parce que le calcul
de la mutual information n'est pas gratuit. La réduction aide à l'inférence et
à la mémoire, pas nécessairement à l'entraînement.

## 5.4 Verdict

**H3 est partiellement soutenue.** **Q3 :** quelques dizaines de
caractéristiques suffisent pour l'essentiel de la performance, mais le nombre
exact dépend de la tâche. En binaire, 10 variables suffisent presque ; en
13 classes, il faut plutôt viser 39 à 58 variables pour ne pas sacrifier les
familles rares. **Q4 :** pour le temps réel, les métriques utiles sont le rappel
sur la classe attaque, le FPR, la latence par lot et le débit ; pas l'accuracy.
Un modèle Top-10 est intéressant pour un capteur de bord, mais une random forest de
300 arbres reste probablement trop lente pour une inspection à plein débit sans
optimisation.

# 6. Explicabilité et analyse d'erreurs

La permutation importance est calculée sur le **test**, jamais sur le train :
on permute une colonne et on mesure la baisse du Macro-F1. Une caractéristique
importante est donc une caractéristique dont la destruction dégrade réellement
les prédictions sur des lignes non vues.

![Permutation importance sur le pli de test pour la random forest à 13 classes : en-têtes TCP, fenêtres et débit.](figures/06_xai_permutation_e1.png)

| Caractéristique | Importance moyenne | Écart-type |
|---|---|---|
| Init Fwd Win Bytes | 0,0226 | 0,0049 |
| Bwd Header Length | 0,0208 | 0,0000 |
| Init Bwd Win Bytes | 0,0192 | 0,0003 |
| Fwd Packets/s | 0,0144 | 0,0032 |
| Flow Bytes/s | 0,0136 | 0,0003 |
| Fwd Seg Size Min | 0,0109 | 0,0015 |
| Bwd Packets/s | 0,0103 | 0,0002 |
| Flow Duration | 0,0078 | 0,0078 |
| Packet Length Mean | 0,0065 | 0,0022 |
| Fwd Packet Length Min | 0,0051 | 0,0046 |

*Tableau 9 — Dix caractéristiques les plus importantes pour le modèle
multiclasses.*

Les premières caractéristiques sont des champs d'en-tête TCP et de fenêtre
(`Bwd Header Length`, `Init Fwd Win Bytes`, `Init Bwd Win Bytes`) ainsi qu'un
débit (`Flow Bytes/s`), pas les tailles moyennes de paquet ni les bulk-rates.
Cela explique à la fois le succès binaire et les confusions multiclasses : deux
familles qui partagent le même profil d'en-tête et de fenêtre sont difficiles à
séparer.

Sur les familles quasi parfaitement détectées (`DrDoS_SNMP`, `TFTP`), aucune
caractéristique unique ne porte le signal : l'importance est proche de zéro
pour chacune prise isolément, ce qui suggère un signal réparti sur plusieurs
colonnes. Syn est plus fragile : `ACK Flag Count`
(0,094), `Init Fwd Win Bytes`
(0,043) et `URG Flag Count`
(0,027) pèsent le plus. Le modèle
s'appuie donc sur des détails de drapeaux TCP qui ne se retrouvent pas dans les
familles vues à l'entraînement.

![Permutation importance pour trois familles tenues à l'écart : DrDoS_SNMP, TFTP et Syn.](figures/06_xai_permutation_e2.png)

Les galeries de faux positifs et de faux négatifs (`results/xai_fp_fn_e1.csv`,
`results/xai_fp_fn_e2_*.csv`) montrent ce que verrait un analyste : quelques
flux `Benign` avec un profil d'en-tête et de débit agressif, et des attaques Syn
à faible débit et faible taux de paquets. Les faux négatifs sur une famille
inconnue sont plus dangereux qu'une erreur d'attribution : aucune règle
existante ne couvre cette famille.

*Limite.* La permutation importance dépend du modèle et de l'échantillon de
test ; les caractéristiques corrélées se partagent le crédit. Les modèles XAI
sont réentraînés avec un plafond de 10 000 lignes par classe pour rester
exécutables ; leurs importances sont donc indicatives, pas exactes pour les
modèles sur données complètes. SHAP n'est pas installé sur Python 3.14 ; aucune
conclusion n'en dépend.

# 7. Discussion

## 7.1 Réponses aux questions

**Q1 — Quelles familles généralisent le mieux ?** Celles dont le profil
d'en-tête, de fenêtre TCP et de débit recouvre celui des familles vues. Dix
familles sur onze restent au-dessus de 0,96, mais Syn est l'exception pour la
random forest : ses flux sont prédits `Benign` ou `UDPLag`, et le rappel tombe
à 0,3041. La logistic regression, plus lisse, résiste mieux
(0,9733).

**Q2 — Un bon binaire suffit-il pour identifier le type d'attaque ?** Non. Le
binaire atteint 0,9991 en Macro-F1, le multiclasses
0,7566 avec le même modèle et les mêmes lignes. Un score
binaire quasi parfait ne prouve pas la compréhension des mécanismes.

**Q3 — Combien de variables sont nécessaires ?** En binaire, 10 variables
suffisent presque (0,9928 contre 0,9989). En 13 classes, il
faut viser 39 à 58 variables pour préserver les familles rares ; 10 variables
coûtent environ 14 % de Macro-F1. Le nombre dépend donc de la tâche, pas d'un
optimum unique.

**Q4 — Quels résultats comptent en temps réel ?** Le rappel sur la classe
attaque, le FPR, la latence par lot et le débit. Un modèle avec un excellent
Macro-F1 mais un FPR élevé est inutilisable en production ; un modèle avec un
bon F1 mais une latence de 100 ms par 1 000 flux ne tient pas la ligne. La
latence médiane mesurée ici, environ 33 ms pour 1 000 flux,
correspond à un débit de l'ordre de 30 000 flux par seconde sur un laptop, ce
qui reste insuffisant pour un lien à très haut débit sans accélération.

## 7.2 Implications opérationnelles

La première recommandation est architecturale : utiliser le binaire comme porte
de triage, puis un modèle de famille uniquement sur les alertes. Cela réduit le
volume à classifier et évite de payer le coût du multiclasses sur tout le
trafic.

La deuxième est de prévoir une classe « inconnue ». Un modèle de famille
entraîné sur un catalogue fermé produira toujours une étiquette, même pour une
attaque qu'il n'a jamais vue. La matrice de confusion vers les familles connues
montre que cette étiquette peut être `Benign` : c'est le pire cas. Une revue
humaine sur les alertes à faible confiance est donc nécessaire.

La troisième est de surveiller les métriques par famille, pas seulement le
score global. Un Macro-F1 de 0,95 peut cacher une famille à 0,60. Le rappel et
le FPR doivent être suivis séparément, et le modèle doit être réentraîné sur des
captures récentes avant tout déploiement.

## 7.3 Limites

- **Jeu de données de laboratoire.** CIC-DDoS2019 date de 2019 ; il ne contient
  ni trafic chiffré, ni dérive conceptuelle, ni adversaire qui adapte son
  attaque après avoir observé le détecteur.
- **Test équilibré en LOADO.** Le test 1:1 rend le rappel et le FPR comparables,
  mais la prévalence de production est très différente. Un FPR de 0,1 % sur un
  trafic majoritairement bénin peut représenter beaucoup d'alertes.
- **Support limité.** Cinq familles sont exclues des rotations LOADO par manque
  de lignes. Le résultat ne dit rien sur leur généralisation.
- **Bruit d'étiquettes.** 5 289 empreintes ont des étiquettes contradictoires ;
  certains flux sont indistinguables au niveau des caractéristiques.
- **Latence.** Mesurée sur un laptop, par lots, avec un cache chaud ; ce n'est
  pas un test de référence sur équipement réseau.
- **Nombre de graines.** La baseline et l'expérience 1 utilisent une seule
  graine ; les expériences 2 et 3 en utilisent trois. Les écarts inférieurs à
  quelques millièmes ne doivent pas être surinterprétés.
- **XAI.** Les modèles d'explicabilité sont plafonnés à 10 000 lignes par
  classe ; les importances sont indicatives.

## 7.4 Recommandations et travail futur

1. Déployer le binaire en premier étage, avec un seuil réglé sur le FPR cible
   du SOC, puis un modèle de famille sur les alertes uniquement.
2. Ajouter une classe « inconnue » et une revue humaine pour les prédictions
   peu confiantes.
3. Réduire les caractéristiques à 39–58 variables pour le multiclasses, et
   mesurer la latence de bout en bout avant de choisir un modèle.
4. Tester des modèles séquentiels ou des ensembles qui combinent la robustesse
   de la logistic regression et la précision de la random forest, en
   particulier pour Syn.
5. Réentraîner sur des captures récentes et surveiller la dérive, notamment sur
   les familles à faible support.

# 8. Utilisation de l'IA

Des outils d'IA générative ont été utilisés comme assistance pour structurer le
code, proposer des tests de cohérence, déboguer et améliorer la rédaction. Les
expériences, les chiffres, les figures et les conclusions proviennent des
notebooks exécutés dans ce dépôt. Aucun résultat affirmé sans exécution n'a été
conservé. Le groupe reste responsable de l'ensemble du travail et doit pouvoir
expliquer chaque choix méthodologique.

# 9. Conclusion

La réponse à la question centrale est nuancée : un modèle entraîné sur certaines
familles DDoS peut reconnaître une famille inconnue, mais cette capacité est
asymétrique. Dix familles restent bien détectées ; Syn s'effondre avec la random forest alors que la logistic regression résiste. Le binaire reste un bon
premier étage ; le multiclasses et l'attribution de famille sont les vrais
points durs.

Trois enseignements se dégagent. D'abord, un score binaire presque parfait ne
prouve rien sur la compréhension des types d'attaque : le passage à 13 classes
fait perdre environ 24 points de Macro-F1 à la random forest. Ensuite, la
généralisation dépend de la famille et du modèle : il faut lire le rappel par
famille et prévoir une classe « inconnue ». Enfin, la réduction de
caractéristiques est utile mais ne remplace pas un choix de modèle adapté au
temps réel : 39 variables suffisent pour l'essentiel, mais le coût dominant
reste la traversée des arbres.

Pour un SOC, les résultats les plus importants ne sont pas l'accuracy globale
mais le rappel sur les familles rares, le FPR et la latence. Le projet fournit
un protocole reproductible pour mesurer ces trois dimensions, et montre que la
généralisation à une famille inconnue est un problème de mesure autant que de
modélisation.

# Annexe A — Commandes de reproduction

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

Chaque notebook est autonome et écrit ses CSV dans `results/`.

# Annexe B — Fichiers de résultats

- `results/baseline_binary.csv`, `results/exp1.csv`
- `results/exp1_per_class.csv`, `results/exp2.csv`
- `results/exp2_confusion_to.csv`, `results/exp2_purge_audit.csv`
- `results/exp2_sibling_check.csv`, `results/exp3.csv`
- `results/exp3_feature_ranking.csv`, `results/xai_permutation_e1.csv`
- `results/xai_permutation_e2.csv`

# Annexe C — Glossaire

| Terme | Définition |
|---|---|
| **LOADO** | Leave-One-Attack-Out : une famille est retirée de l'entraînement, puis utilisée comme test. |
| **FPR** | Taux de trafic `Benign` classé DDoS (faux positifs). |
| **Macro-F1** | Moyenne non pondérée des F1 par classe ; chaque famille compte pareil. |
| **Weighted-F1** | Moyenne des F1 pondérée par le support ; favorise les classes fréquentes. |
| **PR-AUC** | Aire sous la courbe précision-rappel ; adaptée au déséquilibre. |
| **Empreinte** | Hash des 77 caractéristiques d'une ligne ; deux lignes avec la même empreinte sont identiques pour le modèle. |
| **Purge** | Retrait de toutes les lignes d'une famille, dans tous les fichiers, avant l'entraînement. |
| **Confusion-to** | Matrice qui indique à quelle famille connue une famille inconnue est confondue. |
| **Permutation importance** | Baisse de performance lorsqu'une caractéristique est mélangée aléatoirement sur le test. |
