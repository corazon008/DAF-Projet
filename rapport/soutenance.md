# Script de soutenance — 15 minutes + 5 minutes de questions

Les durées sont indicatives : mieux vaut finir à 14 min 30 et garder de l'air
que de courir après le temps. Les chiffres sont ceux du rapport ; les arrondis
à l'oral sont volontaires.

## 0:00–0:40 — Slides 1–3 : question et hypothèses

Bonjour. Nous allons parler d'un problème très concret pour un SOC : un modèle
qui détecte une attaque DDoS sait-il reconnaître une attaque qu'il n'a jamais
vue ?

La détection binaire répond à « est-ce hostile ? ». Elle ne répond pas à
« quel mécanisme ? », et c'est pourtant cette seconde réponse qui détermine la
contre-mesure : un SYN flood ne se traite pas comme une amplification DNS.

Nous testons trois hypothèses. H1 : le multiclasses est plus difficile que le
binaire. H2 : la généralisation dépend de la famille laissée de côté. H3 : une
fraction des variables suffit, avec un coût d'inférence plus faible.

## 0:40–3:00 — Slides 4–6 : données, artefacts et protocole

Le jeu de données est CIC-DDoS2019 : 17 fichiers Parquet, 431 371 flux,
77 caractéristiques et 17 familles. Le déséquilibre est extrême : trois
familles font 74 % des lignes, et WebDDoS ne compte que 51 lignes. C'est
pourquoi nous lisons le Macro-F1 et le rappel par classe, pas l'accuracy.

Deux artefacts auraient rendu le résultat trompeur. Premier artefact :
21 347 lignes sont dans des groupes de doublons exacts, et 5 289 empreintes ont
des étiquettes contradictoires. Si on ne dédoublonne pas avant le split, la
même ligne peut être vue à l'entraînement et au test.

Deuxième artefact : le split publié `-training` / `-testing` n'est pas aléatoire.
Toutes les familles `DrDoS_*` sont dans `-testing`, alors que LDAP, MSSQL,
NetBIOS, Portmap et UDP sont dans `-training`. Utiliser ce split mesure la
reconnaissance d'un fichier, pas la généralisation. Nous l'écartons.

Notre protocole tient en cinq points : une ligne par empreinte, split aléatoire
stratifié 80/20, préprocessing dans une pipeline ajustée sur le train, purge de
la famille dans les 17 fichiers pour le LOADO, et test équilibré pour comparer
rappel et FPR.

## 3:00–4:15 — Slide 7 : baseline

La baseline binaire est presque parfaite : Macro-F1 de 0,999 pour le random
forest, 0,995 pour la logistic regression, avec un FPR de 0,03 % pour le random
forest. Une frontière linéaire suffit déjà. C'est un résultat utile, mais ce
n'est pas une preuve de compréhension : cela dit seulement que le trafic
offensif et le trafic bénin ne se ressemblent pas.

## 4:15–6:15 — Slides 8–9 : expérience 1

Pour l'expérience 1, nous gardons exactement les mêmes lignes, le même split,
les mêmes modèles et la même graine. Seule la cible change : binaire, puis
13 classes, puis 13 classes sans `Protocol`.

La random forest passe de 0,999 à 0,757 de Macro-F1. Le Weighted-F1 reste à
0,982 : les familles fréquentes sont bien classées, mais les familles rares
tirent le Macro-F1 vers le bas. WebDDoS a un rappel de zéro, Portmap de 0,46,
DNS de 0,53. Retirer `Protocol` ne change presque rien : 0,7577 contre 0,7566.
Le modèle ne fait donc pas que lire le protocole de transport.

Réponse à Q2 : non, un excellent binaire n'est pas nécessairement utile pour
identifier le type d'attaque. Une alerte binaire est une porte de triage.

## 6:15–9:45 — Slides 10–13 : expérience 2

L'expérience 2 est le cœur du projet. On tient à l'écart chacune des 11 familles
qui ont au moins 1 000 lignes après dédoublonnage. On purge la famille des
17 fichiers : par exemple, Syn apparaît aussi dans `UDPLag-training`. Si on ne
purge que le fichier homonyme, la famille n'est pas vraiment inconnue. Le test
est équilibré : toutes les lignes de la famille tenue à l'écart, plus un
échantillon apparié de `Benign`. Cela fait 99 fits.

Résultat : dix familles sur onze restent au-dessus de 0,96, et neuf au-dessus
de 0,99. Le meilleur score est atteint par DrDoS_MSSQL, 0,9995, à égalité avec trois autres familles. Mais Syn s'effondre à 0,6035
avec la random forest, avec un rappel de 0,30. Le FPR reste bas : ce n'est pas
la fausse alerte qui explose, c'est l'attaque qui n'est pas vue. Et ce n'est pas
seulement la famille : la logistic regression atteint 0,9733 sur Syn.

La matrice de confusion vers les familles connues explique le cas. Syn est
prédite `Benign` à 45 % et `UDPLag` à 42 %, pas une famille d'attaque unique.
La random forest a appris une frontière qui traite une partie des flux Syn
comme du trafic légitime. À l'inverse, DrDoS_MSSQL est prédite MSSQL à 83 % :
les paires réflexion/exploitation partagent bien une structure.

Nous avons aussi vérifié un point de robustesse : si on purge également la
famille sœur, LDAP avec DrDoS_LDAP par exemple, le minimum reste à 0,998. Le
résultat ne vient donc pas uniquement de la présence de la variante sœur.

Réponse à Q1 : les familles qui généralisent le mieux sont celles dont le profil
d'en-tête, de fenêtre TCP et de débit recouvre celui des familles vues. Syn est
l'exception pour la random forest. Pour un SOC, le cas dangereux n'est pas la
mauvaise étiquette, c'est l'alerte manquée.

## 9:45–11:30 — Slides 14–15 : expérience 3

L'expérience 3 demande combien de variables sont réellement nécessaires. Nous
comparons toutes les variables, 58, 39, 20 et les 10 meilleures. La sélection
est ajustée sur le train uniquement.

En binaire, le Top-10 conserve 0,993 de Macro-F1 contre 0,999 avec toutes les
variables : la réduction est presque gratuite. En 13 classes, 39 variables
maintiennent 0,7658 contre 0,7708 avec toutes, mais le Top-10 tombe à 0,6627.
La réduction n'est donc pas gratuite pour les familles rares.

Sur la latence, il faut être honnête : en binaire, elle ne baisse pas —
33,25 ms contre 33,60 ms pour 1 000 flux. En 13 classes, la médiane baisse de
34 à 23 ms, mais la dispersion entre graines est du même ordre que l'effet. Le
coût dominant d'une random forest de 300 arbres est la traversée des arbres, pas
le nombre de variables. Et la sélection elle-même coûte du temps d'ajustement :
2,5 s avec toutes les variables, 23,8 s avec 39.

Réponses à Q3 et Q4 : dix variables suffisent en binaire, 39 à 58 en
multiclasses. Pour le temps réel, il faut regarder le rappel attaque, le FPR, la
latence par lot et le débit, pas l'accuracy.

## 11:30–12:30 — Slide 16 : XAI

La permutation importance est calculée sur le test. Les variables qui comptent
le plus sont `Init Fwd Win Bytes`, `Bwd Header Length`, `Init Bwd Win Bytes` et
`Flow Bytes/s` : des en-têtes TCP, des fenêtres et du débit. Sur Syn, le modèle
s'appuie surtout sur `ACK Flag Count`, `Init Fwd Win Bytes` et `URG Flag Count` :
des détails de drapeaux TCP qui ne se retrouvent pas dans les familles vues.

Les galeries de faux positifs et de faux négatifs montrent ce que verrait
l'analyste : quelques flux bénins au profil agressif, et des attaques Syn à
faible débit. Un faux négatif sur une famille inconnue est plus dangereux qu'une
erreur d'attribution, car aucune règle existante ne la couvre.

## 12:30–14:15 — Slide 17 : réponses

En résumé. Q1 : la majorité des familles généralisent, Syn est l'exception pour
la random forest, et la logistic regression résiste mieux. Q2 : non, le binaire
ne suffit pas à identifier la famille. Q3 : quelques dizaines de variables
suffisent, mais le nombre dépend de la tâche. Q4 : rappel, FPR, latence et
débit sont les métriques de décision.

## 14:15–15:00 — Slides 18–19 : limites et conclusion

Les limites sont importantes. Le jeu de données est une capture de laboratoire
de 2019 : pas de trafic chiffré, pas de dérive, pas d'adversaire qui s'adapte.
Le test LOADO est équilibré 1:1, ce qui n'est pas la prévalence de production.
Cinq familles rares sont exclues par manque de support, et la latence est
mesurée sur un laptop.

Conclusion : le binaire est un bon premier étage, mais ce n'est pas un produit
de classification. La généralisation dépend de la famille et du modèle : il faut
une classe « inconnue » et une revue humaine. La réduction de variables aide,
mais le choix du modèle reste décisif pour le temps réel.

Merci. Nous sommes prêts pour vos questions.

# Préparation aux questions

## Pourquoi dédoublonner avant le split ?

Parce que 21 347 lignes sont dans des groupes de doublons exacts. Sans
dédoublonnage, la même ligne peut être dans le train et dans le test, et le
score mesure la mémorisation. Le dédoublonnage se fait par empreinte des
77 caractéristiques, pas par ligne brute.

## Pourquoi ignorer le split publié ?

Parce qu'il partitionne les mécanismes : toutes les familles `DrDoS_*` sont dans
`-testing`, et LDAP, MSSQL, NetBIOS, Portmap, UDP dans `-training`. Un modèle
peut reconnaître le fichier source plutôt que l'attaque. Ce n'est pas de la
généralisation à une famille inconnue.

## Pourquoi 11 familles seulement ?

Le seuil est de 1 000 lignes après dédoublonnage, pour que le rappel et le FPR
soient estimables. DrDoS_LDAP (993), Portmap (400), NetBIOS (374),
DrDoS_NetBIOS (311) et WebDDoS (49) sont exclues. C'est une contrainte
d'estimation, pas un jugement sur leur importance.

## Pourquoi un test équilibré en LOADO ?

Pour comparer le rappel et le FPR entre familles sans être dominé par `Benign`.
Avec la prévalence de production, le FPR paraîtrait plus faible et le rappel
inchangé, mais la lecture serait moins directe. C'est une limite assumée.

## Pourquoi le Macro-F1 et pas l'accuracy ?

Parce que le déséquilibre est extrême : trois familles font 74 % des lignes et
WebDDoS en a 51. L'accuracy récompense les classes fréquentes. Le Macro-F1 donne
le même poids à chaque famille, ce qui est le bon choix pour la sécurité.

## Pourquoi la random forest échoue-t-elle sur Syn alors que la logistic regression réussit ?

La random forest apprend une frontière non linéaire qui rapproche les flux Syn
de `Benign` ou `UDPLag` : la matrice confusion-to donne 45 % `Benign` et 42 %
`UDPLag`. La logistic regression garde une frontière plus lisse, qui déclenche
encore. C'est un effet modèle, pas seulement un effet famille.

## Pourquoi ne pas utiliser SHAP ?

SHAP n'est pas installé sur Python 3.14 dans notre environnement. La permutation
importance sur le test répond déjà à la question « quelles variables portent la
décision ? ». Aucune conclusion du rapport ne dépend de SHAP.

## Les scores de 0,999 ne sont-ils pas dus à une fuite ?

Non : le split est aléatoire après dédoublonnage, le préprocessing est ajusté sur
le train, et le test ne contient aucune ligne du train. Le score binaire élevé
vient de la séparation très nette entre trafic bénin et trafic offensif dans
cette capture de laboratoire. Les scores multiclasses, eux, sont beaucoup plus
bas, ce qui montre que le modèle ne mémorise pas tout.

## Pourquoi les latences varient-elles autant ?

Parce qu'elles sont mesurées sur un laptop, avec cinq appels par variante, et
que le système n'est pas isolé. Nous reportons la médiane sur trois graines et
nous interprétons seulement les écarts importants. Le message robuste est que
le nombre de variables n'est pas le facteur dominant pour une random forest.

## Les résultats de E3 sont-ils comparables à E1 et E2 ?

Non, pas directement : E3 plafonne l'entraînement à 20 000 lignes par classe
pour tenir le temps de calcul, alors que E1 et E2 utilisent tout le train.
E3 sert à comparer les variantes entre elles, pas à battre un record absolu.

## Pourquoi 65 variables et pas 77 ?

Douze colonnes sont constantes sur le pli d'entraînement et sont retirées par la
pipeline. Elles n'apportent aucune information et peuvent provoquer des
avertissements numériques.

## Qu'est-ce que le contrôle sibling ?

Dans les étiquettes fines, `LDAP` et `DrDoS_LDAP` sont deux labels mais un même
mécanisme. Le LOADO principal ne purge que le label tenu à l'écart. Le contrôle
purge aussi le label frère : le minimum reste à 0,998, donc le résultat ne vient
pas uniquement de cette proximité.

## Que feriez-vous ensuite ?

D'abord déployer le binaire comme premier étage avec un seuil réglé sur le FPR
cible. Ensuite ajouter une classe « inconnue » et une revue humaine sur les
alertes peu confiantes. Enfin réentraîner sur des captures récentes et tester la
dérive, en particulier sur les familles à faible support.

## Pourquoi une seule graine pour la baseline et E1 ?

Pour garder E1 strictement comparable à la baseline : mêmes lignes, mêmes
modèles, même graine. E2 et E3, qui portent sur la variabilité, utilisent trois
graines. Les écarts inférieurs à quelques millièmes en E1 ne sont pas
surinterprétés.
