# Soutenance — script 15 min + 5 min Q&R

## 0:00–1:00 — Titre et question (slide 1–2)
Bonjour. Notre question : un modèle entraîné sur certaines attaques DDoS
reconnaît-il une stratégie jamais rencontrée ? Trois hypothèses : H1 le
multiclasses est plus dur, H2 la généralisation dépend de la famille, H3 une
fraction des features suffit.

## 1:00–4:00 — Données et pièges (slides 3–5)
Le dataset contient 431 371 flux, 77 features, 17 familles. Deux pièges : les
doublons exacts (21 347 lignes) et le split publié qui partitionne par
mécanisme. Nous dédoublonnons avant le split et nous ignorons le split publié.
Le preprocessing est dans une pipeline ajustée sur le train seulement.

## 4:00–6:00 — Baseline (slide 6)
Le binaire est facile : Macro-F1 ≈ 0,999, avec un FPR de la forêt aléatoire
autour de 0,03 %. Une régression logistique suffit presque. Ce n'est pas une
preuve de compréhension des attaques.

## 6:00–8:30 — Expérience 1 (slides 7–8)
Mêmes lignes, mêmes modèles, seule la cible change. On passe de 0,999 à environ
0,75 en 13 classes. Le Weighted-F1 reste haut : les familles rares sont
oubliées. Retirer Protocol ne change presque rien : le modèle ne fait pas que
lire le protocole. Réponse à Q2 : non, un bon binaire n'est pas un bon
classifieur de famille.

## 8:30–12:00 — Expérience 2 (slides 9–11)
On tient à l'écart 11 familles, une par une. On purge la famille des 17
fichiers : par exemple Syn apparaît aussi dans UDPLag-training. Le test est
équilibré. Résultat : dix familles sur onze restent au-dessus de 0,96, mais Syn
s'effondre avec la RF (Macro-F1 ≈ 0,60) alors que la régression logistique la
détecte (≈ 0,97). La matrice de confusion-to montre que Syn est prédite Benign/UDPLag.
Réponse à Q1 : la majorité des familles généralisent, Syn est l'exception pour
la RF.

## 12:00–13:30 — Expérience 3 et XAI (slides 12–13)
Top-10 features conserve l'essentiel du F1 binaire, mais la chute est plus
nette en 13 classes et la latence du RF ne baisse que modestement : 300 arbres
dominent. Les features importantes sont les en-têtes TCP, les fenêtres
initiales et le débit.
Réponses Q3 et Q4 : quelques dizaines de features, et pour le temps réel il
faut regarder rappel, FPR, latence et débit.

## 13:30–15:00 — Réponses, limites et conclusion (slides 14–15)
Capture 2019, test équilibré, familles rares exclues, latence laptop. Le
binaire est un triage ; il faut une classe « inconnue » et une revue humaine.
Merci.

## Q&R — points à préparer
- Pourquoi le dédoublonnage change-t-il le split ? Parce que les mêmes flux
  seraient sinon dans train et test.
- Pourquoi ignorer le split publié ? Il partitionne par mécanisme.
- Pourquoi 11 familles ? Seuil de 1 000 lignes après dédoublonnage.
- Pourquoi le test E2 est-il équilibré ? Pour comparer FPR et rappel sans être
  dominé par Benign.
- Pourquoi Macro-F1 et pas accuracy ? Déséquilibre extrême.
- Pourquoi SHAP n'est-il pas utilisé ? Non installé sur Python 3.14 ;
  permutation importance sur test suffit à la spec.
