# Déploiement — l'ordre, les murs, la liste de contrôle

> Runbook d'exploitation (LOT prod, étape 7). Propriété : Exécuteur, sous `docs/ops/`.
> Le déploiement réel attend le vrai fournisseur de vérification et la bascule Scolaria —
> ce runbook rend le geste PRÊT, il ne le déclenche pas.

## 1. L'ordre — les migrations d'abord, le boot ensuite

**Le service ne migre JAMAIS au démarrage** (délibéré : une migration est un acte
d'exploitation, pas un effet de bord d'un boot). L'ordre est :

1. `npm ci && npm run build` (l'artefact embarque `.env.example` — le mur C8 en a besoin) ;
2. `npm run migrate` — sous `DATABASE_ADMIN_URL` (owner). Idempotent ; un checksum
   divergent REFUSE (une migration fusionnée est immuable) ;
3. démarrer l'API (`npm run start`) et le worker (`npm run start:worker`) — chacun rejoue
   ses murs de boot et **refuse** de démarrer si un seul manque.

## 2. `NODE_ENV` — rien à poser en production (F1)

Les murs de production sont **le défaut** : un déploiement réel ne pose PAS `NODE_ENV`.
Seuls `development` et `test` (déclarés) les relâchent — l'absence, une valeur vide, une
faute de frappe, un `staging` inconnu **arment**. Ne jamais « corriger » un refus de boot
en posant `NODE_ENV=development` sur un serveur : c'est désarmer tous les murs d'un coup.

## 2bis. `USER_CORE_SIMULATED_SEAMS` — ce qui SÉPARE la pré-production de la production

**Ce n'est pas un secret** : c'est la seule ligne du déploiement qui dise à voix haute
« ce serveur n'envoie encore rien pour de vrai ».

Deux des trois coutures de [CLAUDE.md §3.9](../../CLAUDE.md) n'ont, **mesuré au
21/08/2026**, qu'un seul implémenteur — et c'est un simulateur :

| Couture | Simulateur | Ce qu'il fait vraiment |
|---|---|---|
| `PROVING` | `LyingProver` | rend une référence inventée ; `record_proof_dispatch` enregistre un **succès** et sa ligne de coût. Aucun code n'atteint aucun téléphone. |
| `DISPATCH` | `CountingDispatcher` | empile en mémoire ; le publisher marque l'événement **publié** juste après. Aucune notification ne part — **préavis d'effacement à J-48 h compris**. |

Sous murs de production, chaque couture simulée doit être **nommée** dans la variable,
sinon **le boot est refusé** et le message dit laquelle. Une entrée inconnue
(`PROVER`, `proving`) est un **refus**, pas un silence. Le service **réécrit l'aveu dans
ses journaux à chaque démarrage** — la déclaration ne se perd pas dans un fichier que
plus personne ne relit.

```
# Pré-production (zéro utilisateur réel) — les deux coutures sont simulées :
USER_CORE_SIMULATED_SEAMS=PROVING,DISPATCH
```

🔴 **L'ACTE DE PASSAGE EN PRODUCTION.** Retirer une couture de cette liste **est** le geste
qui fait basculer le déploiement. Le service refusera alors de démarrer tant qu'aucun
fournisseur réel n'est branché — c'est l'effet voulu, pas une panne. **Une liste et non un
booléen**, parce que les deux coutures ont des calendriers de remplacement indépendants :
le jour où la preuve de ligne est réelle mais pas l'envoi sortant, on pose
`USER_CORE_SIMULATED_SEAMS=DISPATCH` **seul**.

⚠️ **Ce que ce mur NE fait PAS** : il ne fournit aucun fournisseur réel, et il ne détecte
pas un fournisseur mal configuré. Il garantit une seule chose — qu'un déploiement qui
simule l'ait **écrit**. Vérifier qu'un vrai fournisseur livre vraiment reste un acte de
liste de contrôle (§5), comme l'événement Sentry de test.

## 3. Les secrets — l'inventaire est LA référence

Les **10 secrets** (4 trousseaux, 2 jeux Ed25519, 2 mots de passe Postgres, DSN Sentry,
clé au repos du dépôt de sauvegardes)
sont inventoriés dans [SECRETS.md §2](SECRETS.md) — formats, commandes de génération,
cycles de vie. Rappels de déploiement :

- injection par l'ENVIRONNEMENT au déploiement, zéro SDK (doctrine C5) — et sa
  contrepartie : **toute rotation est un redéploiement** ([ROTATION.md](ROTATION.md)) ;
- chaque environnement génère SES valeurs — jamais un secret de production sur un poste
  de dev, jamais une valeur de `.env.example` en production (le boot le refuse, mur C8) ;
- TLS vers Postgres et rétention des supports de sauvegarde : exigences d'environnement
  non vérifiables par le service — [SECRETS.md §4](SECRETS.md) et
  [SAUVEGARDES.md §3bis](SAUVEGARDES.md).

## 4. Ce que le boot vérifie tout seul (et refusera)

Config incomplète (violations listées d'un bloc) · rôle Postgres non bridé · trousseaux
incomplets ou clés en collision (les 6 paires + intra) · clé d'empreinte désalignée de la
référence en base · secret publié par `.env.example` (murs armés) · DSN absent **ou
transport Sentry non armé** (murs armés) · **couture simulée non déclarée** (murs armés,
§2bis). Un boot qui refuse est un déploiement qui
n'était pas prêt — le corriger, jamais le contourner.

## 5. Liste de contrôle (avant d'ouvrir le trafic)

- [ ] migrations passées sous owner, `Schéma à jour`, zéro divergence de checksum ;
- [ ] API et worker démarrés — AUCUN refus de boot avalé ;
- [ ] CI verte **à la source** sur le SHA déployé (API check-runs, jamais une capture) ;
- [ ] sauvegardes planifiées, cible hors machine, `R` posé par Kevin —
      et **rétention des supports plafonnée à R** (H1, [SAUVEGARDES.md §3bis](SAUVEGARDES.md)) ;
- [ ] **pas de copie manuelle de dump hors du dépôt de sauvegarde** (H1) ;
- [ ] trousseau HMAC et dépôt de sauvegardes : deux endroits, deux accès
      ([SAUVEGARDES.md §3](SAUVEGARDES.md)) ;
- [ ] un événement Sentry de test reçu (provoquer une erreur bénigne) — « branché » se
      vérifie, il ne se suppose pas ;
- [ ] `USER_CORE_SIMULATED_SEAMS` **relu et assumé** : ce qui y figure ne part pas
      réellement (§2bis). En pré-production, les deux coutures y sont — c'est normal.
      **Le jour de la bascule, cette ligne se retire, et le boot refusera tant qu'aucun
      fournisseur réel n'est branché.**
