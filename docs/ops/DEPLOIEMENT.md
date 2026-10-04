# Déploiement — l'ordre, les murs, la liste de contrôle

> Runbook d'exploitation (LOT prod, étape 7). Propriété : Exécuteur, sous `docs/ops/`.
> Le déploiement réel attend le vrai fournisseur de vérification et la bascule Scolaria —
> ce runbook rend le geste PRÊT, il ne le déclenche pas.

## 1. L'ordre — les migrations d'abord, le boot ensuite

**Le service ne migre JAMAIS au démarrage** (délibéré : une migration est un acte
d'exploitation, pas un effet de bord d'un boot). L'ordre est :

1. `npm ci && npm run build` (l'artefact embarque `.env.example` — le mur C8 en a besoin) ;
2. `npm run migrate` — sous `DATABASE_ADMIN_URL` (owner). Idempotent ; un checksum
   divergent REFUSE (une migration fusionnée est immuable). En conteneur, l'image n'a pas
   `ts-node` : `node dist/scripts/migrate.js`, par le service outil du compose (§7) ;
3. démarrer l'API (`npm run start`) et le worker (`npm run start:worker`) — chacun rejoue
   ses murs de boot et **refuse** de démarrer si un seul manque.

## 2. `NODE_ENV` — rien à poser en production (F1)

Les murs de production sont **le défaut** : un déploiement réel ne pose PAS `NODE_ENV`.
Seuls `development` et `test` (déclarés) les relâchent — l'absence, une valeur vide, une
faute de frappe, un `staging` inconnu **arment**. Ne jamais « corriger » un refus de boot
en posant `NODE_ENV=development` sur un serveur : c'est désarmer tous les murs d'un coup.

**Ce que l'absence de `NODE_ENV` fait à Express (C10, lu et mesuré le 04/10/2026).** Express
se met alors en « development » (Express 5.2.1, `lib/application.js`, `defaultConfiguration` :
`process.env.NODE_ENV || 'development'`), et sa page d'erreur finale montrerait la pile
(finalhandler 2.1.1, `getErrorMessage` : `env !== 'production'`). **Nest intercepte les
erreurs avant elle** : à l'initialisation, `registerRouterHooks` pose son gestionnaire des
routes inconnues et son gestionnaire d'erreurs sur l'adaptateur Express (Nest 11.1.28,
`router/routes-resolver.js`, `registerNotFoundHandler` et `registerExceptionHandler`).
**Aucune exposition mesurée** : sous murs armés, dans l'image de la pré-production, une
route inconnue (404), un paramètre mal encodé (400), un JSON mal formé (400) et un corps
non JSON (415) reçoivent tous une réponse JSON, sans pile ni HTML. **F1 est maintenue.**
*Réouverture* : une route ou un gestionnaire d'erreur Express né hors de Nest — alors
l'environnement d'Express se dérive du prédicat unique `productionWallsArmed()`, jamais de
`NODE_ENV`.

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
§2bis) · **aiguilleurs non déclarés** (`USER_CORE_TRUSTED_PROXIES` absente ou vide, murs
armés ; toute valeur déclarée est validée dans tous les modes — « 1 » refusé, §6) ·
**adresse d'écoute non déclarée** (`USER_CORE_LISTEN_HOST`, murs armés ; « localhost »
refusé dans tous les modes, §6). Un boot qui refuse est un déploiement qui
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
- [ ] `USER_CORE_TRUSTED_PROXIES` et `USER_CORE_LISTEN_HOST` posés selon le mode
      d'exécution (§6.3) — en conteneur, la passerelle **MESURÉE**, jamais `127.0.0.1` ;
- [ ] 🔴 **vérification bloquante n°1** : deux sources différentes ⇒ deux budgets (§6.4) ;
- [ ] 🔴 **vérification bloquante n°2** : le port du service est injoignable depuis
      l'extérieur, et n'écoute que sur `127.0.0.1` côté hôte (§6.4) ;
- [ ] après le démarrage et la vérification n°1 : **aucune** ligne `[ADRESSE CLIENTE]`
      dans les journaux (signaux A3 / A3bis — un aiguilleur mal déclaré, §6.3).

## 6. L'aiguilleur, HTTPS et l'écoute

> Lot déploiement, étape 2 (03/10/2026). Faits du serveur : **sources**, jamais
> suppositions — `docs/DEPLOYMENT_API_VPS.md` du dépôt Scolaria_Api (PR #173, fusion
> `e69f693f`, relevé du 03/10/2026) et la réponse de l'Auditeur Scolaria du même jour
> (`docker ps`, `ss -ltnp`, nginx, UFW, essais depuis l'extérieur). **Ces faits se
> re-MESURENT sur le serveur à chaque bascule** (commandes ci-dessous) : un relevé daté
> vieillit.

### 6.1 Le principe

- **HTTPS se termine à l'aiguilleur** (nginx sur l'hôte). Le service parle **HTTP** sur
  `PORT`, et n'est joignable que par l'aiguilleur.
- Le service ne croit l'en-tête `X-Forwarded-For` **que** s'il arrive d'une adresse
  déclarée dans `USER_CORE_TRUSTED_PROXIES` (point unique :
  `src/client-address/client-address.ts`). Trop peu de confiance : tous les clients
  partagent l'adresse de l'aiguilleur, et chaque plafond par adresse devient un plafond
  **global** — un levier de déni de service. Trop de confiance : n'importe quel client
  écrit l'adresse de son choix et contourne tout plafond.
- 🔴 **EXIGENCE sur l'aiguilleur** : il met l'adresse qu'il voit en **DERNIÈRE** position
  de `X-Forwarded-For` — en écrasant l'en-tête (patron Scolaria :
  `proxy_set_header X-Forwarded-For $remote_addr;`) ou en ajoutant
  (`$proxy_add_x_forwarded_for`). **S'il retransmet l'en-tête du client tel quel, la
  dernière entrée devient forgeable, et aucun code ne peut le voir.** Recommandé :
  l'écrasement, comme Scolaria — un seul saut, rien à démêler.

### 6.2 Les faits du serveur (relevés du 03/10/2026, à re-mesurer)

| Fait | Relevé | Source |
|---|---|---|
| Machine | VPS Hostinger **partagé avec Scolaria** ; `api.scolaria.io` = `187.77.183.20`, **aucun AAAA** | relevé de l'Auditeur User-Core depuis l'extérieur, 03/10/2026 16:23 : A = 187.77.183.20, aucun AAAA ; 22, 80 et 443 répondent ; 3000, 5432 et 6379 sans réponse en 4 s |
| Hébergeur | **Hostinger** : `187.77.176.0/21` et `2a02:4780:f::/48` = `HOSTINGER-HOSTING`, titulaire `MNT-HOSTINGER`, `country: GB` | registre RDAP du RIPE (`rdap.db.ripe.net`, par l'amorçage IANA de `rdap.org`), mesuré le 04/10/2026 à 18:53 par l'Exécuteur — même résultat que le relevé de l'Auditeur du même jour à 08:52 |
| IPv6 globale | `2a02:4780:f:7ed4::1` : seul `sshd` y écoute | Auditeur Scolaria (`ss -ltnp`) |
| Scolaria | en **conteneurs** (compose HORS dépôt, `/opt/scolaria/docker-compose.yml`), ports publiés sur **127.0.0.1 seulement** : **3000** (API), **5432** (Postgres), **6379** (Redis) | `DEPLOYMENT_API_VPS.md` §1 |
| Aiguilleur | **nginx sur l'hôte**, un site par nom (`/etc/nginx/sites-enabled/…`), **IPv4 seulement**, `proxy_set_header X-Forwarded-For $remote_addr;` | idem, et réponse Scolaria |
| Pare-feu | **UFW** refuse par défaut, n'ouvre que **22, 80, 443** (IPv4 et IPv6) ; depuis l'extérieur, seuls 22/80/443 répondent | idem |

⚠️ **`country: GB` est le pays d'ENREGISTREMENT du bloc d'adresses, jamais un LIEU** : il ne
dit pas où se trouve la machine. La résidence des données d'identité reste une question
ouverte (CDC §9 n°3), et un registre d'adresses ne la tranche pas.

⚠️ **Les ports publiés par Docker CONTOURNENT UFW** : les règles de Docker passent avant
celles d'UFW. Un port publié sans `127.0.0.1:` est joignable depuis Internet, pare-feu ou
pas. D'où la règle : **toute publication porte `127.0.0.1:`**.

### 6.3 Le mode d'exécution — deux modes, une valeur par variable

Les ports de l'hôte **3000, 5432 et 6379 sont PRIS par Scolaria**. Tout port ci-dessous
est une **PROPOSITION**, à vérifier libre **avant** usage :

```bash
ss -ltnp | grep -E ':(3100|3101) '   # attendu : aucune ligne avant la mise en place
```

| Variable | Hors conteneur (processus Node sur l'hôte) | En conteneur (comme Scolaria) |
|---|---|---|
| `PORT` | `3100` (proposition) | `3000` dans le conteneur ; publié `127.0.0.1:3100:3000` |
| `USER_CORE_LISTEN_HOST` | **`127.0.0.1`** — seul l'hôte joint le port | **`0.0.0.0`** — toutes les interfaces DU CONTENEUR ; la restriction est la publication sur `127.0.0.1` de l'hôte |
| `USER_CORE_TRUSTED_PROXIES` | **`127.0.0.1`** — nginx joint le service par la boucle locale | **l'adresse de la PASSERELLE du réseau Docker**, MESURÉE (ci-dessous) — **jamais `127.0.0.1`** |
| nginx | `proxy_pass http://127.0.0.1:3100;` | `proxy_pass http://127.0.0.1:3100;` |
| Pare-feu | **aucune ouverture UFW de plus** : le 443 est déjà partagé par nginx | idem |

🟠 **EN CONTENEUR, L'AIGUILLEUR N'EST EN GÉNÉRAL PAS VU EN 127.0.0.1.** nginx joint le
port publié sur l'hôte, et le conteneur voit la connexion arriver depuis la **passerelle
du réseau Docker** (le relais de Docker la ré-émet). Déclarer `127.0.0.1` recréerait **en
silence** le plafond global — c'est exactement ce que le signal **A3bis**
(`FORWARDED_FROM_UNDECLARED_LOCAL_SOURCE`) existe pour signaler. Donc :

1. **Fixer le sous-réseau et la passerelle dans le compose**, pour qu'ils survivent à la
   recréation du réseau (sans cela, Docker en tire de nouveaux, et la déclaration ment) :
   ```yaml
   networks:
     user-core:
       ipam:
         config:
           - subnet: 172.30.0.0/24    # PROPOSITION — vérifier qu'aucun réseau existant ne la chevauche
             gateway: 172.30.0.1
   ```
   ```bash
   docker network ls -q | xargs docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'
   ```
2. **MESURER l'adresse vue, ne pas la supposer** : la passerelle se lit
   (`docker network inspect <réseau> -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'`),
   puis se **prouve** par la vérification bloquante n°1 (§6.4) — une déclaration fausse y
   donne un seul budget pour tout le monde ; et après le démarrage, **aucun** signal
   `[ADRESSE CLIENTE] FORWARDED_FROM_UNDECLARED_LOCAL_SOURCE` dans les journaux.
3. **Le Postgres de User-Core n'est PAS publié sur l'hôte**, même sur `127.0.0.1` : le
   service le joint par le réseau du compose ; les migrations et les sauvegardes passent
   par `docker compose run --rm` / `docker compose exec -T postgres …` (patron Scolaria,
   `DEPLOYMENT_API_VPS.md` §3). Un port de base publié sur un serveur partagé est une
   porte de plus pour tout programme du serveur — et aucun usage ne la réclame.

**Le tableau nom → aiguilleur → port** (nom **provisoire** `swoi.app`, mots de Kevin du
27/09/2026 : *« J'ai "swoi.app" comme choix 1 pour le moment »* ; les sous-adresses sont
des **propositions**, le choix est à Kevin) :

| Nom (proposition) | Usage | Aiguilleur | Port d'hôte (proposition) | Vérification |
|---|---|---|---|---|
| `id-preprod.swoi.app` | pré-production, **maintenant** (zéro utilisateur réel) | nginx de l'hôte, site dédié, 443 partagé, certificat propre au nom | `127.0.0.1:3100` | `ss -ltnp \| grep ':3100 '` → `127.0.0.1:3100` seulement |
| `id.swoi.app` | production, **plus tard** | idem | `127.0.0.1:3101` | `ss -ltnp \| grep ':3101 '` → `127.0.0.1:3101` seulement |

⚠️ **La ligne `id.swoi.app` ne vaut que SI la production vit sur cette machine — et ce
n'est PAS décidé.** La rétention effective des sauvegardes `R` est un **critère de choix
d'hébergeur**, à poser avant la signature ([CAHIER_DES_CHARGES.md](../CAHIER_DES_CHARGES.md)
§9 n°5 et §10 n°17), et la résidence des données d'identité reste une question ouverte
(§9 n°3). Seule la pré-production est prévue ici.

Chaque environnement a SA base, SES secrets, SON compose (séparation dev / pré-production
/ production, CLAUDE.md §6). Chaque nom pointe en **A** vers la machine qui le sert ; **pas
d'AAAA** tant que nginx n'écoute qu'en IPv4.

### 6.4 Les deux vérifications BLOQUANTES — avant d'ouvrir le trafic

**N°1 — deux sources différentes ⇒ deux budgets.** Depuis un premier réseau (source A),
`N` = le budget de connexion déployé + 1 (`AUTH_THROTTLE_MAX_ATTEMPTS`, 10 par défaut ⇒
11 requêtes), chacune avec un **identifiant neuf** (sans quoi le compteur par identifiant
refuserait à la place de l'adresse) :

```bash
H=id-preprod.swoi.app
for i in $(seq 1 11); do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST "https://$H/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"identifier\":\"verif-$i-$RANDOM$RANDOM\",\"secret\":\"verification-sans-compte\"}"
done
# attendu : dix 401, puis 429
```

Puis, **dans la même minute**, depuis un second réseau (source B — un partage de connexion
mobile, par exemple) : une seule requête ⇒ **401**. **Un 429 en B = un seul budget pour
tout le monde : la déclaration est fausse. STOP** — ne pas ouvrir.

**N°2 — le port du service est INJOIGNABLE depuis l'extérieur.** Depuis un réseau tiers :

```bash
nc -vz -w 4 187.77.183.20 3100                # attendu : échec (aucune connexion en 4 s)
curl -s --connect-timeout 4 http://187.77.183.20:3100/health; echo "exit=$?"   # attendu : exit non nul
```

et sur le serveur :

```bash
ss -ltnp | grep -E ':(3100|3101) '            # attendu : 127.0.0.1 seulement — jamais 0.0.0.0 ni [::]
docker ps --format '{{.Names}}\t{{.Ports}}'   # en conteneur : 127.0.0.1:3100->3000/tcp
grep -n 'X-Forwarded-For' /etc/nginx/sites-enabled/<site User-Core>   # attendu : l'adresse vue en DERNIER
```

⚠️ Comme pour Scolaria au 03/10/2026, l'IPv6 n'a pas pu être essayée depuis l'extérieur
faute de réseau d'essai IPv6 : la refaire depuis un réseau IPv6 quand il en existe un
(`nc -6 -vz -w 4 2a02:4780:f:7ed4::1 3100`), et l'écrire **non vérifiée** sinon.

### 6.5 Ce que ce lot NE fait PAS (leçon ⑫)

- **Un aiguilleur qui retransmet l'en-tête du client tel quel** : la dernière entrée
  devient forgeable, et aucun code ne peut le voir. C'est l'exigence du §6.1, vérifiée par
  le `grep` du §6.4, pas par le service.
- **Le partage d'adresse des opérateurs mobiles (CGNAT)** : beaucoup de clients derrière
  une même adresse IPv4 publique partagent un budget. Inconnue de terrain RDC (CLAUDE.md
  §3.11) : les seuils sont des **paramètres**, jamais une valeur supposée.
- **Un abonné IPv6 dispose d'un /64 entier** : chaque adresse du préfixe a son propre
  budget ; le plafond ne regroupe pas par préfixe.
- **Aucun CORS** n'est posé par ce lot.
- **Rien ici ne vit en base** : les compteurs sont en mémoire, par processus — un
  redémarrage les remet à zéro, deux instances ne les partagent pas.
- 🟠 **Sur un serveur partagé, faire confiance à la boucle locale ou à une passerelle
  revient à faire confiance à TOUT programme du serveur, Scolaria comprise** : n'importe
  quel processus local peut joindre le port du service et y écrire l'adresse de son choix.
- **Un programme co-hébergé qui appelle le port en direct** (sans passer par nginx)
  arrive de l'adresse de l'aiguilleur, sans en-tête : il **partage le budget de cette
  adresse**, et sur les routes publiques il lève le signal A3
  (`DECLARED_PROXY_WITHOUT_CLIENT`). Le chemin d'un programme est le nom public, comme
  pour tout client.
- **Le détecteur de largeur ne voit pas une plage publique étroite mais fausse** : il
  attrape les listes qui croiraient une moitié d'Internet ; un /24 qui n'est pas le nôtre
  passe. Seule la vérification n°1 prouve que la liste est la bonne.
- **`USER_CORE_LISTEN_HOST` ne remplace pas le pare-feu** : il borne l'écoute du service,
  pas celle des autres programmes du serveur.

## 7. La pré-production sur le serveur partagé avec Scolaria

> Lot déploiement, étape 3. Écrit le 04/10/2026, **avant tout geste sur le serveur**.
> Fichiers : `Dockerfile`, `.dockerignore`, `deploy/preprod/`. **Un fait du serveur s'écrit
> APRÈS sa mesure** : là où il manque, ce texte dit « à relever à l'étape N », jamais une
> valeur qui ressemblerait à une mesure. La procédure est celle **répétée sur le poste** le
> 04/10/2026 ; elle se relit et se corrige après les étapes 3 à 5, telle que jouée.

### 7.1 Ce qui distingue la pré-production

| | Décision | Pourquoi |
|---|---|---|
| **C6** | **AUCUNE donnée personnelle réelle**, numéros de téléphone des testeurs compris | les deux coutures sont simulées (§2bis) et rien de ce qui protège une famille réelle n'est en place (§7.11) : le jour où une vraie donnée entre, ce n'est plus une pré-production |
| **C7** | **AUCUNE sauvegarde** (décision de l'Auditeur) | pas de donnée réelle ; la base se recrée par les migrations. `R` n'est pas touchée : elle reste à Kevin ([SAUVEGARDES.md](SAUVEGARDES.md) §2) |
| **C8** | **Pas de TLS vers Postgres** | Postgres est local au réseau du compose et **jamais publié** ; l'exigence `sslmode=require` de [SECRETS.md §4](SECRETS.md) vise une base **distante** |
| **C9** | **Un projet Sentry PROPRE** (`user-core-preprod`) | `sentry.ts` étiquette « production » tout environnement armé : deux environnements dans un même projet seraient indiscernables |
| | **Les réglages sont les DÉFAUTS DU CODE** | aucun n'est posé, ni dans `service.env` ni dans le compose. Mesuré le 04/10/2026 à 18:53 : les 37 lectures numériques à défaut du code égalent les valeurs de `.env.example` |
| | **Les deux coutures sont simulées, et DÉCLARÉES** | `USER_CORE_SIMULATED_SEAMS: "PROVING,DISPATCH"` dans le compose versionné (§2bis) |

### 7.2 L'étape 0 — les relevés, en lecture seule

**L'accès** : root, avec une clé **ed25519 dédiée** à User-Core. La partie privée ne quitte
jamais le poste et n'entre dans aucun dépôt ; la ligne publique porte le commentaire
`user-core-preprod`. **Révoquer cet accès = supprimer cette ligne** de
`/root/.ssh/authorized_keys`. L'accès de Scolaria ne sert qu'une fois, sur le « oui » de
Kevin, à poser cette clé : un seul ajout, vérifié (une ligne de plus ; empreinte sha256 de la
partie existante identique avant et après). Ensuite, il n'est plus jamais utilisé.

**La pose passe par `deploy/preprod/add-authorized-key.sh`**, joué côté serveur depuis son
BLOB (`git show <SHA>:…`, jamais la copie de travail, qui peut être en CRLF), la ligne
publique sur l'entrée standard. Le script refuse si sshd ne lit pas `.ssh/authorized_keys`.
Il mesure AVANT : lignes, octets, sha256, droits et propriétaire. 🔴 **Il contrôle la fin de
ligne finale d'`authorized_keys` AVANT l'ajout** : sans elle, la clé se COLLERAIT à la
dernière clé existante — peut-être celle de Scolaria — et la casserait. Si elle manque, il
l'ajoute. Il mesure APRÈS, et chaque contrôle est une égalité exigée.

La clé n'a **pas de phrase de passe**, parce que les sessions ne sont pas interactives : **sa
protection est celle du poste**, comme pour la clé de Scolaria. Créée sur le poste le
04/10/2026 à 21:04, empreinte `SHA256:GwrYFevh0TQ4NYD4E9zGjzQU34VYy3Nu+PzSLGYmcBA`. Elle ne
sert que par l'alias `user-core-preprod` de `~/.ssh/config`, ajouté en fin de fichier (la
partie existante vérifiée identique, sha256 avant et après). Cet alias porte
`IdentitiesOnly yes` — la clé GitHub, identité PAR DÉFAUT d'ssh, n'est jamais offerte au
serveur —, `BatchMode yes` et `StrictHostKeyChecking yes` : l'empreinte d'hôte est déjà
connue du poste (`ED25519 SHA256:Mqu5eOxo…kp14`), aucune autre n'est acceptée. **La preuve de
la séparation** se lit au journal d'authentification du serveur : la clé ACCEPTÉE est
celle-ci, ni celle de Scolaria, ni celle de GitHub — empreinte et heure seulement, jamais
l'adresse d'origine.

| Relevé | Commande | Valeur |
|---|---|---|
| système, architecture, processeurs | `cat /etc/os-release` · `uname -m` · `nproc` | à relever à l'étape 0 |
| le `/bin/sh` du serveur (C19) | `readlink -f /bin/sh` | à relever à l'étape 0 |
| mémoire disponible | `free -m` (colonne *available*) | à relever à l'étape 0 |
| disque | `df -h / /var/lib/docker` | à relever à l'étape 0 |
| ports 3100 et 3199 libres | `ss -ltnp` | à relever à l'étape 0 |
| Docker, compose, relais userland | `docker version` · `docker compose version` · `/etc/docker/daemon.json` (lecture) · `pgrep -a docker-proxy` | à relever à l'étape 0 |
| sous-réseaux existants | `docker network inspect` de chaque réseau | à relever à l'étape 0 |
| Scolaria AVANT | `docker ps` | à relever à l'étape 0 |
| nginx | `nginx -v` · `ls -l /etc/nginx/sites-enabled/` · `nginx -T` **filtré** sur `server_name\|listen\|ssl_certificate\|ssl_protocols\|ssl_ciphers\|proxy_pass\|X-Forwarded-For` | à relever à l'étape 0 |
| certificats | `certbot certificates` (filtré) et ses minuteries | à relever à l'étape 0 |
| pare-feu | `ufw status verbose` | à relever à l'étape 0 |
| tâches planifiées qui agissent sur Docker, nginx ou certbot | `crontab -l` de root et `/etc/cron.d/*`, FILTRÉS sur `docker\|nginx\|certbot` — on relève, on n'y touche pas. La procédure de Scolaria en nomme une : `docker image prune -f --filter until=24h`, qui « ne touche pas aux images taguées » (Scolaria_Api `main` @ `3845a2ff`, `docs/DEPLOYMENT_API_VPS.md` §3) | à relever à l'étape 0 |

**Arrêt et rapport** si : un port est pris, un sous-réseau chevauche `172.30.0.0/24`, le
relais userland est inactif, la méthode de certificat diffère, la mémoire ou le disque
manquent, l'architecture n'est pas celle attendue.

### 7.3 L'image

- **La base est épinglée par empreinte**, relevée le 04/10/2026 à 16:21 (index
  multi-architecture) : `node:22-bookworm-slim@sha256:43ac6c60…772c` (Node 22.23.3) et
  `postgres:15@sha256:724292da…3550` (15.19). **Changer une empreinte** : la relire
  (`docker buildx imagetools inspect <image>:<étiquette>`), la remplacer dans le
  `Dockerfile` ou le compose, reconstruire, et rejouer les preuves de contenu ci-dessous.
- **Trois étapes** : les dépendances de production, la construction, l'exécution. L'image
  d'exécution n'exécute aucun `npm`. Elle reçoit `dist/src`, `dist/scripts`, `db/` (sous
  `dist/db`, où le runner de migrations le cherche) et `.env.example` à la racine du
  répertoire de travail (le mur C8 le lit dans le répertoire courant). Utilisateur `node`,
  **aucun `NODE_ENV`** (§2).
- **Le contexte de construction est fermé par défaut** (`.dockerignore` en liste
  d'admission). Mesuré le 04/10/2026 : 109 fichiers, exactement les fichiers suivis des
  chemins admis.
- **C15 — le mur des scripts d'installation.** `npm ci --ignore-scripts`, parce que le
  `prepare` du dépôt appelle `git`, absent de l'image. La construction **échoue** si les
  paquets installés que le verrou marque `hasInstallScript` diffèrent de
  `{node_modules/argon2}`, dans un sens ou dans l'autre. La ligne « contrôle C15 : … —
  conforme » du journal de construction prouve que le contrôle a tourné. **Un écart se
  tranche**, jamais en allongeant la liste par réflexe.
- **C3 et C18 — les preuves de contenu, rejouées sur l'image DU SERVEUR**, jamais sur celle
  d'une répétition. La liste des fichiers se lit par `docker create` puis
  `docker export | tar -t`, en comptes, jamais en entier. Elle doit montrer : aucun `.env`
  hors `.env.example`, aucun `tests/`, aucune source `.ts` hors `node_modules`, aucune
  dépendance de développement, et 33 migrations. `argon2` se charge, ce que le démarrage
  prouve. **Identifiant de l'image : à relever à l'étape 3**, écrit ici à côté du SHA déployé
  (C11).
- **C4 — où construire.** Pic mesuré sur le poste le 04/10/2026 : **≈ 1 052 Mio** sans
  plafond, cache de pages compris ; la construction tient aussi sous un plafond dur de
  512 Mio sans swap. **On retient le chiffre prudent** : sur le serveur, rien ne plafonne la
  construction, à côté de la production de Scolaria. Donc *available* ≥ 2,1 Gio à l'étape 0 →
  construction sur le serveur. **C4bis** : la mémoire disponible se RE-MESURE juste avant la
  construction, parce qu'une mise en production de Scolaria peut tomber entre l'étape 0 et
  l'étape 3 ; moins de 2,1 Gio à cet instant ⇒ repli sur le poste, sans discussion. Le repli :
  construction **sur le poste**, depuis l'arbre EXACT du SHA, puis transfert, architecture
  vérifiée :
  ```bash
  git -c core.autocrlf=false archive <SHA> | tar -x -C <répertoire vide>
  # AVANT de construire : 0 fichier différent du blob. Sous core.autocrlf=true, « git archive »
  # seul écrit l'arbre en CRLF — 217 fichiers sur 217, mesuré le 04/10/2026.
  docker build -t user-core-preprod:local <répertoire>
  docker save user-core-preprod:local | ssh <hôte> docker load
  ```

### 7.4 Les secrets — ils naissent SUR le serveur

- **`generate-secrets.sh <répertoire>`** écrit `admin.env` (Postgres et migrate seulement) et
  `service.env` (l'API et le worker), en 600 : les quatre trousseaux, la clé de signature
  Ed25519, les deux mots de passe. La clé d'empreinte porte l'identifiant **`H1`** : il est
  gravé par `006`, et `assertFingerprintKeyAligned` refuse tout autre. **Aucune valeur n'est
  affichée** ; le script refuse d'écraser, et n'écrit rien si un tirage échoue.
- **`app-role-password.psql`** pose le mot de passe du rôle bridé **après** les migrations
  (`001` crée le rôle sans mot de passe). La valeur se lit dans l'environnement du conteneur
  Postgres (`\getenv`), jamais dans une ligne de commande. Le journal du serveur recopie
  d'ordinaire une instruction en échec. Mesuré le 04/10/2026 : 1 copie sans réglage, 0 avec
  `SET log_min_error_statement = panic`, posé avant toute instruction qui porte la valeur.
- **`add-sentry-dsn.sh <fichier du DSN> <service.env>`** (C17). Il retire le BOM et les CR,
  exige **exactement une** ligne, contrôle la forme par un compte
  (`https://<32 hexadécimaux>@<hôte>/<identifiant>`), refuse si un DSN existe déjà et écrit
  de façon atomique ; chaque contrôle échoue fermé. 🔴 **Jamais un DSN de répétition sur le
  serveur** : il satisferait le mur G1, et ferait exactement ce que G1 existe pour empêcher —
  un service aveugle qui se croit surveillé (leçon ⑨). Postgres, les migrations et
  l'`ALTER ROLE` peuvent précéder le DSN ; **l'API et le worker attendent le vrai**.
- **C19 — chaque script de `deploy/` se joue d'abord À BLANC sous le `/bin/sh` du serveur.**
  `add-sentry-dsn.sh` tourne d'abord sur un DSN **fabriqué** et une copie fabriquée de
  `service.env`, dans un répertoire jetable : accepté, 1 ligne, 0 CR ; puis un refus provoqué
  (deux lignes). Ensuite seulement, le vrai DSN. Sur le poste, le 04/10/2026 : mêmes verdicts
  sous Git Bash et sous dash 0.5.12 (Debian 13). `generate-secrets.sh` n'a pas besoin de
  passage à blanc : il refuse d'écraser et n'écrit rien si un tirage échoue.
- **La source du DSN** : le script ne la supprime pas. La procédure la supprime sur le
  serveur d'abord, puis le fichier de Kevin sur le poste, **une fois le démarrage de l'API
  prouvé** (transport Sentry armé, G1).

### 7.5 L'hygiène des secrets sur le serveur (C16)

Les secrets voyagent par l'ENVIRONNEMENT des conteneurs : **tout ce qui l'affiche est
proscrit sur le serveur** —
- `docker compose config` sans `-q`, qui résout les `env_file` et imprime leurs valeurs ;
- `docker inspect` NON filtré (`Config.Env`) ;
- `docker exec … env`, `printenv` ;
- un `run` sans `--rm`, qui laisserait derrière lui un conteneur porteur d'`admin.env`.

**Relire une variable** : seulement un NOM écrit dans un bloc `environment` du compose
versionné — `PORT`, `USER_CORE_LISTEN_HOST`, `USER_CORE_TRUSTED_PROXIES`,
`USER_CORE_SIMULATED_SEAMS`, `NO_COLOR` — et par cette forme seulement :
```bash
docker compose -p user-core-preprod -f deploy/preprod/compose.yaml exec -T <service> node -e "console.log(process.env.NOM)"
```
Le critère est STRUCTUREL, comme celui du mur C8 : ce qui est écrit dans le fichier versionné
est public, ce qui vient d'un `env_file` est secret. Cette forme lit ce que le processus EN
COURS a reçu : un conteneur qu'on n'a pas recréé après une retouche du compose se voit.
**Le durcissement** se relit par `docker inspect -f` sur des champs NOMMÉS
(`ReadonlyRootfs`, `CapDrop`, `SecurityOpt`, `Memory`, `MemorySwap`, `LogConfig`), jamais en
entier.

### 7.6 La procédure — répétée sur le poste le 04/10/2026, à jouer à l'étape 3

**L'étape 3 attend le Go de l'Auditeur**, donné après qu'il a vérifié lui-même les relevés de
l'étape 0. C'est l'engagement pris devant Kevin le 04/10/2026 : chaque étape donne un rapport,
vérifié avant la suivante. C'est la première fois que quelque chose s'installe sur la machine
de production de Scolaria.

🔴 **Ce serveur porte la production de Scolaria** (C1).
- Chaque commande compose porte `-p user-core-preprod -f deploy/preprod/compose.yaml`.
- Jamais de commande docker globale (`prune`, suppression de tous les conteneurs).
- Jamais `/etc/docker/daemon.json`, jamais un redémarrage du démon.
- Aucune commande `ufw`.
- Une commande par saut SSH ; les codes de sortie se lisent côté serveur.

```bash
C="docker compose -p user-core-preprod -f deploy/preprod/compose.yaml"
# 1. le code, au SHA dont la CI est verte, sans aucun identifiant GitHub sur le serveur
#    (mécanisme à écrire tel que joué à l'étape 3) ;
#    /opt/user-core/preprod/{code,secrets} — secrets/ en 700, root
# 2. les secrets
sh deploy/preprod/generate-secrets.sh /opt/user-core/preprod/secrets
# 3. l'image : construite ici, ou chargée depuis le poste (C4, §7.3)
$C build api
# 4. Postgres, dont le démarrage crée le réseau du projet ; puis la passerelle, MESURÉE
#    (§7.7) — si elle diffère de la déclaration, arrêt AVANT que l'API ne démarre
$C up -d --wait postgres
# 5. les migrations, puis le mot de passe du rôle bridé
$C run --rm migrate
$C exec -T postgres sh -c 'psql -X -q -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < deploy/preprod/app-role-password.psql
# 6. le DSN : à blanc d'abord (C19), puis le vrai (§7.4)
sh deploy/preprod/add-sentry-dsn.sh <fichier du DSN> /opt/user-core/preprod/secrets/service.env
# 7. l'API et le worker
$C up -d api worker
```

**Les contrôles** :
- `curl -s http://127.0.0.1:3100/health` → 200 ;
- `ss -ltnp` → `127.0.0.1:3100` seulement ;
- `docker ps` : Postgres non publié, et **les conteneurs de Scolaria identiques à l'étape 0** ;
- les journaux portent l'aveu des deux coutures simulées (`[SIMULATION DÉCLARÉE]`) ;
- le cron `docker image prune -f --filter until=24h` du serveur (§7.2) épargne les images
  étiquetées ; qu'il épargne aussi l'image d'un conteneur en marche : à vérifier à l'étape 3.

| Fait du déploiement | Valeur |
|---|---|
| SHA déployé (C11) | à relever à l'étape 3 |
| identifiant de l'image | à relever à l'étape 3 |
| pic de construction contre mémoire disponible (C4) | à relever aux étapes 0 et 3 |
| limites de mémoire définitives : leur somme contre *available*, marge de Scolaria comprise | à relever après l'étape 0 |

### 7.7 La passerelle — mesurée, jamais supposée

Le réseau du projet a un sous-réseau et une passerelle FIGÉS (`172.30.0.0/24`, `172.30.0.1`,
à confirmer sans chevauchement à l'étape 0), et `USER_CORE_TRUSTED_PROXIES: "172.30.0.1"`
vit à côté, dans le même fichier. Si l'étape 0 impose un autre sous-réseau, **les deux
changent ensemble, dans le même commit**.

La valeur se MESURE par un conteneur d'écho jetable, publié sur `127.0.0.1:3199` et retiré
aussitôt. Il s'attache au réseau **du projet**, `user-core-preprod_user-core` — jamais au
pont par défaut, qui mesurerait une autre passerelle :
```bash
docker run -d --rm --name uc-echo --network user-core-preprod_user-core -p 127.0.0.1:3199:8080 \
  --read-only --cap-drop ALL --entrypoint node user-core-preprod:local \
  -e "require('http').createServer((q,s)=>s.end(q.socket.remoteAddress+String.fromCharCode(10))).listen(8080)"
curl -s http://127.0.0.1:3199/
docker rm -f uc-echo
```
**La passerelle du serveur : à relever à l'étape 3.** Si elle diffère de la déclaration :
arrêt et rapport. ⚠️ La mesure du poste (`::ffff:172.30.0.1`, Docker Desktop, 04/10/2026) ne
vaut QUE pour le poste. La valeur du serveur se PROUVE ensuite par la vérification
bloquante n°1 (§6.4).

### 7.8 nginx et HTTPS — les contraintes connues (étapes 4 et 5)

Le plan de l'étape 4 se présente à l'Auditeur avant son Go, et le message de Kevin à
l'équipe Scolaria part avant tout geste sur nginx.
- **Deux temps**, parce que `nginx -t` refuserait un `ssl_certificate` absent :
  1. le site du port 80 seul, avec le chemin du défi ACME selon la méthode de Scolaria ;
  2. `nginx -t`, puis `reload` ;
  3. `certbot certonly` ;
  4. le site complet ;
  5. `nginx -t`, puis `reload`.

  Jamais `restart`. Après CHAQUE `reload` : relire `sites-enabled` (seul notre fichier
  s'ajoute) et vérifier que Scolaria répond.
- **Notre bloc 443 hérite des réglages TLS de l'hôte**, donc de ceux de Scolaria. Les
  versions acceptées se mesurent de l'extérieur à l'étape 5, et une connexion en TLS 1.1 doit
  être refusée. **Versions acceptées : à relever à l'étape 5.**
- **L'événement Sentry de test** : sa méthode est à définir, à jouer et à écrire à
  l'étape 5.

### 7.9 Le retour arrière, sans toucher à Scolaria (h)

1. retirer le lien de notre site dans `sites-enabled`, `nginx -t`, puis `reload` — jamais
   `restart` ;
2. `docker compose -p user-core-preprod -f deploy/preprod/compose.yaml down` : **le volume
   est gardé**, le supprimer est une décision à part ;
3. optionnel : `certbot delete --cert-name id-preprod.swoi.app` ;
4. le DNS : côté Kevin ;
5. vérifier ensuite que les conteneurs de Scolaria sont identiques à l'étape 0, et que
   Scolaria répond ;
6. **la révocation de l'accès de User-Core** — une décision à part, comme le volume, et en
   DERNIER, parce qu'après elle User-Core n'a plus aucun accès au serveur. Retirer de
   `/root/.ssh/authorized_keys` la seule ligne qui se termine par `user-core-preprod`, en
   vérifiant que toutes les autres lignes restent identiques. Puis, sur le poste, retirer
   l'alias `user-core-preprod` de `~/.ssh/config` et les deux fichiers de la clé.

### 7.10 Ce que ce runbook ne prévoyait pas (i)

Ce runbook n'avait jamais été joué. La répétition sur le poste, le 04/10/2026, a révélé :
- **les migrations ne tournent pas telles quelles dans une image de production** :
  `npm run migrate` passe par `ts-node`, une dépendance de développement. D'où
  `node dist/scripts/migrate.js`, avec `db/` copié sous `dist/db` ;
- **`H1` est contractuel** (`006`) : un autre identifiant de clé d'empreinte refuse le
  démarrage ;
- **l'`ALTER ROLE` n'était écrit nulle part ici** (seulement à [SECRETS.md](SECRETS.md)
  n°7) — et un `ALTER ROLE` en échec aurait recopié le mot de passe dans le journal du
  serveur ;
- **le worker n'avait aucune recette d'exécution**, et **aucune recette d'image**
  n'existait ;
- **`npm ci` lance le `prepare` du dépôt**, qui appelle `git`, absent d'une image slim ;
- **les journaux et la mémoire de Docker ne sont pas bornés par défaut** : ils le sont ici,
  service par service, sans swap ;
- **`docker compose config` sans `-q` imprime les valeurs des `env_file`** (C16) ;
- **`git archive` écrit l'arbre en CRLF sous `core.autocrlf=true`** (217 fichiers sur 217) ;
- **la réponse portait `X-Powered-By: Express`** : notre site nginx l'arrête ;
- **les journaux de Nest étaient colorés** : `NO_COLOR` les en débarrasse ;
- **la fusion `<<` de compose est superficielle** : un bloc `environment` posé dans une
  ancre est perdu dès qu'un service a le sien ;
- **une inégalité sur un compte qui peut être vide accepte quand l'outil plante**
  (`[ "$n" -ne 1 ]`). Trouvé dans un brouillon de `add-sentry-dsn.sh`, corrigé en égalités
  exigées avant toute exécution ;
- **A3bis crie aussi sous `NONE`** dès qu'un `X-Forwarded-For` arrive d'une source privée :
  c'est le comportement juste, il faut le connaître ;
- **l'événement Sentry de test n'était décrit nulle part** (§7.8) ;
- C8, C9 et C10 : ci-dessus, et au §2.

*À compléter par ce que les étapes 3 à 5 révéleront.*

### 7.11 La ligne — le jour de la première famille réelle (j)

Ce jour-là, ce n'est plus une pré-production, et tout ce qui suit devient obligatoire d'un
coup :
- **`R`**, la rétention effective des sauvegardes, posée par Kevin ([SAUVEGARDES.md](SAUVEGARDES.md)
  §2 et §3bis) ;
- **la séparation dev / pré-production / production** (CLAUDE.md §6) ;
- **le fournisseur de SMS** : une couture retirée de `USER_CORE_SIMULATED_SEAMS` (§2bis) ;
- **les plafonds par adresse deviennent un arbitrage de Kevin** : `.env.example` le dit en
  toutes lettres pour `AUTH_REGISTER_THROTTLE_MAX_ATTEMPTS` (CGNAT, inconnue de terrain,
  CLAUDE.md §3.11) ;
- 🔴 **un instantané Hostinger du serveur entier mettrait la base ET le trousseau
  d'empreinte au même endroit** ([SAUVEGARDES.md](SAUVEGARDES.md) §3) : c'est **bloquant
  pour une production sur cette machine**.

### 7.12 Ce que le lot ne fait PAS (leçon ⑫)

- **AUCUNE CI ne construit l'image** : un lot qui ajoute une dépendance de production, ou
  une lecture de fichier à l'exécution, ne rougira qu'au déploiement. *Réouverture* : avant
  la production, ou au premier lot qui touche l'un des deux.
- **Aucun fournisseur réel** : les deux coutures sont simulées, et déclarées (§2bis).
- **Aucune sauvegarde** (C7), et aucune donnée réelle qui l'exigerait (C6).
- **L'IPv6 n'est pas essayée depuis l'extérieur**, faute de réseau d'essai (§6.4).
- **Le passage sous dash est prouvé sur dash 0.5.12** (Debian 13) ; celui du serveur reste
  dû (C19).
- **Pas encore mesurés** : la passerelle, la mémoire disponible, l'identifiant de l'image et
  le SHA déployé (§7.6, §7.7).
