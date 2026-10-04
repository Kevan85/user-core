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
| IPv6 globale | `2a02:4780:f:7ed4::1` : seul `sshd` y écoute | Auditeur Scolaria (`ss -ltnp`) |
| Scolaria | en **conteneurs** (compose HORS dépôt, `/opt/scolaria/docker-compose.yml`), ports publiés sur **127.0.0.1 seulement** : **3000** (API), **5432** (Postgres), **6379** (Redis) | `DEPLOYMENT_API_VPS.md` §1 |
| Aiguilleur | **nginx sur l'hôte**, un site par nom (`/etc/nginx/sites-enabled/…`), **IPv4 seulement**, `proxy_set_header X-Forwarded-For $remote_addr;` | idem, et réponse Scolaria |
| Pare-feu | **UFW** refuse par défaut, n'ouvre que **22, 80, 443** (IPv4 et IPv6) ; depuis l'extérieur, seuls 22/80/443 répondent | idem |

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
