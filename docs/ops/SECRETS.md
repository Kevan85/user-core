# Secrets — inventaire, injection, murs de boot

> Runbook d'exploitation (LOT prod, étape 3). Propriété : Exécuteur, sous `docs/ops/`
> (arbitrage C7). Le socle doctrinal (CLAUDE.md, CDC, CONTRAT) reste à l'Auditeur.

---

## 1. La doctrine d'injection — variables d'environnement, ZÉRO SDK

Les secrets arrivent au service **par l'environnement, posés au déploiement** (agent ou CLI
du gestionnaire de secrets — Vault, Infisical ou équivalent). **Aucun SDK de fournisseur
n'entre dans le code** : le contrat du service est « variables d'environnement + boot
fail-closed », il existe déjà et il suffit. Un SDK serait une quatrième couture (§3.9) et
un couplage du cœur à un fournisseur d'infrastructure.

**⚠️ CONTREPARTIE ASSUMÉE (arbitrage C5, écrite ici pour ne pas devenir une justification
périmée)** : sans SDK, il n'y a **ni rotation à chaud, ni bail court**. **Toute rotation de
secret est un redéploiement** — un geste planifié, avec sa fenêtre. C'est un coût accepté
en connaissance de cause ; le jour où une exigence réelle (bail court imposé par un
partenaire, rotation quotidienne) le rend intenable, c'est cette doctrine qu'on rouvre
avec l'Auditeur — pas un SDK qu'on ajoute en silence.

Conséquences pratiques :
- `.env` n'est **jamais** committé ; `.env.example` ne contient **jamais** une valeur
  fonctionnelle (règle C14 — et c'est ce qui rend possible le mur du §3 ci-dessous).
- **Jamais un secret de production sur un poste de dev** (§5) : chaque environnement
  (dev, staging, prod) génère **ses** valeurs, aucune ne circule entre eux.
- La rotation de chaque secret suit sa procédure propre (étape 4 du LOT prod) ; ce
  fichier n'en donne que le cycle de vie résumé.

## 2. L'inventaire — chaque secret, sa forme, sa naissance, son cycle de vie

| # | Secret | Variable(s) | Forme | Génération | Cycle de vie |
|---|---|---|---|---|---|
| 1 | Trousseau de **chiffrement** (AES-256-GCM) | `USER_CORE_ENC_KEYS` + `USER_CORE_ENC_ACTIVE_KEY_ID` | JSON `{kid: base64}`, **32 octets exacts** | `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"` | Rotation **ordinaire** : ajouter une clé, basculer l'active, les anciennes restent lisibles par leur `enc_key_id`. |
| 2 | Trousseau d'**empreinte téléphone** (HMAC-SHA256) | `USER_CORE_HMAC_KEYS` + `_ACTIVE_KEY_ID` | JSON `{kid: base64}`, 32 octets min. | idem | Rotation **EXCEPTIONNELLE** : déchiffrer et re-hacher toute la PII, migration signée, bascule de `hmac_key_reference`, fenêtre d'indisponibilité planifiée (étape 4e — le mur avant le script). |
| 3 | Trousseau des **codes de possession** (HMAC-SHA256) | `USER_CORE_PROOF_CODE_KEYS` + `_ACTIVE_KEY_ID` | idem | idem | Rotation **simple** : les codes vivent 300 s ; recouvrement d'une fenêtre, puis retrait de l'ancienne clé. |
| 4 | Trousseau des **références d'idempotence** (HMAC-SHA256) | `USER_CORE_REF_HMAC_KEYS` + `_ACTIVE_KEY_ID` | idem | idem | Rotation exceptionnelle : **l'idempotence ne traverse pas une rotation** (021) — conséquence et parade tranchées à l'étape 4d. |
| 5 | Clés de **signature des jetons** (Ed25519) | `AUTH_SIGNING_KEYS` + `AUTH_ACTIVE_KEY_ID` | JSON `{kid: base64(PKCS8 DER)}` | `node -e "const{generateKeyPairSync}=require('crypto');console.log(generateKeyPairSync('ed25519').privateKey.export({format:'der',type:'pkcs8'}).toString('base64'))"` | Rotation par `kid` : le JWKS sert toutes les clés, recouvrement ≥ TTL des jetons (900 s), puis retrait. |
| 6 | Clés **publiques des programmes** (Ed25519) | — (en base, `program_client_keys`) | enregistrée via `scripts/program-client-admin.ts` | **chez le programme** — le cœur ne détient jamais une clé privée de client | Révocation par ligne (append-only) ; le programme régénère chez lui. |
| 7 | Mot de passe du **rôle applicatif** | dans `DATABASE_URL` (`USER_CORE_APP_PASSWORD` : dev/CI seulement) | chaîne forte | générateur du gestionnaire de secrets | Posé par `ALTER ROLE` (acte d'exploitation), **jamais par une migration**. Rotation = `ALTER ROLE` + redéploiement. |
| 8 | Mot de passe du **propriétaire** | dans `DATABASE_ADMIN_URL` | chaîne forte | idem | Migrations et exploitation **uniquement** — le service ne lit jamais cette variable, et refuse de tourner sous ce rôle (`assertBridledRole`). |
| 9 | **DSN Sentry** | `SENTRY_DSN` | URL fournisseur | console Sentry | **Obligatoire quand les murs de production sont armés** (C2, via `productionWallsArmed()` : un DSN absent = boot refusé — on ne part pas aveugle en silence) ; optionnel en mode permissif déclaré. Livré à l'étape 5. |
| 10 | Clé de **chiffrement au repos du dépôt de sauvegardes** | — (infra de sauvegarde, jamais lue par le service) | selon le support | gestionnaire de l'infra de sauvegarde | Règle SAUVEGARDES.md §3 : jamais stockée avec les dumps, NI au même endroit que le trousseau HMAC. Sa rotation suit le support ; les dumps qu'elle protégeait restent sensibles J+R durant. |

Les quatre trousseaux (1-4) ont **quatre cycles de vie distincts** et **aucune valeur
partagée** : le boot refuse toute paire de clés identiques, entre trousseaux comme au sein
d'un même trousseau (dette ②, étape 1), et aucun trousseau ne s'assemble hors du point
unique `src/crypto/keyring.ts` (garde CI, motif H).

## 3. Les murs de boot (état livré à l'étape 3)

Le service **refuse de démarrer** si :
1. la config est incomplète — toutes les violations listées d'un bloc (`ConfigViolations`) ;
2. le rôle Postgres n'est pas le rôle bridé `user_core_app` (`assertBridledRole`) ;
3. deux clés de trousseau partagent une valeur, ou un trousseau manque (dette ②) ;
4. la clé d'empreinte active diverge de la référence gravée en base
   (`assertFingerprintKeyAligned`, fail-closed P0112) ;
5. **`NODE_ENV=production` et un secret porte une valeur publiée par `.env.example`**
   (mur C8, étape 3) : le fichier versionné est public par construction — égalité sur les
   noms à signature de secret, recherche en sous-chaîne pour les mots de passe d'URL,
   et refus fail-closed si `.env.example` est illisible en production ;
6. murs armés, **le transport Sentry ne s'est pas armé après `init()`** (G1, étape 6) :
   la vérité se demande au SDK, jamais à la présence du DSN — un DSN illisible ferait
   partir le service aveugle en croyant être surveillé.

**⚠️ Ce que l'observabilité NE couvre PAS** (écrit ici pour que « Sentry est branché » ne
soit jamais lu comme « couverture totale ») : `defaultIntegrations: false` retire aussi
les capteurs d'exception non gérée. Une exception qui échappe au filtre HTTP et au catch
du worker — un `setTimeout`, un callback détaché — ne remonte pas : le processus meurt et
c'est l'orchestrateur qui le voit. C'est un choix assumé (aucune intégration par défaut =
aucune fuite par défaut) ; l'élargir se décide avec l'Auditeur, jamais en silence.

## 4. Exigences de déploiement non vérifiables par le service

Nommées ici, portées par le runbook de déploiement (étape 7) :
- **TLS vers Postgres** (`sslmode=require` au minimum vers une base distante) — le service
  ne peut pas savoir ce que l'infra fournit ; c'est une exigence d'environnement, pas un
  mur de boot.
- **`NODE_ENV` — le mode permissif se déclare, jamais l'inverse (F1)** : les murs de
  production sont **le défaut**. Seuls `development` et `test` les relâchent ; l'absence,
  une valeur vide, une faute de frappe ou un `staging` inconnu les **arment**. Un
  déploiement réel n'a rien à poser ; un poste de dev déclare `development` (ligne
  fournie par `.env.example`). Le pire cas est un boot refusé bruyamment sur un poste
  mal configuré — jamais une production silencieusement désarmée.
