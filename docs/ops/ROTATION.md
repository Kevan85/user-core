# Rotation des clés — une procédure par trousseau

> Runbook d'exploitation (LOT prod, étape 4). Propriété : Exécuteur, sous `docs/ops/`.
> Rappel structurel ([SECRETS.md §1](SECRETS.md)) : **toute rotation est un
> redéploiement** — les secrets arrivent par l'environnement, il n'y a ni rotation à
> chaud ni bail court. C'est un geste planifié, jamais un réflexe.

Le patron commun : **ajouter la clé neuve au trousseau, basculer l'active, redéployer,
laisser passer la fenêtre de recouvrement, retirer l'ancienne, redéployer.** Le retrait
est le vrai point de non-retour — et il échoue **explicitement** (jamais un déchiffrement
silencieusement faux) : les tests de `keyring-rotation.spec.ts` le prouvent à chaque CI.

## 1. Chiffrement (`USER_CORE_ENC_KEYS`) — le geste ordinaire

1. Générer la clé neuve, l'ajouter au trousseau, la nommer active. Redéployer.
2. Les anciennes valeurs restent lisibles par leur `enc_key_id` ; les écritures neuves
   partent sous la clé neuve. **Aucune migration, aucune fenêtre.**
3. Retrait de l'ancienne clé : seulement quand plus AUCUNE ligne ne la porte
   (`SELECT count(*) FROM phone_claims WHERE enc_key_id = '<ancienne>'` — et l'équivalent
   sur `persons.enc_key_id`). Un re-chiffrement de masse est un lot dédié, pas un geste
   d'exploitation.

## 2. Codes de possession (`USER_CORE_PROOF_CODE_KEYS`) — fenêtre de 300 s

1. Ajouter, basculer, redéployer. Les codes en vol (TTL 300 s) se vérifient sous la clé
   **nommée par leur ligne** — ils traversent la bascule.
2. Retirer l'ancienne clé au déploiement suivant (≥ TTL après la bascule). Un code émis
   sous une clé retirée est refusé proprement (`null`), jamais faussement accepté.

## 3. Signature des jetons (`AUTH_SIGNING_KEYS`) — recouvrement de 900 s

1. Ajouter le kid neuf, basculer `AUTH_ACTIVE_KEY_ID`, redéployer. Le JWKS publie
   **tous** les kids du trousseau : les programmes vérifient l'ancien comme le neuf.
2. Retirer l'ancien kid après ≥ TTL du jeton (900 s). Les jetons signés sous un kid
   retiré meurent proprement (`null` → 401, le client se ré-authentifie).

## 4. Références d'idempotence (`USER_CORE_REF_HMAC_KEYS`) — l'idempotence traverse (024)

1. Ajouter, basculer, redéployer. **La recherche d'idempotence couvre toutes les clés du
   trousseau** (migration 024) : le re-clic d'une requête ancienne reconnaît sa référence
   — jamais une deuxième fiche d'enfant. L'écriture et le verrou restent sous la clé
   active.
2. Retrait de l'ancienne clé : quand plus aucun re-clic legitime ne peut la viser — la
   fenêtre utile est celle des retries des programmes (heures, pas mois). Après retrait,
   un re-clic antique crée une fiche neuve : c'est le comportement d'avant 024, assumé
   hors fenêtre.

## 5. Empreinte téléphone (`USER_CORE_HMAC_KEYS`) — LE CAS DUR, service arrêté

**⚠️ Fenêtre d'indisponibilité STRUCTURELLE, à planifier** : pendant la rotation, la clé
active du service diverge de la référence en base — le boot refuse
(`assertFingerprintKeyAligned`). Rien ne tourne entre l'arrêt et le redéploiement final.

L'ordre est gardé par **la base**, pas par la discipline (mur 025, P0115) : la référence
ne bascule pas tant qu'une revendication ACTIVE vit sous une autre clé. Un script
interrompu laisse une transaction avortée — jamais un état à deux clés.

Procédure :
1. **Arrêter le service** (api ET worker).
2. Déployer l'environnement de rotation : trousseau = ancienne + neuve, active = neuve.
3. `npx ts-node scripts/rotate-phone-hmac.ts` (owner, `DATABASE_ADMIN_URL`) — une seule
   transaction : re-dérivation d'intégrité par le point unique (une divergence
   empreinte/chiffré arrête TOUT), re-hachage des ACTIVE, triggers réarmés, bascule de la
   référence en dernier. Le script est idempotent (le rejouer : « rien à faire »).
4. **Redémarrer** le service (l'alignement clé/référence est re-vérifié au boot).
5. Retirer l'ancienne clé du trousseau au déploiement suivant.

Conséquences bornées, assumées (en-tête de 025) :
- les revendications **PENDING** sous l'ancienne clé ne s'activent plus (P0109) — la
  personne re-déclare sa ligne ;
- les **invitations en attente** ne portent aucun chiffré (012, délibéré) : rien à
  re-hacher — leur acceptation rend `LINE_NOT_PROVEN`, puis elles expirent ; ré-inviter
  est sans coût (021). Pour minimiser : planifier la rotation hors campagne
  d'inscriptions.
- l'historique (REVOKED) garde ses empreintes d'époque : il n'entre dans aucune unicité.

## 6. Clés des programmes (Ed25519, en base)

La rotation appartient **au programme** : il génère sa paire chez lui et enregistre la
clé publique neuve (`scripts/program-client-admin.ts`) ; l'ancienne se révoque par ligne
(append-only). Le cœur ne détient jamais une clé privée de client — il n'a donc rien à
tourner.

## 7. Mots de passe Postgres

`ALTER ROLE ... PASSWORD` (acte d'exploitation, jamais une migration) + mise à jour du
gestionnaire de secrets + redéploiement. Le service refuse de tourner sous un autre rôle
que le rôle bridé — une inversion d'URL ne démarre pas.
