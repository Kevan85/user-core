# Sauvegardes — rétention R, restauration jouée, et ce qu'un dump contient vraiment

> Runbook d'exploitation (LOT prod, étape 6). Propriété : Exécuteur, sous `docs/ops/`.

## 1. La procédure

- `npx ts-node scripts/backup-db.ts` — variables **toutes obligatoires, aucun défaut** :
  `DATABASE_ADMIN_URL` (owner), `BACKUP_DIR` (cible), `BACKUP_RETENTION_DAYS` (**R**).
- Format `pg_dump --format=custom` ; nom `user-core-<horodatage UTC>.dump`. La rétention
  purge par **horodatage de nom** (jamais le mtime — une copie, un rsync le réécrivent) ;
  un fichier au nom inconnu n'est **jamais** supprimé (fail-closed : on ne purge que ce
  qu'on a soi-même nommé). Un dump vide ou avorté est retiré, jamais conservé.
- La planification (cron, timer systemd) appartient au déploiement ; la cible vit **hors
  de la machine de la base** (une sauvegarde qui meurt avec son serveur n'en est pas une).

## 2. R — la rétention est une décision de Kevin, pas un réglage

**R (`BACKUP_RETENTION_DAYS`) est une inconnue de terrain (§3.11)** : le script refuse de
courir sans elle, et aucune valeur « raisonnable » n'est fournie nulle part — les valeurs
qui apparaissent dans les tests sont des **planchers de test**, marquées comme telles.

**Pourquoi R est non négociable — le lien avec le LOT effacement** : la crypto-destruction
(« effacer une personne = détruire SON sel ») n'est effective **qu'à J+R** — toute
sauvegarde antérieure contient encore l'ancien sel, donc la donnée reste techniquement
recouvrable tant qu'un dump vivant la porte. **« Effacé » veut dire « effacé à J+R ».**
Sans rétention bornée, la crypto-destruction est un mensonge. C'est ce que le LOT
effacement devra dire à Kevin pour qu'il fixe R en connaissance de cause (droit à
l'effacement d'un côté, capacité de restauration de l'autre).

## 3. ⚠️ Ce qu'un dump contient — exigence de CONCEPTION, pas précaution générale

Un dump contient **les empreintes HMAC déterministes** des numéros. La PII chiffrée est
illisible sans le trousseau — mais **l'espace des numéros de téléphone est énumérable** :
quiconque détient *le dump ET le trousseau HMAC* peut tester chaque numéro possible
contre chaque empreinte et reconstruire toute la base par force brute. Conséquences,
gravées ici :

1. **Une sauvegarde ne se stocke JAMAIS au même endroit que le trousseau HMAC** — ni le
   même serveur, ni le même gestionnaire de secrets, ni le même compte fournisseur. La
   compromission d'un seul des deux ne suffit à rien.
2. **Une sauvegarde est chiffrée au repos** (chiffrement du volume ou du dépôt de
   sauvegarde — la clé de CE chiffrement suit la règle 1 : jamais avec les dumps).
3. La rotation de la clé HMAC (ROTATION.md §5) ne « nettoie » pas les dumps antérieurs :
   ils portent les empreintes de l'époque, sous l'ancienne clé — une clé HMAC retirée du
   trousseau ne doit donc pas être considérée comme morte avant J+R.

## 3bis. ⚠️ H1 — R ne vaut que s'il s'applique à TOUTES les copies

**La valeur effective de R est le MAXIMUM de toutes les couches de rétention, pas celle
du script.** Le script purge SON répertoire ; la promesse « effacé à J+R » porte, elle,
sur **toute copie existante** d'un dump. Tout ce que le script ne voit pas la casse :

- les **snapshots de l'hébergeur** sur le volume de sauvegarde (souvent 30-90 jours,
  souvent activés par défaut) ;
- le **versioning d'objets** et le **soft-delete / corbeille** d'un stockage objet —
  plusieurs fournisseurs les activent par défaut : un objet « supprimé » y reste
  récupérable ;
- la **sauvegarde du serveur de sauvegardes** lui-même ;
- toute **copie manuelle** vers un poste « pour déboguer ».

Si une seule de ces couches conserve plus longtemps que R, **R est un chiffre décoratif
et la crypto-destruction redevient le mensonge que le CDC nomme.** Exigences de
déploiement (le script ne peut pas les vérifier — même famille que le TLS,
SECRETS.md §4) :

1. **toute copie d'un dump hérite de R** — la rétention de chaque support (snapshots,
   versioning, corbeille, sauvegarde de la sauvegarde) est **plafonnée à R**, ou l'écart
   est **documenté comme la valeur réelle de R** communiquée à Kevin ;
2. **pas de copie manuelle hors du dépôt de sauvegarde** — ligne de contrôle du runbook
   de déploiement ;
3. au LOT effacement, la phrase écrite à Kevin porte la valeur **effective** (le maximum
   des couches), jamais le paramètre du script sur parole.

**⚠️ Changement d'hébergeur (statut 30/07/2026 : en cours, `R` NON RÉPONDABLE — CDC §9
n°5).** La bascule AJOUTE deux couches que personne n'inventorie spontanément : la **copie
de migration** elle-même (le dump transporté, gardé « le temps de vérifier ») et les
**snapshots de l'ancien hébergeur**, qui survivent régulièrement à la résiliation et
échappent par construction à tout script de purge. **La destruction prouvée des données
chez l'ancien hébergeur est une ligne de contrôle de la bascule**, pas une intention.

**⚠️ Ce qu'un dump contient TOUJOURS, même après un effacement** (LOT effacement, résidu
F1 — détail : [EFFACEMENT.md §4](EFFACEMENT.md)) : l'empreinte de la ligne d'une personne
effacée survit dans trois registres append-only (`possession_proof_refusals`,
`program_invitations`, `program_invitation_refusals`). **Le test de présence « dump +
trousseau HMAC » est donc BORNÉ par l'effacement, pas FERMÉ** — la règle « jamais un dump
au même endroit que le trousseau » (§3) ne faiblit pas après un effacement.

## 4. La restauration se JOUE, elle ne se documente pas

Le cycle réel — dump → base neuve → migrations vérifiées (versions **et** checksums,
liste entière) → données relues (ligne semée + poids des registres) — est rejoué **à
chaque CI** par `tests/ops/backup-restore.spec.ts`. Une procédure de restauration jamais
exécutée est une hypothèse.

Restauration manuelle (incident réel) :
1. base neuve : `CREATE DATABASE user_core_restore;`
2. `pg_restore --dbname <url du propriétaire vers user_core_restore> <fichier.dump>`
3. vérifier `schema_migrations` (liste entière contre le dépôt) puis les poids des
   registres ; basculer les URL du service seulement après.
4. ⚠️ Toute restauration REMONTE LE TEMPS des registres append-only : ce qui a été écrit
   après le dump (preuves, révocations, consentements) n'existe plus. C'est un acte
   d'incident majeur, jamais un outil de « correction » — il se décide avec Kevin.
