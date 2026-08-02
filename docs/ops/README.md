# docs/ops — l'index (à lire à 3 h du matin)

> Runbooks d'exploitation. Propriété : Exécuteur. Le socle doctrinal (CLAUDE.md, CDC,
> CONTRAT) appartient à l'Auditeur — rien d'ici ne le remplace.

**Un incident est en cours ?** → [INCIDENT.md](INCIDENT.md) — fuite de PII (couper le
canal d'abord), clé compromise (tableau par trousseau), programme à révoquer,
restauration (acte majeur, avec Kevin).

| Besoin | Runbook |
|---|---|
| Déployer / redéployer, liste de contrôle, ordre migrations → boot | [DEPLOIEMENT.md](DEPLOIEMENT.md) |
| Un incident : fuite, clé compromise, programme, restauration | [INCIDENT.md](INCIDENT.md) |
| Tourner une clé (procédure par trousseau, fenêtre HMAC) | [ROTATION.md](ROTATION.md) |
| Les secrets : inventaire des 10, injection sans SDK, murs de boot | [SECRETS.md](SECRETS.md) |
| Sauvegardes, rétention R, restauration jouée, H1 (R = max des couches) | [SAUVEGARDES.md](SAUVEGARDES.md) |
| Effacement : le circuit, les compteurs du worker, les résidus assumés, J+R | [EFFACEMENT.md](EFFACEMENT.md) |

Trois faits que tout lecteur d'ici doit avoir en tête :

1. **Les murs de production sont le défaut** (F1) : ne jamais « réparer » un refus de
   boot en posant `NODE_ENV=development` — c'est tout désarmer.
2. **Toute rotation est un redéploiement** (C5) — et la rotation d'empreinte téléphone
   arrête le service (fenêtre planifiée, mur 025).
3. **« Effacé » veut dire « effacé à J+R »**, et R vaut le MAXIMUM de toutes les couches
   de rétention (H1) — un dump + le trousseau HMAC = toute la base.
