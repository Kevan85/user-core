-- =============================================================================
-- 031 — LA PORTE D'ÉMANCIPATION EST FERMÉE AU RÔLE APPLICATIF (LOT U-sec,
-- étape 2). ON FERME LA PORTE, ON GARDE LES MURS.
--
-- POURQUOI FERMER PLUTÔT QUE CORRIGER. Le défaut est un plancher d'identité :
-- open_emancipation reçoit DE L'APPELANT la personne visée ET la coordonnée
-- (020:104-109), si bien que la preuve qui suit établit « je détiens la ligne
-- que je viens de déclarer » — jamais « je suis cette personne ». La cible est
-- l'identifiant public, conçu pour être DICTÉ AU GUICHET (014:78) : une
-- désignation, pas une authentification. Le corriger demande un défi dont la
-- coordonnée est LUE au registre, donc une conception qui suppose une
-- population à servir.
--
-- CETTE POPULATION N'EXISTE PAS, ET C'EST MESURÉ, pas supposé :
--   · aucun chemin applicatif ne rend un compte inactif — « UPDATE accounts »
--     ne se trouve qu'à UN endroit dans tout le dépôt (028_erase_person.sql:286)
--     — donc la ré-acquisition d'un compte mort n'a aucun bénéficiaire possible ;
--   · une personne effacée est de toute façon murée par P0116 (026) ;
--   · rien n'est déployé, et LyingProver reste le seul implémenteur de la preuve
--     de ligne (src/main.ts) — l'exposition réelle est NULLE.
-- Construire le plancher aujourd'hui serait payer une conception difficile
-- (l'unicité mondiale d'une ligne, 006:107-108, interdit d'activer une
-- revendication de plus dans un foyer qui partage un téléphone) pour un usage
-- qui n'a encore aucun utilisateur.
--
-- CE QUI RESTE, INTACT — c'est le point de tout ce fichier : les MURS. 017 et
-- son P0113 (la coupure est définitive), l'invariant d'émancipation différé,
-- 019 (le droit d'accès appartient à la PERSONNE, jamais au compte), et les
-- deux fonctions elles-mêmes : leur corps, leurs verdicts, leurs gardes d'âge
-- et de fraîcheur. Le jour où un usage réel apparaît, le plancher d'identité se
-- construit à ce moment-là — correctement, et avec la contrainte du foyer
-- partagé connue d'avance (CDC §10 n°15).
--
-- CE QUE CE FICHIER NE FAIT PAS, ET POURQUOI :
--   · il ne DROP rien. Une porte se ferme par un statut, pas par une
--     suppression (§3.10 dans son esprit) : supprimer effacerait l'intention et
--     le travail de 020, que l'étape suivante reprendra.
--   · il ne retire PAS le droit à l'OWNER. Les tests d'invariants de 017/020
--     continuent d'exercer ces fonctions sous le propriétaire — c'est la seule
--     façon de garantir que les murs SURVIVENT à la fermeture au lieu de
--     devenir du code que plus personne n'éprouve.
--
-- Pas de BEGIN/COMMIT interne : le runner enveloppe cette migration.
-- =============================================================================

REVOKE EXECUTE ON FUNCTION open_emancipation(text, text, text, text, text)
  FROM user_core_app;

REVOKE EXECUTE ON FUNCTION complete_emancipation(uuid, text, text)
  FROM user_core_app;
