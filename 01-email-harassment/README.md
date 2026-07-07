# Case 01: Email Harassment Investigation

## Executive Summary

*À compléter une fois l'investigation terminée : qui, quoi, conclusion principale en 2-3 phrases.*

## Case Background

Enquête sur un email de harcèlement envoyé par un étudiant à un membre du corps enseignant. Le cas est basé sur un scénario hébergé par digitalcorpora.org ([description du scénario](https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/) et [capture réseau](https://downloads.digitalcorpora.org/corpora/scenarios/2008-nitroba/nitroba.pcap) disponibles sur leur site).

## Objective

Utiliser Wireshark et t-shark pour analyser le trafic réseau capturé et identifier les preuves permettant de reconstituer l'origine et le contenu de l'email de harcèlement.

## Known Facts (Given Information)

- L'enseignante (Lily Tuckrige) a reçu un premier email de harcèlement sur son 
  adresse personnelle Yahoo, provenant de l'adresse `nobody@nitroba.org`.
- Après signalement au support IT, elle a fourni les en-têtes complets du mail. 
  L'en-tête `Received` indique une connexion SMTP depuis l'IP `140.247.62.34`.
- Une résolution DNS inverse de cette IP pointe vers `G24.student.nitroba.org`, 
  une chambre du dortoir universitaire.
- La chambre G24 est partagée par trois étudiantes : Alice, Barbara et Candice.
- Le réseau des dortoirs fournit un port Ethernet filaire dans chaque chambre, 
  mais pas de Wi-Fi officiel.
- Le petit ami de l'une des occupantes (Kenny, petit ami de Barbara) a installé 
  un point d'accès Wi-Fi personnel dans la chambre, **sans mot de passe**.
- Conséquence importante pour l'investigation : n'importe quel appareil à portée 
  du signal Wi-Fi peut se connecter sans authentification et utiliser l'IP de la 
  chambre pour sortir sur le réseau. L'IP source ne suffit donc pas à elle seule 
  à identifier l'auteur : il faudra chercher d'autres éléments dans le trafic 
  capturé (user-agent, cookies de session, contenu des requêtes) pour relier une 
  connexion précise à une personne.
- Un **second email** est reçu peu après, cette fois envoyé via 
  `noreply@willselfdestruct.com`, un service tiers d'emails anonymes et 
  temporaires (message affiché une seule fois puis détruit). Le contenu confirme 
  qu'il s'agit du même harceleur : *"vous ne pouvez pas vous cacher de nous, 
  arrêtez d'enseigner"* (paraphrase).
- Ce service nécessite que l'auteur ait lui-même visité `willselfdestruct.com` 
  pour composer et envoyer le message. C'est une piste distincte de l'envoi SMTP 
  initial : si une visite de ce site est retrouvée dans la capture réseau, 
  provenant de la même IP ou dans une fenêtre de temps cohérente, cela renforce 
  la corrélation entre les deux emails et la ou les connexions suspectes.
- La liste des étudiants du cours de chimie CHEM109 de Lily Tuckrige est 
  disponible comme liste de suspects potentiels (nécessaire uniquement si 
  l'auteur s'avère être un étudiant du cours, à confirmer par l'analyse).

## Investigation Plan

1. Cartographier le réseau de la chambre concernée à partir de la capture réseau.
2. Retrouver le flux TCP correspondant à l'envoi du premier mail de harcèlement.
3. Rechercher dans la capture une connexion vers `willselfdestruct.com` 
   correspondant à l'envoi du second mail, et vérifier si elle provient de la 
   même source que le premier envoi.
4. Identifier les autres connexions réseau associées à cette même source dans 
   la capture (navigation web, autres services).
5. Rechercher, dans ces connexions, une information permettant d'identifier 
   concrètement l'auteur (au-delà de la simple adresse IP partagée) : par 
   exemple des identifiants saisis dans un formulaire, un cookie de session, 
   ou tout élément liant une session réseau à une personne précise.
## Tools & Environment

- Wireshark
- t-shark (CLI)

## Methodology

### 1. Initial Traffic Analysis (Wireshark)

*À compléter : approche suivie, filtres utilisés, captures d'écran clés.*

### 2. Command-Line Analysis (t-shark)

*À compléter : pourquoi passer en CLI, ce que ça permet en plus.*

### 3. Email Reconstruction

*À compléter : comment isoler et reconstituer le contenu de l'email.*

## Findings

*À compléter : preuves concrètes trouvées, avec captures d'écran et extraits pertinents.*

## Conclusion

*À compléter : ce que l'investigation a permis d'établir.*

## Skills Demonstrated

- Network traffic analysis
- Protocol filtering (SMTP/POP3/IMAP)
- CLI-based forensic analysis
