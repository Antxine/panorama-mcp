# Débogage de tickets via Panorama

Ce fork de [Palo-MCP](https://github.com/apius-tech/Palo-MCP) aide à diagnostiquer les tickets utilisateurs (« je suis bloqué ») sur des firewalls gérés par Panorama.

## Ce que le fork ajoute

| Ajout | Détail |
|---|---|
| Lecture seule par défaut | `PANOS_READ_ONLY=true` (par défaut). Les outils d'écriture (set, delete, commit, push, `run_op_command`) ne sont pas chargés. |
| Relais Panorama → firewall | Les commandes op passent par `target=<serial>`. Une seule clé Panorama suffit pour User-ID, les sessions, GlobalProtect et `test`. Le paramètre `device` accepte un hostname ou un numéro de série. |
| Diagnostic de ticket | Prompt `diagnose_ticket` plus quatre outils `diagnose_*` qui concluent sur la cause au lieu de renvoyer des données brutes. |
| Custom URL categories | Liste, contenu, recherche URL → catégorie (wildcards PAN-OS), usage dans les règles et les profils. |
| Playbook | Pièges connus : logs absents, dépendances tierces, App-ID, User-ID, décryption, EDL, etc. Disponible via la ressource `panorama://playbook` et l'outil `get_troubleshooting_playbook`. |
| Corrections de Palo-MCP | Le parseur XML garde les valeurs en texte (les numéros de série gardent leurs zéros initiaux). Les entrées sont validées avant d'être insérées dans les XPath et les requêtes. |

## Installation

Prérequis : Node.js 22.19 ou plus, et un compte admin Panorama dédié au MCP avec un rôle en lecture seule. Dans ce rôle, l'API XML doit autoriser **Configuration**, **Operational Requests** et **Log**. Sans Operational Requests, les outils en direct (User-ID, `test`, sessions) répondent « Type [op] not authorized » ; les outils de config et de logs fonctionnent quand même.

```bash
npm install && npm run build
npx panos-keygen --host panorama.example.local --user svc-mcp-ro --name panorama
```

Déclaration dans Claude Code (stdio, sur le poste de chaque ingénieur) :

```bash
claude mcp add panorama \
  --env PANOS_MODULES=panorama-debug \
  -- node /chemin/vers/PaloAlto_MCP/dist/index.js
```

La clé API est stockée dans le trousseau de l'OS par `panos-keygen`, jamais en clair.

### GitHub Copilot CLI

Dans Copilot CLI, lance `/mcp add` (type local/stdio), ou édite `~/.copilot/mcp-config.json` :

```json
{
  "mcpServers": {
    "panorama": {
      "type": "local",
      "command": "node",
      "args": ["C:\\chemin\\vers\\PaloAlto_MCP\\dist\\index.js"],
      "env": { "PANOS_MODULES": "panorama-debug" },
      "tools": ["*"]
    }
  }
}
```

Vérifie avec `/mcp show` que le serveur `panorama` est connecté.

Copilot CLI n'affiche pas forcément les prompts MCP et ne transmet pas forcément les instructions du serveur au modèle. La méthode est donc aussi exposée par l'outil `start_ticket_diagnosis` et par `AGENTS.md`, que Copilot CLI lit quand on le lance depuis ce dossier.

## Utilisation

Colle l'extrait du ticket dans le prompt `diagnose_ticket`, ou demande simplement : « Diagnostique ce ticket : … ».

Le modèle suit cette méthode :

1. **Extraire les faits** : utilisateur, IP, URL, action tentée, heure.
2. **`diagnose_user_blocks`** : chronologie de tous les blocages de l'utilisateur, tous types de logs confondus, classés par cause (règle, catégorie URL, file-blocking, antivirus/WildFire, vulnérabilité, décryption, DNS Security, zone protection…). Avec `reported_url`, l'outil repère les blocages sur **d'autres domaines au même moment**. Exemple : ABC.com envoie ses fichiers sur XYZ.com, c'est XYZ.com qu'il faut autoriser.
3. **Analyse ciblée** selon la cause :
   - `diagnose_url_access` : catégories custom qui couvrent **déjà** l'URL, entrées du même domaine qui ne matchent pas (erreur de motif), catégorie PAN-DB, règles et profils qui utilisent ces catégories.
   - `diagnose_threat_block` : profil réellement appliqué (profile group résolu), exception **déjà existante** ou non pour ce threat ID, règle file-blocking qui a matché, verdict WildFire.
   - `diagnose_flow` : mapping User-ID et groupes, règle réellement matchée par le firewall (`test security-policy-match`), règles qui autorisent l'application (y compris les fonctions `*-uploading`).
4. **Conclusion** : preuves, cause racine, niveau de confiance, correctif minimal qui réutilise l'existant, et informations à demander à l'utilisateur si des données manquent.

## Identités utilisateur

PAN-OS ne permet qu'une correspondance **exacte** sur l'utilisateur. Selon la source :
- GlobalProtect et Prisma Access : UPN (`prenom.nom@domaine`, souvent `nom-external@domaine` pour les externes) ;
- Citrix et AD : `DOMAINE\id` (par exemple `emea\u123456`), derrière des IP Citrix partagées.

Sur un PC Windows du domaine, l'outil `ad_lookup_user` interroge l'Active Directory avec ta session. À partir d'un e-mail, d'un `DOMAINE\id` ou d'un « Prénom Nom », il renvoie le compte, les groupes AD et les identités telles qu'elles apparaissent dans les logs. `diagnose_user_blocks` s'en sert automatiquement : avec un e-mail, il cherche les logs sous l'UPN **et** sous `DOMAINE\id`.

L'outil `ad_user_rules` croise les groupes AD de l'utilisateur, groupes imbriqués compris, avec le `source_user` des règles. Il liste les règles qui le visent déjà, et par quel groupe. Avec `contains` (application, catégorie…), il liste aussi les règles pertinentes réservées à d'autres groupes, avec le groupe qui lui manque. Souvent, la bonne correction est alors d'**ajouter l'utilisateur au groupe existant**, pas de créer une règle. Les groupes Entra ID purement cloud (Cloud Identity Engine) ne sont pas visibles dans l'AD on-prem.

Sans AD, donne à `diagnose_user_blocks` l'URL bloquée (`blocked_url`) ou le site demandé (`reported_url`) : l'outil liste les identités vues pour cette URL.

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `PANOS_READ_ONLY` | `true` | `false` réactive les outils d'écriture de Palo-MCP |
| `PANOS_MODULES` | `panorama-debug` | `all` charge aussi les outils de Palo-MCP pensés pour les firewalls isolés |
| `PANOS_AD_LOOKUP` | `auto` | Recherche AD : active sous Windows, `false` pour la désactiver, `true` pour la forcer |
| `PANOS_LOG_TIMEOUT` | `120` | Délai maximal d'une requête de logs, en secondes ; au-delà, les résultats partiels sont renvoyés |

## Limites connues

- La config lue est la **running config de Panorama**. Les règles locales des firewalls et les changements non poussés n'y apparaissent pas. `test_security_policy_match` interroge le firewall et reste la référence.
- La correspondance URL ↔ catégorie custom est une **approximation** des règles PAN-OS. Le firewall (`test_url_category`, logs) fait foi.
- PAN-OS ne loggue pas les catégories URL en action `allow`. Pour les dépendances d'un site, un export DevTools/HAR peut rester nécessaire.
- Les logs globalprotect, userid et auth sont filtrés localement (sur 2000 entrées au plus), car leurs champs de filtre diffèrent des logs traffic et threat.
- Les heures de logs sont dans le fuseau horaire de Panorama.
- Les recherches sur 30 jours dépassent souvent le délai : préfère `incident_time` (±30 min) ou `last-24-hrs`.
- Prisma Access (« GP cloud service », « RN-… ») : pas de commandes en direct, uniquement les logs et la config des device groups Prisma.
- Les réponses sont plafonnées à environ 40 Ko (listes tronquées, avec mention) pour éviter que le client ne les écrive dans des fichiers.

## À valider sur notre Panorama

Certaines sorties de commandes op varient selon la version de PAN-OS. Il faut vérifier :
`show devicegroups`, `test url`, `test security-policy-match`, `show user user-ids`, `request system external-list show`, le filtre `receive_time in last-hour` et les champs des logs GlobalProtect.

## Écriture (plus tard)

`PANOS_READ_ONLY=false` réactive les outils d'écriture de Palo-MCP. Recommandation pour la suite : ajouter des outils dédiés (par exemple ajouter une URL à une catégorie existante) qui montrent le diff et demandent une confirmation explicite, et ne jamais faire de commit ni de push automatique.
