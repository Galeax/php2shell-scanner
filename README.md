# Galeax — php2shell exposure checker

Vérificateur d'exposition à la vulnérabilité **php2shell**
(**CVE-2026-109618** / **CVE-2026-109619**) — RCE pré-authentification dans le
cœur de PHP, corrigée dans PHP **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**.

Script autonome, **non-destructif**, sans dépendance. Fourni par Galeax pour que
vous puissiez tester vos propres systèmes.

---

## Prérequis

- `bash` (≥ 4), `curl` (mode web), `grep`/`sed` (présents partout).
- Aucune installation, aucun paquet tiers.

## Autorisation

À n'utiliser que sur des systèmes dont vous êtes **propriétaire ou explicitement
autorisé** à tester. Le script n'envoie aucune charge d'exploitation ; en mode
`--active` il émet des requêtes HTTP volumineuses (sonde de taille) — à réserver
aux environnements que vous maîtrisez.

---

## Usage

La **cible** (premier argument) choisit le mode — une seule commande à retenir :

```bash
./galeax-php2shell-check.sh <cible> [options]
```

| Cible | Mode | Exemple |
|---|---|---|
| une **URL** | test à distance (boîte noire) | `./galeax-php2shell-check.sh https://site/` |
| **`local`** | test sur CE serveur — verdict **CERTAIN** | `./galeax-php2shell-check.sh local` |
| une **version** `x.y.z` | verdict direct sur cette version | `./galeax-php2shell-check.sh 8.4.26` |

### Options

- **`--deep`** — (à distance) récupération de version renforcée : plusieurs
  chemins et méthodes HTTP, plus leak par page d'erreur.
- **`--active`** — (à distance) ajoute une sonde `post_max_size` (envoie des
  corps HTTP ; à réserver aux environnements maîtrisés).
- **`--crash`** — (à distance) **sonde de crash active** : envoie des corps
  multipart piégés (clés imbriquées 62 niveaux, 1 → 8 → 20 Mio) pour **déclencher
  et observer** le plantage mémoire → **preuve** de la vulnérabilité, même version
  masquée. **INTRUSIF** : peut faire tomber le service (OOM worker) ; ~29 Mio
  envoyés par hôte. À réserver aux cibles maîtrisées. Voir `--sapi`.
- **`--sapi auto|mod_php|fpm`** — filtre les signaux de crash selon le SAPI
  (`mod_php` ignore les signatures propres à FPM comme les 502/503/504, et
  inversement). Défaut `auto`.
- **`--path <p>`** (répétable) / **`--path-file <f>`** — chemins à tester pour la
  sonde de crash (défaut : chemin de l'URL, sinon `/index.php`). Les cibles
  phpMyAdmin sont automatiquement rejouées sur `/show_config_errors.php`.
- **`-H "Clé: valeur"`** (répétable) — en-tête HTTP custom (auth, cookies…),
  propagé à toutes les requêtes.
- **`--phpinfo <url>`** — lit une page `phpinfo()` exposée (version + config
  autoritatives).
- **`--php <chemin>`** — (mode `local`) binaire PHP précis à tester.
- **`--json`** — sortie machine (CI) · **`--no-color`** · **`-h`** aide.

### Exemples

```bash
./galeax-php2shell-check.sh https://site/ --deep            # à distance, identification poussée
./galeax-php2shell-check.sh https://site/ --deep --active   # + sonde post_max_size
./galeax-php2shell-check.sh https://site/ --crash           # PROUVE le bug à distance (intrusif)
./galeax-php2shell-check.sh local                           # sur le serveur (certain)
./galeax-php2shell-check.sh 8.4.26                          # verdict sur une version
```

> À distance **sans `--crash`**, le verdict repose sur la **version** : fiable
> lorsqu'elle est exposée (en-têtes, `phpinfo`, ou récupérée par `--deep`).
> **`--crash`** va plus loin et **prouve** la corruption mémoire en la déclenchant
> — au prix de l'intrusivité (service potentiellement impacté). Pour une certitude
> non-destructive, utilisez la cible **`local`**.

### Identification du stack & présence PHP

- **Présence PHP** confirmée même sans numéro de version, via les en-têtes, les
  cookies de framework (`PHPSESSID`, `laravel_session`, `ci_session`, `CAKEPHP`,
  `symfony`) et les hébergeurs PHP managés. Dans ce cas : verdict **« PHP confirmé
  — version masquée »** + renvoi vers la cible `local` (au lieu d'« indéterminé »).
- **Stack réel si PHP absent** : Python (Flask/Werkzeug, FastAPI/uvicorn,
  Django), Node/Express, ASP.NET, Ruby/Rails, Java (Spring/Tomcat), Go → verdict
  **HORS PÉRIMÈTRE**. Si la cible n'est pas en PHP, l'outil te le dit.
- **WAF / CDN** en façade (Cloudflare, Sucuri, Akamai, Imperva, CloudFront,
  F5, ModSecurity) signalé : il peut masquer la version, et l'origine derrière
  le proxy peut différer.

### Robustesse réseau (passe les cas réels)

- **UA navigateur** par défaut : sans ça, les CDN/WAF (Cloudflare bot-management…)
  servent une page dégradée et masquent le contenu. Surchargeable via
  `GALEAX_UA="…"`.
- **Compression** gzip/br gérée (`--compressed`) et **certificats TLS invalides**
  acceptés (`-k`) — fréquents en pentest.
- **Hébergeurs managés** (Kinsta, WP Engine, Pantheon…) reconnus comme PHP.
- **Challenge anti-bot** (CF « Just a moment… », Incapsula…) détecté et signalé
  (détection partielle ; rejouer depuis une IP/navigateur autorisé).
- **Cible injoignable** (DNS/TLS/timeout/filtrage) : verdict `INJOIGNABLE` explicite.

### Détection de version — robustesse

- Plusieurs sources (en-têtes de tous les sauts de redirection, corps, `phpinfo`) ;
  en cas de versions divergentes (proxy vs backend), la **plus basse** (la plus à
  risque) est retenue et le conflit est signalé.
- **Rétroportages distribution** : sur un build Debian / Ubuntu / RHEL…, le numéro
  de version est *figé* et les correctifs sont rétroportés. Un `PHP/8.2.7` Debian
  peut donc être **déjà patché**. Dans ce cas l'outil n'affirme pas « vulnérable »
  avec certitude (confiance *moyenne*) et renvoie vers la cible **`local`**, qui
  tranche via la présence du symbole du correctif.

---

## Démonstrations (POC)

Captures des quatre cas de détection (clic → lecteur vidéo GitHub) :

| | Local (`local`) | À distance (URL) |
|---|---|---|
| **Vulnérable** | [▶ Voir la démo](media/poc/POC_DETECT_VULN_LOCAL.mp4) | [▶ Voir la démo](media/poc/POC_DETECT_VULN_REMOTE.mp4) |
| **Non vulnérable** | [▶ Voir la démo](media/poc/POC_DETECT_NOT_VULN_LOCAL.mp4) | [▶ Voir la démo](media/poc/POC_DETECT_NOT_VULN_REMOTE.mp4) |

---

## Interprétation

| Verdict | Signification |
|---|---|
| **VULNÉRABLE** | version/build antérieurs au correctif, branche EOL non corrigée, ou **crash prouvé** via `--crash` |
| **NON VULNÉRABLE** | correctif présent (version ≥ corrigée, ou symbole du correctif détecté en local) |
| **EXPOSITION RÉDUITE** | vulnérable mais une mitigation détectée limite le vecteur |
| **INDÉTERMINÉ** | version non obtenue à distance — utiliser `--deep`, `--phpinfo` ou `local` |

**Codes de sortie** : `0` non vulnérable · `1` vulnérable · `2` exposition réduite ·
`3` indéterminé.

## Remédiation

- **Appliquer le correctif PHP** : 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (remédiation
  complète — la seule qui ferme définitivement la faille).
- Branches **5.x / 7.x / 8.0 / 8.1** : en fin de vie, jamais corrigées → **migrer**.
- Durcissement partiel (ne remplace pas le correctif) : `memory_limit=-1`
  non-overridable, `post_max_size` bas, `session.upload_progress.enabled=0`,
  `allow_url_include=Off`, (PHP 8.5) `fatal_error_backtraces=0`.

---

© Galeax — Offensive Security. Pour toute question : votre contact Galeax.
