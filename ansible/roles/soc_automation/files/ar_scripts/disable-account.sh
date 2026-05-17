#!/bin/sh
# ════════════════════════════════════════════════════════════════════════════════
# disable-account.sh — Active Response Wazuh : verrouillage compte utilisateur
# ════════════════════════════════════════════════════════════════════════════════
#
# Déclenché par le workflow Shuffle wf-privesc quand le risk_score atteint le
# seuil auto_contain (>=75). Verrouille le compte utilisateur cible via
# `passwd -l` (Linux) - équivalent Windows hors scope ici.
#
# CONVENTION WAZUH ACTIVE RESPONSE
# --------------------------------
# $1 = action ("add" | "delete")
# $2 = user                   -- compte cible (CHAMP CRITIQUE ici)
# $3 = srcip                  -- (peu utile pour privesc)
# $4 = alertid
# $5 = rule_id
# $6 = agentname
# $7 = agentip
#
# GARDE-FOUS (en ordre, premier match = NOOP):
#   1. SOC_AR_DRY_RUN=1 (env var)              -> log only
#   2. user absent (vide)                       -> error + exit 1
#   3. user in whitelist-users                  -> log only (admin, soc-ops, root)
#   4. action != "add"                          -> action="delete" = unlock
# ════════════════════════════════════════════════════════════════════════════════

set -u

# Configuration externe (source si présente). Ansible-managed.
SOC_AR_CONF="/var/ossec/active-response/soc-ar.env"
if [ -f "$SOC_AR_CONF" ]; then
    # shellcheck disable=SC1090
    . "$SOC_AR_CONF"
fi

LOG_FILE="/var/ossec/logs/active-response.log"
WHITELIST_FILE="/var/ossec/etc/lists/ar-whitelist-users.txt"

log() {
    printf '%s disable-account[%d]: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$$" "$*" >> "$LOG_FILE"
}

in_whitelist() {
    needle="$1"
    [ -f "$WHITELIST_FILE" ] || return 1
    [ -z "$needle" ] && return 1
    grep -qE "^[[:space:]]*${needle}[[:space:]]*\$" "$WHITELIST_FILE" 2>/dev/null
}

action="${1:-add}"
target_user="${2:-}"
alertid="${4:-unknown}"
agentname="${6:-unknown}"

log "invoked action=$action user=$target_user agent=$agentname alertid=$alertid"

# Garde-fou 1
if [ "${SOC_AR_DRY_RUN:-1}" = "1" ]; then
    log "DRY_RUN=1 -> no-op (would have ${action}ed user=$target_user on $agentname)"
    exit 0
fi

# Garde-fou 2
if [ -z "$target_user" ]; then
    log "ERROR: empty user argument -> cannot $action account"
    exit 1
fi

# Garde-fou 3 (toujours appliqué, même en "delete" — on ne touche jamais les protégés)
if in_whitelist "$target_user"; then
    log "WHITELIST match for user=$target_user -> no-op"
    exit 0
fi

# Vérifier que le user existe
if ! id "$target_user" >/dev/null 2>&1; then
    log "ERROR: user=$target_user does not exist on $agentname"
    exit 1
fi

# ── Action ────────────────────────────────────────────────────────────────────
case "$action" in
    add)
        if command -v passwd >/dev/null 2>&1; then
            if passwd -l "$target_user" >> "$LOG_FILE" 2>&1; then
                log "Locked account user=$target_user"
                exit 0
            else
                log "ERROR: passwd -l $target_user failed (rc=$?)"
                exit 1
            fi
        else
            log "ERROR: passwd binary not found"
            exit 1
        fi
        ;;
    delete)
        if command -v passwd >/dev/null 2>&1; then
            if passwd -u "$target_user" >> "$LOG_FILE" 2>&1; then
                log "Unlocked account user=$target_user (action=delete)"
                exit 0
            else
                log "ERROR: passwd -u $target_user failed (rc=$?)"
                exit 1
            fi
        else
            log "ERROR: passwd binary not found"
            exit 1
        fi
        ;;
    *)
        log "ERROR: unknown action=$action"
        exit 1
        ;;
esac
