#!/bin/sh
# ════════════════════════════════════════════════════════════════════════════════
# isolate-agent.sh — Active Response Wazuh : isolation réseau d'un host
# ════════════════════════════════════════════════════════════════════════════════
#
# Déclenché par le workflow Shuffle wf-malware (scenarios) quand le risk_score
# atteint le seuil auto_contain (>=75). Coupe l'egress réseau du host cible
# sauf vers le Wazuh manager (port 1514/1515) et le DNS.
#
# CONVENTION WAZUH ACTIVE RESPONSE
# --------------------------------
# Le script reçoit une alerte JSON sur stdin (format Wazuh AR API v4).
# Les arguments en ligne de commande:
#   $1 = action ("add" | "delete")  -- Wazuh distingue déclenchement vs cleanup
#   $2 = user                       -- (vide ici)
#   $3 = srcip                      -- IP source de l'alerte
#   $4 = alertid                    -- ID de l'alerte
#   $5 = rule_id                    -- ID de la rule Wazuh
#   $6 = agentname                  -- nom de l'agent ciblé
#   $7 = agentip                    -- IP de l'agent ciblé
#
# GARDE-FOUS (en ordre, premier match = NOOP):
#   1. SOC_AR_DRY_RUN=1 (env var)         -> log only, exit 0
#   2. agent hostname in whitelist-hosts  -> log only, exit 0
#   3. agent IP in whitelist-hosts        -> log only, exit 0
#   4. action != "add"                    -> log only, exit 0 (delete = restore)
#
# DESTRUCTIVITÉ
# -------------
# iptables drop egress total sauf {DNS:53, Wazuh manager:1514-1515}.
# La restauration (action="delete") supprime les règles via comments tagué.
# Ne touche PAS les rules existantes utilisateur (filtre par commentaire SOC_AR).
# ════════════════════════════════════════════════════════════════════════════════

set -u

# ── Configuration externe (source si présente) ─────────────────────────────────
# Permet à Ansible de toggler SOC_AR_DRY_RUN sans modifier le script.
# Format du fichier: simples assignations shell (ex: SOC_AR_DRY_RUN=0).
SOC_AR_CONF="/var/ossec/active-response/soc-ar.env"
if [ -f "$SOC_AR_CONF" ]; then
    # shellcheck disable=SC1090
    . "$SOC_AR_CONF"
fi

# ── Constantes ──────────────────────────────────────────────────────────────────
LOG_FILE="/var/ossec/logs/active-response.log"
WHITELIST_FILE="/var/ossec/etc/lists/ar-whitelist-hosts.txt"
IPTABLES_COMMENT="SOC_AR_isolate-agent"
WAZUH_MANAGER_PORTS="1514,1515"

# ── Helpers ─────────────────────────────────────────────────────────────────────
log() {
    printf '%s isolate-agent[%d]: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$$" "$*" >> "$LOG_FILE"
}

in_whitelist() {
    needle="$1"
    [ -f "$WHITELIST_FILE" ] || return 1
    [ -z "$needle" ] && return 1
    grep -qE "^[[:space:]]*${needle}[[:space:]]*\$" "$WHITELIST_FILE" 2>/dev/null
}

# ── Parse args ──────────────────────────────────────────────────────────────────
action="${1:-add}"
agentname="${6:-unknown}"
agentip="${7:-unknown}"
alertid="${4:-unknown}"

log "invoked action=$action agent=$agentname agentip=$agentip alertid=$alertid argv=[$*]"

# Garde-fou 1: DRY RUN global
if [ "${SOC_AR_DRY_RUN:-1}" = "1" ]; then
    log "DRY_RUN=1 -> no-op (would have isolated $agentname/$agentip on action=$action)"
    exit 0
fi

# Garde-fou 2 & 3: whitelist hostname OR IP
if in_whitelist "$agentname" || in_whitelist "$agentip"; then
    log "WHITELIST match for $agentname/$agentip -> no-op"
    exit 0
fi

# Garde-fou 4: action "delete" = restauration => retirer les rules SOC_AR
if [ "$action" = "delete" ]; then
    if command -v iptables >/dev/null 2>&1; then
        # Supprime toutes les rules taggées SOC_AR (sortie OUTPUT)
        iptables-save 2>/dev/null | grep -v "$IPTABLES_COMMENT" | iptables-restore 2>/dev/null \
            && log "Restored egress (removed $IPTABLES_COMMENT rules)" \
            || log "Failed to restore iptables (rc=$?)"
    else
        log "iptables binary not found -> nothing to restore"
    fi
    exit 0
fi

# ── Action principale: isolate (action="add") ───────────────────────────────────
if ! command -v iptables >/dev/null 2>&1; then
    log "ERROR: iptables binary not found -> cannot enforce isolation on $agentname"
    exit 1
fi

# 1. Allow DNS (UDP/TCP 53)
iptables -A OUTPUT -p udp --dport 53 -m comment --comment "$IPTABLES_COMMENT-dns" -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m comment --comment "$IPTABLES_COMMENT-dns" -j ACCEPT

# 2. Allow Wazuh manager comms (1514/1515)
for port in $(echo "$WAZUH_MANAGER_PORTS" | tr ',' ' '); do
    iptables -A OUTPUT -p tcp --dport "$port" -m comment --comment "$IPTABLES_COMMENT-wazuh" -j ACCEPT
    iptables -A OUTPUT -p udp --dport "$port" -m comment --comment "$IPTABLES_COMMENT-wazuh" -j ACCEPT
done

# 3. Allow loopback
iptables -A OUTPUT -o lo -m comment --comment "$IPTABLES_COMMENT-lo" -j ACCEPT

# 4. Drop everything else
iptables -A OUTPUT -m comment --comment "$IPTABLES_COMMENT-deny" -j DROP

log "Isolated $agentname/$agentip (egress dropped except DNS+Wazuh manager+loopback)"
exit 0
