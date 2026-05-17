#!/usr/bin/env python3
"""
_generator.py — Génère les workflows Shuffle scenario à partir d'une spec compacte.

Usage:
    python3 _generator.py

Émet les fichiers wf-malware.json, wf-bruteforce.json, wf-privesc.json dans
le répertoire courant.

Les JSONs produits sont consommés par
roles/shuffle/tasks/_import_scenario_workflow.yml qui les patche à l'import
avec workflow_variables, environment_id, http app_id, etc.

Structure produite par scénario:
  1. Trigger WEBHOOK -> create_thehive_alert
  2. Enrichissement (Cortex analyzers + MISP) spécifique au scenario
  3. call_risk_engine (avec scenario=<key>)
  4. Branches selon risk_decision:
       auto_closed   -> ignore_alert
       reviewed      -> add_observable (no case)
       auto_promoted -> promote_to_case + add_observable
       contained     -> promote + observable + AR (custom per scenario)
       escalated     -> promote + observable + AR + escalate severity critical

Conventions Shuffle:
  - Tous les IDs d'action doivent être de longueur >= 1 (lower-case, [a-z_])
  - L'app HTTP utilisé est 1.4.0 (pinné dans defaults Shuffle)
  - Le placeholder app_id reste vide ici; il est injecté à l'import par Ansible
  - Les positions x/y sont indicatives (pour layout UI)
"""

import json
import os
from typing import Any

HTTP_APP_NAME = "http"
HTTP_APP_VERSION = "1.4.0"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _param(name: str, value: str) -> dict[str, str]:
    """Build a minimal Shuffle action parameter (only name+value required)."""
    return {"name": name, "value": value}


def _condition_field(value: str) -> dict[str, Any]:
    """Build the verbose 'field' object used in branch conditions."""
    return {
        "description": "", "id": "", "name": "", "example": "",
        "value": value, "multiline": False, "multiselect": False,
        "options": None, "action_field": "", "variant": "",
        "required": False, "configuration": False, "tags": None,
        "schema": {"type": ""}, "skip_multicheck": False,
        "value_replace": None, "unique_toggled": False,
        "error": "", "hidden": False,
    }


def _branch(source_id: str, destination_id: str, condition_value: str | None = None,
            condition_op: str = "=", expected: str | None = None) -> dict[str, Any]:
    """Build a branch with optional condition on risk_decision."""
    branch: dict[str, Any] = {
        "source_id": source_id,
        "destination_id": destination_id,
        "conditions": [],
    }
    if condition_value and expected is not None:
        branch["conditions"] = [{
            "source":      _condition_field(condition_value),
            "condition":   _condition_field(condition_op),
            "destination": _condition_field(expected),
        }]
    return branch


def _http_action(action_id: str, method: str, x: int, y: int,
                 url: str, headers: str = "", body: str | None = None,
                 ssl_verify: str = "false") -> dict[str, Any]:
    """Build an HTTP action with the standard parameter set."""
    params = [
        _param("url", url),
        _param("method", method),
        _param("headers", headers),
    ]
    if body is not None:
        params.append(_param("body", body))
    params.append(_param("verify", ssl_verify))
    return {
        "id": action_id,
        "label": action_id,
        "app_name": HTTP_APP_NAME,
        "app_version": HTTP_APP_VERSION,
        "name": method,
        "parameters": params,
        "position": {"x": x, "y": y},
    }


def _trigger_webhook(trigger_id: str, name: str) -> dict[str, Any]:
    return {
        "trigger_type": "WEBHOOK",
        "id": trigger_id,
        "name": name,
        "status": "running",
        "parameters": [{"name": "info", "value": "Webhook trigger from Wazuh"}],
        "position": {"x": -800, "y": 0},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Common action factories
# ─────────────────────────────────────────────────────────────────────────────

def make_create_alert(scenario_key: str, severity: int = 2) -> dict[str, Any]:
    """TheHive alert creation — common across all scenarios."""
    headers = "Authorization: Bearer $ENV_THEHIVE_APIKEY\nContent-Type: application/json"
    body = json.dumps({
        "title": f"[{scenario_key.upper()}] $exec.all_fields.rule.description",
        "type": "External",
        "source": "wazuh",
        "sourceRef": "wazuh-$exec.all_fields.agent.id-$exec.all_fields.rule.id-$exec.all_fields.timestamp",
        "description": (
            "Agent: $exec.all_fields.agent.name ($exec.all_fields.agent.ip) | "
            "Rule: $exec.all_fields.rule.id | Level: $exec.all_fields.rule.level | "
            f"Scenario: {scenario_key}"
        ),
        "severity": severity,
        "tags": [
            "source:wazuh",
            f"scenario:{scenario_key}",
            "agent:$exec.all_fields.agent.name",
            "rule:$exec.all_fields.rule.id",
        ],
    })
    return _http_action("action_create_thehive_alert", "POST", -400, 0,
                        url="$ENV_THEHIVE_URL/api/v1/alert",
                        headers=headers, body=body)


def make_risk_engine_call(scenario_key: str, extra_fields: dict[str, str] | None = None,
                          x: int = 400, y: int = 0) -> dict[str, Any]:
    """Risk engine call — payload includes scenario key for multiplier (Phase 5)."""
    headers = "Content-Type: application/json"
    payload = {
        "case_id": "$action_create_thehive_alert.body._id",
        "wazuh_severity": "$exec.all_fields.rule.level",
        "agent_name": "$exec.all_fields.agent.name",
        "asset_type": "$exec.all_fields.agent.labels.type",
        "scenario": scenario_key,
        "frequency": 1,
        "environment": "$ENV_SOC_ENVIRONMENT",
    }
    if extra_fields:
        payload.update(extra_fields)
    body = json.dumps(payload)
    return _http_action("action_call_risk_engine", "POST", x, y,
                        url="$ENV_RISK_ENGINE_URL/score",
                        headers=headers, body=body)


def make_ignore_alert() -> dict[str, Any]:
    headers = "Authorization: Bearer $ENV_THEHIVE_APIKEY\nContent-Type: application/json"
    body = json.dumps({"status": "Ignored"})
    return _http_action("action_ignore_alert", "PATCH", 800, -300,
                        url="$ENV_THEHIVE_URL/api/v1/alert/$action_create_thehive_alert.body._id",
                        headers=headers, body=body)


def make_promote_to_case(suffix: str = "") -> dict[str, Any]:
    headers = "Authorization: Bearer $ENV_THEHIVE_APIKEY\nContent-Type: application/json"
    body = json.dumps({})
    return _http_action(f"action_promote_to_case{suffix}", "POST", 800, 0,
                        url="$ENV_THEHIVE_URL/api/v1/alert/$action_create_thehive_alert.body._id/case",
                        headers=headers, body=body)


def make_add_case_observable(data_template: str, dtype: str = "other",
                             action_id: str = "action_add_case_observable",
                             x: int = 1100, y: int = 0) -> dict[str, Any]:
    headers = "Authorization: Bearer $ENV_THEHIVE_APIKEY\nContent-Type: application/json"
    body = json.dumps({
        "dataType": dtype,
        "data": data_template,
        "tags": ["source:wazuh"],
    })
    return _http_action(action_id, "POST", x, y,
                        url="$ENV_THEHIVE_URL/api/v1/case/$action_promote_to_case.body._id/observable",
                        headers=headers, body=body)


def make_escalate(severity: int = 4, tlp: int = 3,
                  action_id: str = "action_escalate",
                  x: int = 1400, y: int = 300) -> dict[str, Any]:
    """Escalate the case (raise severity + TLP)."""
    headers = "Authorization: Bearer $ENV_THEHIVE_APIKEY\nContent-Type: application/json"
    body = json.dumps({"severity": severity, "tlp": tlp, "flag": True})
    return _http_action(action_id, "PATCH", x, y,
                        url="$ENV_THEHIVE_URL/api/v1/case/$action_promote_to_case.body._id",
                        headers=headers, body=body)


def make_update_case_risk(x: int = 1100, y: int = 150) -> dict[str, Any]:
    """
    Persist risk_score_v2 + risk_decision custom fields in TheHive case.
    Parity with alert-triage workflow. Without this action, the case has no
    risk_score visible in TheHive UI / selftest assertions (but the engine
    still computes it — visible in Shuffle execution results).

    NOTE: The custom field `risk_score_v2` uses `{"float": <value>}` envelope
    (TheHive 5 typed custom field input format). `risk_decision` uses `{"string": ...}`.
    Both fields must be pre-created (handled by 190-soc-risk-engine scoring_model).
    """
    headers = "Authorization: Bearer $ENV_THEHIVE_APIKEY\nContent-Type: application/json"
    # Build the body as a raw string (not via json.dumps) because the field
    # values contain Shuffle variable references like `$action_call_risk_engine.body.risk_score`
    # which must remain unquoted-numeric in the JSON for TheHive to accept it as float.
    body = (
        '{"tags":["source:wazuh","risk_engine:processed",'
        '"risk_decision:$action_call_risk_engine.body.risk_decision"],'
        '"customFields":{'
        '"risk_score_v2":{"float":$action_call_risk_engine.body.risk_score},'
        '"risk_decision":{"string":"$action_call_risk_engine.body.risk_decision"}'
        '}}'
    )
    return _http_action("action_update_case_risk", "PATCH", x, y,
                        url="$ENV_THEHIVE_URL/api/v1/case/$action_promote_to_case.body._id",
                        headers=headers, body=body)


def make_get_wazuh_jwt(x: int = 1400, y: int = 400) -> dict[str, Any]:
    """Authenticate against Wazuh API to get a JWT for the AR call."""
    headers = "Authorization: Basic $ENV_WAZUH_B64AUTH"
    return _http_action("action_get_wazuh_jwt", "POST", x, y,
                        url="$ENV_WAZUH_API_URL/security/user/authenticate",
                        headers=headers, body=None)


def make_active_response(ar_command: str, agent_id_template: str,
                         action_id: str = "action_active_response",
                         x: int = 1700, y: int = 400,
                         extra_args: list[str] | None = None) -> dict[str, Any]:
    """Call Wazuh API to trigger an Active Response on the target agent."""
    headers = (
        "Authorization: Bearer $action_get_wazuh_jwt.body.data.token\n"
        "Content-Type: application/json"
    )
    payload = {
        "command": ar_command,
        "alert": {"data": {"srcip": "$exec.all_fields.data.srcip"}},
        "arguments": extra_args or [],
    }
    qs = f"?agents_list={agent_id_template}"
    body = json.dumps(payload)
    return _http_action(action_id, "PUT", x, y,
                        url=f"$ENV_WAZUH_API_URL/active-response{qs}",
                        headers=headers, body=body)


def make_misp_event(scenario_key: str, observable_type: str, observable_template: str,
                    x: int = 1700, y: int = 600) -> dict[str, Any]:
    headers = "Authorization: $ENV_MISP_APIKEY\nContent-Type: application/json"
    body = json.dumps({
        "Event": {
            "info": f"[SOC-{scenario_key}] $exec.all_fields.rule.description",
            "distribution": 0,
            "threat_level_id": 2,
            "analysis": 1,
            "Attribute": [{
                "type": observable_type,
                "value": observable_template,
                "category": "Network activity" if observable_type.startswith("ip") else "Payload delivery",
                "to_ids": True,
                "comment": "Case: $action_promote_to_case.body._id | Score: $action_call_risk_engine.body.risk_score",
            }],
        }
    })
    return _http_action("action_misp_create_event", "POST", x, y,
                        url="$ENV_MISP_URL/events/add", headers=headers, body=body)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario builders
# ─────────────────────────────────────────────────────────────────────────────

def build_malware_workflow() -> dict[str, Any]:
    """
    Malware execution scenario.
    Source events: Sysmon ProcessCreate with hash (rules 100200-100202).
    Enrichment: hash analyzers (MalwareBazaar, CIRCL) + MISP hash search.
    AR: isolate-agent (custom script, Phase 4).
    """
    trigger = _trigger_webhook("trigger_wazuh_webhook", "Wazuh Malware Webhook")

    actions: list[dict[str, Any]] = [
        make_create_alert("malware", severity=3),

        # Cortex MalwareBazaar
        _http_action("action_run_cortex_hash_mb", "POST", -100, -150,
                     url="$ENV_CORTEX_URL/api/analyzer/$ENV_CORTEX_HASH_ANALYZER_MB/run",
                     headers="Authorization: Bearer $ENV_CORTEX_APIKEY\nContent-Type: application/json",
                     body=json.dumps({
                         "data": "$exec.all_fields.data.hash_sha256",
                         "dataType": "hash",
                         "tlp": 2,
                         "message": "auto-malware-mb",
                     })),
        _http_action("action_get_cortex_hash_mb_result", "GET", 100, -150,
                     url="$ENV_CORTEX_URL/api/job/$action_run_cortex_hash_mb.body._id/waitreport?atMost=30seconds",
                     headers="Authorization: Bearer $ENV_CORTEX_APIKEY"),

        # Cortex CIRCL Hashlookup
        _http_action("action_run_cortex_hash_circl", "POST", -100, 150,
                     url="$ENV_CORTEX_URL/api/analyzer/$ENV_CORTEX_HASH_ANALYZER_CIRCL/run",
                     headers="Authorization: Bearer $ENV_CORTEX_APIKEY\nContent-Type: application/json",
                     body=json.dumps({
                         "data": "$exec.all_fields.data.hash_sha256",
                         "dataType": "hash",
                         "tlp": 2,
                         "message": "auto-malware-circl",
                     })),
        _http_action("action_get_cortex_hash_circl_result", "GET", 100, 150,
                     url="$ENV_CORTEX_URL/api/job/$action_run_cortex_hash_circl.body._id/waitreport?atMost=30seconds",
                     headers="Authorization: Bearer $ENV_CORTEX_APIKEY"),

        # MISP hash search
        _http_action("action_search_misp_hash", "POST", 200, 0,
                     url="$ENV_MISP_URL/attributes/restSearch",
                     headers="Authorization: $ENV_MISP_APIKEY\nContent-Type: application/json\nAccept: application/json",
                     body=json.dumps({"value": "$exec.all_fields.data.hash_sha256", "returnFormat": "json"})),

        # Risk engine — pass cortex taxonomy_level (scalar string) only.
        # Les fields *_taxonomies (arrays) ont été retirés : Shuffle injecte la valeur
        # comme string brute dans le JSON body, ce qui corrompt la syntaxe quand le
        # tableau contient des guillemets (`"[{"level":"safe"...}]"` casse ast.literal_eval
        # côté worker → SyntaxError, jamais d'appel au risk-engine).
        # Le risk-engine v2.4 sait inférer max_level à partir de _taxonomy_level scalaire.
        make_risk_engine_call("malware", extra_fields={
            "cortex_hash_mb_taxonomy_level":    "$action_get_cortex_hash_mb_result.body.report.summary.taxonomies.0.level",
            "cortex_hash_circl_taxonomy_level": "$action_get_cortex_hash_circl_result.body.report.summary.taxonomies.0.level",
            "misp_hash_attributes":             "$action_search_misp_hash.body.response.Attribute",
        }),

        # Branches
        make_ignore_alert(),
        make_promote_to_case(),
        make_add_case_observable("$exec.all_fields.data.hash_sha256", dtype="hash"),
        make_update_case_risk(),

        # Escalated path: Wazuh AR (isolate-agent)
        make_get_wazuh_jwt(),
        make_active_response("isolate-agent",
                             "$exec.all_fields.agent.id",
                             extra_args=["isolate"]),
        make_misp_event("malware", "sha256", "$exec.all_fields.data.hash_sha256"),
        make_escalate(severity=4, tlp=3),
    ]

    # Branches: trigger -> create_alert; create_alert -> 5 enrichments;
    # all enrichments -> risk_engine; risk_engine -> 5 conditional branches
    branches = [
        _branch("trigger_wazuh_webhook", "action_create_thehive_alert"),
        _branch("action_create_thehive_alert", "action_run_cortex_hash_mb"),
        _branch("action_run_cortex_hash_mb",   "action_get_cortex_hash_mb_result"),
        _branch("action_create_thehive_alert", "action_run_cortex_hash_circl"),
        _branch("action_run_cortex_hash_circl","action_get_cortex_hash_circl_result"),
        _branch("action_create_thehive_alert", "action_search_misp_hash"),
        _branch("action_get_cortex_hash_mb_result",    "action_call_risk_engine"),
        _branch("action_get_cortex_hash_circl_result", "action_call_risk_engine"),
        _branch("action_search_misp_hash",             "action_call_risk_engine"),

        # 5 conditional branches from risk_engine
        _branch("action_call_risk_engine", "action_ignore_alert",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="auto_closed"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="reviewed"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="auto_promoted"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="contained"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="escalated"),

        # After promote_to_case -> add observable -> update_case_risk
        _branch("action_promote_to_case",     "action_add_case_observable"),
        _branch("action_add_case_observable", "action_update_case_risk"),

        # Contained/escalated path: AR + MISP + escalate (gated on risk_decision)
        _branch("action_update_case_risk", "action_get_wazuh_jwt",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="contained"),
        _branch("action_update_case_risk", "action_get_wazuh_jwt",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="escalated"),
        _branch("action_get_wazuh_jwt",   "action_active_response"),
        _branch("action_active_response", "action_misp_create_event"),
        _branch("action_misp_create_event", "action_escalate"),
    ]

    return {
        "name": "SOC Malware Triage",
        "description": "Sysmon ProcessCreate -> hash analyzers -> MISP -> risk engine -> isolate-agent if score>=75",
        "start": "action_create_thehive_alert",
        "tags": ["soc", "scenario", "malware", "wazuh", "thehive", "cortex", "misp"],
        "actions": actions,
        "triggers": [trigger],
        "branches": branches,
        "workflow_variables": [],
    }


def build_bruteforce_workflow() -> dict[str, Any]:
    """
    Brute-force authentication scenario.
    Source events: SSH/Win/RDP auth failures (5712, 60122, 92657).
    Enrichment: MaxMind GeoIP on srcip + MISP IP search.
    AR: firewall-drop (Wazuh native).
    """
    trigger = _trigger_webhook("trigger_wazuh_webhook", "Wazuh BruteForce Webhook")

    actions: list[dict[str, Any]] = [
        make_create_alert("bruteforce", severity=2),

        _http_action("action_run_cortex_geoip", "POST", -100, -150,
                     url="$ENV_CORTEX_URL/api/analyzer/$ENV_CORTEX_ANALYZER/run",
                     headers="Authorization: Bearer $ENV_CORTEX_APIKEY\nContent-Type: application/json",
                     body=json.dumps({
                         "data": "$exec.all_fields.data.srcip",
                         "dataType": "ip",
                         "tlp": 2,
                         "message": "auto-bruteforce-geoip",
                     })),
        _http_action("action_get_cortex_geoip_result", "GET", 100, -150,
                     url="$ENV_CORTEX_URL/api/job/$action_run_cortex_geoip.body._id/waitreport?atMost=30seconds",
                     headers="Authorization: Bearer $ENV_CORTEX_APIKEY"),

        _http_action("action_search_misp_ip", "POST", 200, 150,
                     url="$ENV_MISP_URL/attributes/restSearch",
                     headers="Authorization: $ENV_MISP_APIKEY\nContent-Type: application/json\nAccept: application/json",
                     body=json.dumps({"value": "$exec.all_fields.data.srcip", "returnFormat": "json"})),

        # NOTE: cortex_taxonomies (array) retiré — corrompt le body JSON quand Shuffle
        # interpole un tableau de dicts comme string. Voir wf-malware pour le pattern.
        make_risk_engine_call("bruteforce", extra_fields={
            "cortex_taxonomy_level": "$action_get_cortex_geoip_result.body.report.summary.taxonomies.0.level",
            "misp_attributes":       "$action_search_misp_ip.body.response.Attribute",
        }),

        make_ignore_alert(),
        make_promote_to_case(),
        make_add_case_observable("$exec.all_fields.data.srcip", dtype="ip"),
        make_update_case_risk(),

        make_get_wazuh_jwt(),
        make_active_response("firewall-drop", "$exec.all_fields.agent.id"),
        make_escalate(severity=3, tlp=2),
    ]

    branches = [
        _branch("trigger_wazuh_webhook",       "action_create_thehive_alert"),
        _branch("action_create_thehive_alert", "action_run_cortex_geoip"),
        _branch("action_run_cortex_geoip",     "action_get_cortex_geoip_result"),
        _branch("action_create_thehive_alert", "action_search_misp_ip"),
        _branch("action_get_cortex_geoip_result", "action_call_risk_engine"),
        _branch("action_search_misp_ip",          "action_call_risk_engine"),

        _branch("action_call_risk_engine", "action_ignore_alert",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="auto_closed"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="reviewed"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="auto_promoted"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="contained"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="escalated"),

        _branch("action_promote_to_case",     "action_add_case_observable"),
        _branch("action_add_case_observable", "action_update_case_risk"),
        _branch("action_update_case_risk",    "action_get_wazuh_jwt",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="contained"),
        _branch("action_update_case_risk",    "action_get_wazuh_jwt",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="escalated"),
        _branch("action_get_wazuh_jwt",   "action_active_response"),
        _branch("action_active_response", "action_escalate"),
    ]

    return {
        "name": "SOC BruteForce Triage",
        "description": "SSH/RDP auth failures -> GeoIP + MISP IP -> risk engine -> firewall-drop if score>=75",
        "start": "action_create_thehive_alert",
        "tags": ["soc", "scenario", "bruteforce", "wazuh", "thehive", "cortex", "misp"],
        "actions": actions,
        "triggers": [trigger],
        "branches": branches,
        "workflow_variables": [],
    }


def build_privesc_workflow() -> dict[str, Any]:
    """
    Privilege escalation scenario.
    Source events: sudo abuse, Win SeDebugPrivilege (5402, 5403, 4672).
    Enrichment: agent context (Wazuh /agents/{id}).
    AR: disable-account (custom script, Phase 4).
    """
    trigger = _trigger_webhook("trigger_wazuh_webhook", "Wazuh PrivEsc Webhook")

    actions: list[dict[str, Any]] = [
        make_create_alert("privesc", severity=3),

        # Enrich with agent details (host, OS, groups)
        _http_action("action_get_wazuh_jwt_enrich", "POST", -100, -150,
                     url="$ENV_WAZUH_API_URL/security/user/authenticate",
                     headers="Authorization: Basic $ENV_WAZUH_B64AUTH"),
        _http_action("action_enrich_agent_context", "GET", 100, -150,
                     url="$ENV_WAZUH_API_URL/agents/$exec.all_fields.agent.id",
                     headers="Authorization: Bearer $action_get_wazuh_jwt_enrich.body.data.token"),

        make_risk_engine_call("privesc", extra_fields={
            "agent_os":     "$action_enrich_agent_context.body.data.affected_items.0.os.platform",
            "agent_groups": "$action_enrich_agent_context.body.data.affected_items.0.group",
        }),

        make_ignore_alert(),
        make_promote_to_case(),
        make_add_case_observable("$exec.all_fields.data.dstuser", dtype="user"),
        make_update_case_risk(),

        make_get_wazuh_jwt(),
        make_active_response("disable-account", "$exec.all_fields.agent.id"),
        # privesc = always escalate at high severity even at "reviewed" decision
        make_escalate(severity=4, tlp=3),
    ]

    branches = [
        _branch("trigger_wazuh_webhook",          "action_create_thehive_alert"),
        _branch("action_create_thehive_alert",    "action_get_wazuh_jwt_enrich"),
        _branch("action_get_wazuh_jwt_enrich",    "action_enrich_agent_context"),
        _branch("action_enrich_agent_context",    "action_call_risk_engine"),

        _branch("action_call_risk_engine", "action_ignore_alert",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="auto_closed"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="reviewed"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="auto_promoted"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="contained"),
        _branch("action_call_risk_engine", "action_promote_to_case",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="escalated"),

        _branch("action_promote_to_case",     "action_add_case_observable"),
        _branch("action_add_case_observable", "action_update_case_risk"),
        # privesc => always escalate after risk update (no condition gating)
        _branch("action_update_case_risk", "action_escalate"),
        # AR only on contained/escalated
        _branch("action_update_case_risk", "action_get_wazuh_jwt",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="contained"),
        _branch("action_update_case_risk", "action_get_wazuh_jwt",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="escalated"),
        _branch("action_get_wazuh_jwt",   "action_active_response"),
    ]

    return {
        "name": "SOC PrivEsc Triage",
        "description": "Sudo/SeDebug abuse -> agent enrichment -> risk engine -> disable-account if score>=75 (always escalate)",
        "start": "action_create_thehive_alert",
        "tags": ["soc", "scenario", "privesc", "wazuh", "thehive"],
        "actions": actions,
        "triggers": [trigger],
        "branches": branches,
        "workflow_variables": [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    workflows = {
        "wf-malware.json":    build_malware_workflow(),
        "wf-bruteforce.json": build_bruteforce_workflow(),
        "wf-privesc.json":    build_privesc_workflow(),
    }
    for filename, wf in workflows.items():
        path = os.path.join(here, filename)
        with open(path, "w") as f:
            json.dump(wf, f, indent=2)
            f.write("\n")
        print(f"  wrote {filename} — actions={len(wf['actions'])} branches={len(wf['branches'])}")


if __name__ == "__main__":
    main()
