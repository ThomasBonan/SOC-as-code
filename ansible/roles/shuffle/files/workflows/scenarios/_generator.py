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
                 ssl_verify: str = "false", timeout: int = 90) -> dict[str, Any]:
    """Build an HTTP action with the standard parameter set.

    `timeout` (default 90s) override le default 5s du worker Shuffle http app.
    Indispensable pour les Cortex waitreport (atMost=60s) qui peuvent prendre
    jusqu'à 60s côté Cortex avant de retourner le report — sans bump à 90s côté
    worker, on tombe en ReadTimeout(5s) avant que Cortex ait répondu et le
    workflow part en ABORTED (cas vécu 2026-05-17 sur le pipeline E2E selftest).
    En cold-cache, MalwareBazaar+CIRCL+GeoIP peuvent prendre 30-50s chacun;
    atMost=60s laisse une marge pour les pics, le timeout=90s ajoute 30s de
    buffer HTTP pour roundtrip + parsing avant ReadTimeout côté worker.
    """
    params = [
        _param("url", url),
        _param("method", method),
        _param("headers", headers),
    ]
    if body is not None:
        params.append(_param("body", body))
    params.append(_param("verify", ssl_verify))
    params.append(_param("timeout", str(timeout)))
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
                          bare_value_fields: dict[str, str] | None = None,
                          x: int = 400, y: int = 0) -> dict[str, Any]:
    """Risk engine call — payload includes scenario key for multiplier (Phase 5).

    `bare_value_fields` accepte des paires nom→ref-Shuffle qui sont injectées
    SANS guillemets autour de la variable, pour que Shuffle 1.4 résolve la
    référence à une valeur JSON native (array ou dict) sans corrompre la
    syntaxe du body. Indispensable pour les arrays `cortex_*_taxonomies` et
    `misp_*_attributes` que Shuffle ne sait pas escape correctement quand
    on les injecte dans une string ("[{...nested-quotes...}]" → SyntaxError
    côté worker http app, cas vécu 2026-05-17).

    Defensive wrapping (Phase 6b, 2026-05-22) : chaque bare-value est encadrée
    par `[...]` pour absorber une substitution vide quand l'analyzer Cortex
    rend status=InProgress/Failure (cas vécu : MalwareBazaar n'a pas fini
    avant atMost=60s → `body.report.summary.taxonomies` n'existe pas → Shuffle
    substitue par '' → body devient `"x": ,` → SyntaxError côté worker Python
    AVANT le POST risk-engine → action.success=false → toute la chaîne post-
    enrichissement est SKIPPED, l'alerte reste New).

    Avec le wrap `[$expr]` :
      - $expr résout vide      → "x": []           (array vide, JSON valide)
      - $expr résout en `null` → "x": [null]       (toléré)
      - $expr résout en array  → "x": [[...]]      (single-nested, flatten
                                                    côté risk-engine v2.5+
                                                    via _coerce_list)
    """
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

    # Sérialisation : json.dumps pour les fields normaux puis on injecte les
    # bare_value_fields à la main (sans guillemets autour de la valeur Shuffle),
    # chacun wrappé dans `[...]` pour produire un JSON valide même quand
    # l'expression $expr résout en chaîne vide (voir docstring above).
    body = json.dumps(payload)
    if bare_value_fields:
        body = body.rstrip("}")
        if not body.endswith("{"):
            body += ", "
        bare_parts = [f'"{k}": [{v}]' for k, v in bare_value_fields.items()]
        body += ", ".join(bare_parts) + "}"
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


def make_update_case_risk(x: int = 1100, y: int = 150,
                          extra_tags: list[str] | None = None) -> dict[str, Any]:
    """
    Persist risk_score_v2 + risk_decision custom fields in TheHive case.
    Parity with alert-triage workflow. Without this action, the case has no
    risk_score visible in TheHive UI / selftest assertions (but the engine
    still computes it — visible in Shuffle execution results).

    `extra_tags` appends extra case tags (each a literal JSON string that MAY
    contain a Shuffle ref, e.g. "mitre:$action_normalize.body.techniques_csv").
    Used by the alert-triage workflow to surface the behavioral verdict
    (MITRE techniques / tactics) on the case. Scenarios pass nothing.

    NOTE: The custom field `risk_score_v2` uses `{"float": <value>}` envelope
    (TheHive 5 typed custom field input format). `risk_decision` uses `{"string": ...}`.
    Both fields must be pre-created (handled by 190-soc-risk-engine scoring_model).
    """
    headers = "Authorization: Bearer $ENV_THEHIVE_APIKEY\nContent-Type: application/json"
    # Build the body as a raw string (not via json.dumps) because the field
    # values contain Shuffle variable references like `$action_call_risk_engine.body.risk_score`
    # which must remain unquoted-numeric in the JSON for TheHive to accept it as float.
    tags = ['"source:wazuh"', '"risk_engine:processed"',
            '"risk_decision:$action_call_risk_engine.body.risk_decision"']
    for t in (extra_tags or []):
        tags.append('"' + t + '"')
    body = (
        '{"tags":[' + ",".join(tags) + '],'
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


def make_slack_notify(scenario_key: str, x: int = 2000, y: int = 700) -> dict[str, Any]:
    """Slack notification on escalated decision (risk_score >= 90).

    Phase 8 (2026-05-28). Posts a Block Kit message to a Slack channel via incoming
    webhook. The webhook URL is injected as a workflow_variable ENV_SLACK_WEBHOOK_URL
    by _import_scenario_workflow.yml (read from K8s Secret soc-slack-webhook, itself
    synced by ESO from Vault soc/integrations/slack, seeded from .secrets/slack.env).

    Dry-run mechanism: when soc_slack.dry_run=true at Ansible time, the import task
    INJECTS AN EMPTY URL — the HTTP action then fails with "invalid URL" but the
    branch is terminal so the rest of the workflow is unaffected. No Slack post
    happens. To enable real posts: set soc_slack.dry_run=false and re-run 185.

    The action MUST be wired by the caller as a BRANCH from action_escalate (or
    action_update_case_risk for privesc which always escalates) gated on
    risk_decision == "escalated" — see build_*_workflow().

    Block Kit fields included:
      - Header (header block, :rotating_light:)
      - Scenario, risk_score, decision (section/fields)
      - Wazuh agent name + rule id/level
      - IOC (truncated, single line, mrkdwn quoted)
      - Action button → TheHive case URL (apps.soc.lab Ingress, public-facing)
      - Channel mention (mrkdwn header field, cosmetic)

    Excluded by design:
      - Full IOC (truncated to first 32 chars + "…")
      - API keys / tokens (never referenced)
      - Stack traces (no error data forwarded)
      - Raw Wazuh log content (may contain parsed credentials)
    """
    headers = "Content-Type: application/json"

    # Per-scenario IOC field (single source: trim to 32 chars in Slack via mrkdwn).
    # We pull the same field the workflow uses for the case observable so the
    # operator sees the same value in Slack and in TheHive.
    ioc_template = {
        "malware":    "$exec.all_fields.data.hash_sha256",
        "bruteforce": "$exec.all_fields.data.srcip",
        "privesc":    "$exec.all_fields.data.dstuser",
    }.get(scenario_key, "$exec.all_fields.rule.id")

    # Build Block Kit message. Use plain concatenation (not json.dumps on the whole
    # thing) because we need Shuffle $variable refs to remain UN-quoted inside the
    # numeric `risk_score` slot — same trick as make_update_case_risk().
    body = (
        '{'
        '"channel": "$ENV_SLACK_CHANNEL",'
        '"text": "SOC ESCALATED — ' + scenario_key + ' on $exec.all_fields.agent.name '
        '(score $action_call_risk_engine.body.risk_score)",'
        '"blocks": ['
        '{"type":"header","text":{"type":"plain_text","text":":rotating_light: SOC ESCALATED",'
        '"emoji":true}},'
        '{"type":"section","fields":['
        '{"type":"mrkdwn","text":"*Scenario:*\\n' + scenario_key + '"},'
        '{"type":"mrkdwn","text":"*Risk score:*\\n$action_call_risk_engine.body.risk_score / 100"},'
        '{"type":"mrkdwn","text":"*Decision:*\\n$action_call_risk_engine.body.risk_decision"},'
        '{"type":"mrkdwn","text":"*Agent:*\\n$exec.all_fields.agent.name"},'
        '{"type":"mrkdwn","text":"*Rule:*\\n$exec.all_fields.rule.id (lvl $exec.all_fields.rule.level)"},'
        '{"type":"mrkdwn","text":"*Environment:*\\n$ENV_SOC_ENVIRONMENT"}'
        ']},'
        '{"type":"section","text":{"type":"mrkdwn",'
        '"text":"*IOC:* `' + ioc_template + '`"}},'
        '{"type":"actions","elements":['
        '{"type":"button","text":{"type":"plain_text","text":"Open TheHive case",'
        '"emoji":true},'
        '"url":"$ENV_THEHIVE_PUBLIC_URL/cases/$action_promote_to_case.body._id"}'
        ']}'
        ']'
        '}'
    )
    return _http_action(f"action_notify_slack_{scenario_key}", "POST", x, y,
                        url="$ENV_SLACK_WEBHOOK_URL",
                        headers=headers, body=body, timeout=5)


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
                     url="$ENV_CORTEX_URL/api/job/$action_run_cortex_hash_mb.body._id/waitreport?atMost=60seconds",
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
                     url="$ENV_CORTEX_URL/api/job/$action_run_cortex_hash_circl.body._id/waitreport?atMost=60seconds",
                     headers="Authorization: Bearer $ENV_CORTEX_APIKEY"),

        # MISP hash search
        _http_action("action_search_misp_hash", "POST", 200, 0,
                     url="$ENV_MISP_URL/attributes/restSearch",
                     headers="Authorization: $ENV_MISP_APIKEY\nContent-Type: application/json\nAccept: application/json",
                     body=json.dumps({"value": "$exec.all_fields.data.hash_sha256", "returnFormat": "json"})),

        # Risk engine — bare-value interpolation pour les arrays (cortex_*_taxonomies +
        # misp_hash_attributes). Voir _http_action.bare_value_fields pour explication.
        # Le risk-engine v2.4 sait parser ces arrays via _resolve_cortex_max_level +
        # _resolve_misp_hit. Cortex MalwareBazaar `malicious` → cortex_dim=100.
        make_risk_engine_call("malware", bare_value_fields={
            "cortex_hash_mb_taxonomies":    "$action_get_cortex_hash_mb_result.body.report.summary.taxonomies",
            "cortex_hash_circl_taxonomies": "$action_get_cortex_hash_circl_result.body.report.summary.taxonomies",
            "misp_hash_attributes":         "$action_search_misp_hash.body.response.Attribute",
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
        make_slack_notify("malware"),
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

        # Slack notify on escalated only (post-escalate, terminal leaf)
        _branch("action_escalate", "action_notify_slack_malware",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="escalated"),
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
                     url="$ENV_CORTEX_URL/api/job/$action_run_cortex_geoip.body._id/waitreport?atMost=60seconds",
                     headers="Authorization: Bearer $ENV_CORTEX_APIKEY"),

        _http_action("action_search_misp_ip", "POST", 200, 150,
                     url="$ENV_MISP_URL/attributes/restSearch",
                     headers="Authorization: $ENV_MISP_APIKEY\nContent-Type: application/json\nAccept: application/json",
                     body=json.dumps({"value": "$exec.all_fields.data.srcip", "returnFormat": "json"})),

        # Bare-value interpolation (cf wf-malware). AbuseIPDB `malicious` sur les
        # IPs abusives → cortex_dim=100. MISP search par IP → misp_dim=100.
        make_risk_engine_call("bruteforce", bare_value_fields={
            "cortex_taxonomies": "$action_get_cortex_geoip_result.body.report.summary.taxonomies",
            "misp_attributes":   "$action_search_misp_ip.body.response.Attribute",
        }),

        make_ignore_alert(),
        make_promote_to_case(),
        make_add_case_observable("$exec.all_fields.data.srcip", dtype="ip"),
        make_update_case_risk(),

        make_get_wazuh_jwt(),
        make_active_response("firewall-drop", "$exec.all_fields.agent.id"),
        make_escalate(severity=3, tlp=2),
        make_slack_notify("bruteforce"),
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

        # Slack notify on escalated only (post-escalate, terminal leaf)
        _branch("action_escalate", "action_notify_slack_bruteforce",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="escalated"),
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
        make_slack_notify("privesc"),
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

        # Slack notify on escalated only (post-escalate, terminal leaf).
        # privesc branches escalate unconditionally above (action_update_case_risk
        # -> action_escalate), so the gate on risk_decision == "escalated" here
        # is what guarantees Slack fires only when score >= 90.
        _branch("action_escalate", "action_notify_slack_privesc",
                condition_value="$action_call_risk_engine.body.risk_decision",
                expected="escalated"),
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
# Generic fallback workflow (alert-triage) — ROBUST rebuild (Phase 9)
# ─────────────────────────────────────────────────────────────────────────────

def build_alert_triage_workflow() -> dict[str, Any]:
    """
    Generic fallback triage workflow — replaces the hand-built alert-triage.json.

    Robustness fixes vs the legacy workflow (which deadlocked when an analyzer
    received an empty IOC):
      1. First call risk-engine /normalize → clean single-value IOCs
         (sha256 works for Windows Sysmon eventchannel AND Linux/syslog).
      2. Dispatch Cortex/MISP CONDITIONALLY (only when the IOC is present) so an
         empty value is NEVER sent to an analyzer → no failed action → no broken
         join. Pattern mirrors the proven multi-conditional-branch join already
         used for risk_decision → promote_to_case.
      3. A single-condition "no enrichable IOC" branch (has_ioc==false) routes
         behavioral-only events (e.g. encoded PowerShell with no file/net IOC)
         straight to /score → the behavioral floor still applies.
      4. command_line is forwarded to /score → PowerShell decode + YARA floor.
      5. Observables are added CONDITIONALLY (guarded) → no empty observable.

    No Active Response here: AR is scenario-specific; the generic fallback only
    creates/promotes/escalates + adds observables. Enrichment bare-value fields
    use the `[$expr]` wrapping so a non-executed branch resolves to [] safely.
    """
    trigger = _trigger_webhook("trigger_wazuh_webhook", "Wazuh Alert Webhook")

    cx_hdr = "Authorization: Bearer $ENV_CORTEX_APIKEY\nContent-Type: application/json"
    misp_hdr = "Authorization: $ENV_MISP_APIKEY\nContent-Type: application/json\nAccept: application/json"

    # /normalize body — scalar substitutions only (no bare-dict injection). Missing
    # fields resolve to literal "$..." strings which the engine ignores (startswith $).
    # rule.mitre.{id,tactic} are forwarded as QUOTED scalars (always valid JSON).
    # Whatever shape Shuffle renders the arrays into (JSON, python repr, CSV), the
    # engine's _mitre_score regex-extracts the T#### ids and substring-matches the
    # tactics — so the MITRE behavioral floor works without bare-value injection.
    norm_body = json.dumps({
        "data": {
            "hash_sha256": "$exec.all_fields.data.hash_sha256",
            "srcip":       "$exec.all_fields.data.srcip",
            "dstuser":     "$exec.all_fields.data.dstuser",
            "win": {"eventdata": {
                "hashes":      "$exec.all_fields.data.win.eventdata.hashes",
                "commandLine": "$exec.all_fields.data.win.eventdata.commandLine",
            }},
        },
        "rule": {"mitre": {
            "id":     "$exec.all_fields.rule.mitre.id",
            "tactic": "$exec.all_fields.rule.mitre.tactic",
        }},
    })

    # LINEAR SPINE (deadlock-proof). Lesson learned live (2026-05-31): Shuffle 1.4
    # DEADLOCKS a join node whose parents include conditionally-skipped 2-hop chains
    # (risk_engine stayed EXECUTING forever). So risk_engine here has EXACTLY ONE
    # parent (normalize). Deep Cortex/MISP enrichment is the SCENARIO workflows' job
    # (they work — all parents always run). The generic fallback does fast triage:
    # wazuh severity + behavioral floor (command_line decode + YARA) + asset. The
    # multi-conditional fan-out into promote_to_case is the PROVEN single-source
    # pattern. Observables are conditional terminal leaves (no join).
    actions: list[dict[str, Any]] = [
        make_create_alert("triage", severity=2),

        _http_action("action_normalize", "POST", -200, 0,
                     url="$ENV_RISK_ENGINE_URL/normalize",
                     headers="Content-Type: application/json", body=norm_body),

        # Single parent → risk_engine. Pass the INTEGER behavior_score from /normalize
        # (NOT the raw command_line — its embedded quotes/backslashes corrupt the JSON
        # body Shuffle builds, which hangs the workflow; observed live 2026-05-31).
        # No cortex/misp bare-values: those dims default to 0 (scenarios do deep enrichment).
        make_risk_engine_call("triage",
                              extra_fields={"behavior_score": "$action_normalize.body.behavior_score"},
                              x=400, y=0),

        make_ignore_alert(),
        make_promote_to_case(),
        make_add_case_observable("$action_normalize.body.sha256", dtype="hash",
                                 action_id="action_add_obs_hash", x=1300, y=-200),
        make_add_case_observable("$action_normalize.body.srcip", dtype="ip",
                                 action_id="action_add_obs_ip", x=1300, y=0),
        # PowerShell / process command — base64 (quote/$-safe for the JSON body).
        # The analyst base64-decodes; behavioral verdict is in the case tags (yara).
        _http_action("action_add_obs_cmd", "POST", 1300, 200,
                     url="$ENV_THEHIVE_URL/api/v1/case/$action_promote_to_case.body._id/observable",
                     headers="Authorization: Bearer $ENV_THEHIVE_APIKEY\nContent-Type: application/json",
                     body=json.dumps({
                         "dataType": "other",
                         "data":     "$action_normalize.body.command_b64",
                         "message":  "Process command line (base64-encoded — decode to read)",
                         "tags":     ["source:wazuh", "powershell-command", "encoding:base64"],
                     })),
        # Surface the behavioral verdict on the case: MITRE techniques + tactics
        # (Shuffle-safe CSV scalars from /normalize). One tag each — the analyst
        # sees WHICH classic technique fired (e.g. mitre:T1053.005, tactic:Persistence).
        make_update_case_risk(x=1100, y=0, extra_tags=[
            "mitre:$action_normalize.body.techniques_csv",
            "tactic:$action_normalize.body.tactics_csv",
        ]),
        make_escalate(severity=4, tlp=3),
    ]

    branches = [
        _branch("trigger_wazuh_webhook", "action_create_thehive_alert"),
        _branch("action_create_thehive_alert", "action_normalize"),
        # risk_engine: SINGLE unconditional parent → no join, never deadlocks.
        _branch("action_normalize", "action_call_risk_engine"),

        # decision branches — PROVEN single-source multi-conditional fan-out.
        # NB: "reviewed" (score 15-50) does NOT create a case — the alert stays an
        # alert for human triage. Only auto_promoted/contained/escalated promote.
        # (Fixes low-score events like file-drops being promoted with no justification.)
        _branch("action_call_risk_engine", "action_ignore_alert",    condition_value="$action_call_risk_engine.body.risk_decision", expected="auto_closed"),
        _branch("action_call_risk_engine", "action_promote_to_case", condition_value="$action_call_risk_engine.body.risk_decision", expected="auto_promoted"),
        _branch("action_call_risk_engine", "action_promote_to_case", condition_value="$action_call_risk_engine.body.risk_decision", expected="contained"),
        _branch("action_call_risk_engine", "action_promote_to_case", condition_value="$action_call_risk_engine.body.risk_decision", expected="escalated"),

        # post-promote: persist risk (single parent) + guarded observables (terminal leaves)
        _branch("action_promote_to_case", "action_update_case_risk"),
        _branch("action_promote_to_case", "action_add_obs_hash", condition_value="$action_normalize.body.has_sha256", expected="true"),
        _branch("action_promote_to_case", "action_add_obs_ip",   condition_value="$action_normalize.body.has_srcip", expected="true"),
        _branch("action_promote_to_case", "action_add_obs_cmd",  condition_value="$action_normalize.body.has_command", expected="true"),
        _branch("action_update_case_risk", "action_escalate", condition_value="$action_call_risk_engine.body.risk_decision", expected="escalated"),
    ]

    return {
        "name": "SOC Alert Triage",
        "description": "Generic fallback: Wazuh -> normalize -> risk engine (behavioral floor) -> TheHive (linear, deadlock-proof)",
        "start": "action_create_thehive_alert",
        "tags": ["soc", "triage", "fallback", "wazuh", "thehive"],
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

    # alert-triage (generic fallback) lives one level up, in files/workflows/.
    triage = build_alert_triage_workflow()
    triage_path = os.path.join(os.path.dirname(here), "alert-triage.json")
    with open(triage_path, "w") as f:
        json.dump(triage, f, indent=2)
        f.write("\n")
    print(f"  wrote ../alert-triage.json — actions={len(triage['actions'])} branches={len(triage['branches'])}")


if __name__ == "__main__":
    main()
