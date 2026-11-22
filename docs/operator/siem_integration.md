# SIEM Integration — Operator Setup Guide

**Audience**: platform operators wiring Recurse's SIEM Log Forwarder (FR-048 surface 1) into a
customer's existing SIEM.
**Schema reference**: the full event schema, transport options, and GRC alert recipes live in
`specs/001-api-jido-foundations/contracts/siem_log_forwarder.md`. This document is a tight,
per-SIEM operator's setup guide. Every field referenced here is defined there.

Three target SIEMs ship Phase-1 first-class: **Splunk HEC**, **Datadog Logs**, **Microsoft
Sentinel**. Each section below is intentionally tight (~one page). Additional SIEMs (Sumo
Logic, Elastic, generic syslog) are Feature 002+ work.

---

## 1. Splunk HEC (HTTP Event Collector)

### 1.1 Prerequisites

- Splunk Enterprise or Splunk Cloud with HEC enabled.
- An HEC token with `indexer ack: disabled` (at-least-once semantics are provided by the
  forwarder; indexer ack adds latency without improving correctness here).
- An index dedicated to Recurse events — recommended name: `recurse`. Sourcetype:
  `recurse:siem`.

### 1.2 Forwarder config (vector recommended; fluentd alternative)

Vector config for stdout → Splunk HEC:

```toml
[sources.recurse_siem]
type = "stdin"                     # Recurse Gateway emits NDJSON on stdout
max_length = 1048576

[transforms.recurse_parse]
type = "remap"
inputs = ["recurse_siem"]
source = '''
. = parse_json!(.message)
.host = "recurse-gateway"
.source = "recurse:siem"
'''

[sinks.splunk_hec]
type = "splunk_hec_logs"
inputs = ["recurse_parse"]
endpoint = "https://splunk.corp.example:8088"
default_token = "${SPLUNK_HEC_TOKEN}"
index = "recurse"
sourcetype = "recurse:siem"
encoding.codec = "json"
batch.max_events = 500
batch.timeout_secs = 5
compression = "gzip"
request.retry_attempts = 6
tls.verify_certificate = true
```

The forwarder's built-in HTTP-push mode (§3.2 of `siem_log_forwarder.md`) is the
no-sidecar alternative; see that doc for direct-to-HEC config.

### 1.3 Field-mapping table (SIEM schema → Splunk field names)

Splunk's default indexing flattens dotted paths. The forwarder emits dotted nested objects
(`principal.kind`, `machine_identity.spiffe_id`); Splunk's default `KV_MODE=json` + automatic
KV extraction handles these directly. Only `_time` needs explicit mapping.

| SIEM field | Splunk field | Notes |
|---|---|---|
| `timestamp` | `_time` | Set via `TIME_PREFIX="timestamp":"` + `TIME_FORMAT=%Y-%m-%dT%H:%M:%S.%3N%Z` in `props.conf` |
| `event_id` | `event_id` | Dedup key; configure at search time with `dedup event_id` |
| `tenant_id` | `tenant_id` | Recommend a tenant-scoped index-time field for multi-tenant Splunk deployments |
| `principal.kind` | `principal.kind` | Auto-extracted |
| `principal.subject` | `principal.subject` | `obo_human` only |
| `principal.account_id` | `principal.account_id` | `service_account` only |
| `machine_identity.spiffe_id` | `machine_identity.spiffe_id` | Governance shapes |
| `machine_identity.observed_jwt_subject` | `machine_identity.observed_jwt_subject` | Standalone Gateway shape |
| `tool_called` | `tool_called` | Use `like(tool_called, "aws:iam:%")` in alerts |
| `policy_decision` | `policy_decision` | `ALLOW` / `DENY` / `NOT_APPLICABLE` |
| `policy_canonical_hash` | `policy_canonical_hash` | Join key for correlating receipts across bundle versions |
| `verification_level` | `verification_level` | Enum: `signed`, `local_inclusion_verified`, `global_inclusion_verified` |
| `session_state` | `session_state` | Non-null for boundary events |
| `commit_retry_exhausted` | `commit_retry_exhausted` | Boolean; critical-alert target (SC-015) |

Example `props.conf`:

```ini
[recurse:siem]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%Z
KV_MODE = json
TRUNCATE = 65536
```

### 1.4 Sample alert — service-account DENY spike

Saved search (`savedsearches.conf`):

```ini
[Recurse — service-account DENY spike]
search = index=recurse sourcetype=recurse:siem principal.kind=service_account policy_decision=DENY tool_called=aws:iam:* \
 | bin _time span=10m \
 | stats count AS deny_count BY _time, principal.account_id, tenant_id \
 | where deny_count >= 5
dispatch.earliest_time = -15m
dispatch.latest_time = now
cron_schedule = */5 * * * *
action.email = 1
action.email.to = grc-oncall@corp.example
action.email.subject = Recurse: service-account DENY spike — $result.principal.account_id$
alert.severity = 3
```

---

## 2. Datadog Logs

### 2.1 Prerequisites

- Datadog account with Logs enabled.
- Datadog API key (for `dd-agent`) or a HTTP intake endpoint + API key for direct push.
- A Pipeline configured on the Datadog side for `service:recurse` — we install a preprocessor
  to move `timestamp` into Datadog's reserved `@timestamp` attribute.

### 2.2 `dd-agent` config snippet

`/etc/datadog-agent/conf.d/recurse.d/conf.yaml`:

```yaml
logs:
  - type: tcp
    port: 10514                    # forwarder writes NDJSON to this TCP listener
    service: recurse
    source: recurse-siem
    sourcecategory: sourcecode
    log_processing_rules:
      - type: multi_line
        pattern: ^\{
        name: json_event_start
```

Alternative: if the Gateway emits to a file, use `type: file` with `path: /var/log/recurse/siem.ndjson`.

### 2.3 Log parsing pipeline (Datadog UI → Logs → Pipelines → New)

Required preprocessors (apply in order):

1. **JSON parser** — parses the NDJSON into structured attributes.
2. **Date remapper** — source: `timestamp` → target: official date (`@timestamp`).
3. **Service remapper** — source: `recurse_deployment_shape` → target: `service` (override to
   `recurse-<shape>`, e.g., `recurse-managed-saas`).
4. **Status remapper** — custom rule mapping `policy_decision`:
   - `ALLOW` → `info`
   - `DENY` → `warn`
   - `NOT_APPLICABLE` → `info`
5. **Trace ID remapper** — source: `correlation_id` → target: `trace_id` (enables distributed
   tracing correlation in APM if customer uses it).
6. **Reserved attribute remapper** — source: `machine_identity.spiffe_id` → target: `host.id`
   (Datadog's host-dedup field; avoids clobbering `host`).

### 2.4 Field-mapping table

| SIEM field | Datadog attribute | Notes |
|---|---|---|
| `timestamp` | `@timestamp` | Set by Date remapper |
| `correlation_id` | `@trace_id` | Enables APM tie-in |
| `event_id` | `@event_id` | Dedup key |
| `tenant_id` | `@tenant_id` | Facet candidate |
| `principal.kind` | `@principal.kind` | Facet candidate |
| `principal.subject` | `@principal.subject` | `obo_human` only |
| `policy_decision` | `@policy_decision` | Status remapper also uses this |
| `tool_called` | `@tool_called` | Facet candidate |
| `recurse_deployment_shape` | `service` | Service remapper |
| `commit_retry_exhausted` | `@commit_retry_exhausted` | Monitor target |

### 2.5 Sample monitor — OBO human admin-escalation attempts

Monitor definition (Datadog → Monitors → New → Logs):

```yaml
name: "Recurse — OBO human admin-escalation pattern"
type: log alert
query: |
  logs("service:recurse-managed-saas @event_kind:tool_call @policy_decision:DENY
        @principal.kind:obo_human
        @tool_called:(aws:iam:* OR gcp:iam:* OR mcp://admin/*)")
    .rollup("count").by("@principal.subject","@tenant_id").last("5m") > 3
message: |
  {{#is_alert}}
  OBO human {{@principal.subject.name}} in tenant {{@tenant_id.name}} hit >3 admin-scope
  DENYs in 5m. Review session history in Recurse Audit Plane.
  {{/is_alert}}
  @pagerduty-grc
tags:
  - team:grc
  - recurse:enterprise
```

---

## 3. Microsoft Sentinel

### 3.1 Prerequisites

- Azure Log Analytics workspace.
- A Data Collector API endpoint + Shared Key (preferred) OR a Log Ingestion API via a Data
  Collection Rule + Data Collection Endpoint (Azure's modern replacement — recommended for new
  deployments).
- Custom table: `Recurse_SIEM_CL` (the `_CL` suffix is auto-appended by Log Analytics for
  custom logs).

### 3.2 Log Analytics workspace config

For the modern Log Ingestion API path:

1. Create a Data Collection Endpoint (DCE) in the same region as the workspace.
2. Create a custom table via ARM:

```json
{
  "properties": {
    "schema": {
      "name": "Recurse_SIEM_CL",
      "columns": [
        {"name": "TimeGenerated",         "type": "datetime"},
        {"name": "event_id_s",            "type": "string"},
        {"name": "tenant_id_s",           "type": "string"},
        {"name": "run_id_s",              "type": "string"},
        {"name": "session_id_s",          "type": "string"},
        {"name": "turn_id_s",             "type": "string"},
        {"name": "step_id_s",             "type": "string"},
        {"name": "event_kind_s",          "type": "string"},
        {"name": "correlation_id_s",      "type": "string"},
        {"name": "machine_identity_s",    "type": "dynamic"},
        {"name": "principal_s",           "type": "dynamic"},
        {"name": "tool_called_s",         "type": "string"},
        {"name": "policy_decision_s",     "type": "string"},
        {"name": "policy_canonical_hash_s","type": "string"},
        {"name": "verification_level_s",  "type": "string"},
        {"name": "tier_completeness_advisory_s", "type": "string"},
        {"name": "session_state_s",       "type": "string"},
        {"name": "commit_retry_exhausted_b","type": "bool"},
        {"name": "signer_s",              "type": "string"},
        {"name": "payload_hash_s",        "type": "string"},
        {"name": "payload_uri_s",         "type": "string"},
        {"name": "recurse_deployment_shape_s", "type": "string"}
      ]
    }
  }
}
```

3. Create a Data Collection Rule referencing the custom table and the DCE.
4. Configure the Recurse SIEM Log Forwarder's HTTP push mode with `auth.kind: sentinel_shared_key`
   (legacy HTTP Data Collector API) OR install an Azure Monitor Agent on the Gateway host and
   tail the NDJSON file.

### 3.3 Field-mapping table

Log Analytics type-suffix convention (`_s` string, `_d` double, `_b` bool, `_t` datetime,
`dynamic` for nested objects):

| SIEM field | Sentinel column | Notes |
|---|---|---|
| `timestamp` | `TimeGenerated` | Set via DCR transformKql: `source | extend TimeGenerated = todatetime(timestamp)` |
| `event_id` | `event_id_s` | Dedup key |
| `principal` | `principal_s` (dynamic) | Query via `principal_s.kind`, `principal_s.subject`, etc. |
| `machine_identity` | `machine_identity_s` (dynamic) | Query via `machine_identity_s.spiffe_id` |
| `policy_decision` | `policy_decision_s` | `ALLOW` / `DENY` / `NOT_APPLICABLE` |
| `commit_retry_exhausted` | `commit_retry_exhausted_b` | Bool |
| `recurse_deployment_shape` | `recurse_deployment_shape_s` | Shape segmentation |

### 3.4 Sample analytic rule — commit-retry exhaustion (SC-015)

KQL rule (Sentinel → Analytics → Scheduled query rule):

```kql
Recurse_SIEM_CL
| where TimeGenerated > ago(15m)
| where commit_retry_exhausted_b == true
| project
    TimeGenerated,
    tenant_id_s,
    session_id_s,
    session_state_s,
    verification_level_s,
    signer_s
| summarize
    exhausted_sessions = dcount(session_id_s),
    earliest = min(TimeGenerated),
    latest = max(TimeGenerated)
  by tenant_id_s
```

Rule settings:
- **Severity**: High
- **Query frequency**: every 5 minutes
- **Query period**: last 15 minutes
- **Alert threshold**: `exhausted_sessions >= 1`
- **Entity mapping**: `tenant_id_s` → `CustomEntity` (for SOAR playbooks)
- **Incident creation**: enabled; group alerts by `tenant_id_s` within 1 hour

---

## 4. Cross-SIEM operational notes

- **Clock skew**: every event carries two timestamps — `timestamp` (authoritative event time
  per FR-031) and `emitted_at` (forwarder-local). Alert-window math SHOULD use `timestamp`.
  `emitted_at` is useful only for debugging forwarder lag.
- **Multi-tenant segmentation**: always partition dashboards/alerts by `tenant_id`. Cross-tenant
  rollups are almost always a mistake and can leak one customer's volume patterns to another.
- **Dedup**: all three SIEMs can dedup on `event_id`. At-least-once transport means retries will
  produce duplicates; dedup at ingest where possible, or at search time as a fallback.
- **Escaping**: the forwarder does NOT escape dotted attribute names (Datadog's `@principal.kind`
  vs. Splunk's `principal.kind` vs. Sentinel's `principal_s.kind`) — alert authors adjust per
  SIEM. Schema stays consistent across all three.
- **Version bumps**: when `recurse_envelope_version` increments (additive: no action; breaking:
  one deprecation window), re-run the field-mapping tables against the updated
  `siem_log_forwarder.md` and adjust pipelines accordingly. Splunk/Datadog/Sentinel all tolerate
  extra unknown fields without config changes.
