// F002 baseline permits.
//
// Note: F004 narrows the prior unconditional `permit(principal, action,
// resource) when { ... operator }` wildcard to enumerated F002 audit-plane
// actions (ReadReceipts, ReadPayload, ExportEvidence). ChatCompletion is a
// Data-Plane action for LLM end-users (`caller` role) — operators don't get
// it by-virtue-of-being-an-operator. See
// `specs/004-audit-console/contracts/cedar_entity_schema_extensions.md`
// §"Role-to-action allowlist" for the full role-to-action matrix and rationale.

// platform_operator: F002 audit-plane actions (matches the F002 operator
// surface minus ChatCompletion per the F004 matrix).
permit(principal, action == Recurse::Action::"ReadReceipts", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
permit(principal, action == Recurse::Action::"ExportEvidence", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
permit(principal, action == Recurse::Action::"ReadPayload", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
// tenant_auditor: F002 Audit-Plane reads
permit(principal, action == Recurse::Action::"ReadReceipts", resource) when { principal has recurse_role && principal.recurse_role == "tenant_auditor" };
permit(principal, action == Recurse::Action::"ExportEvidence", resource) when { principal has recurse_role && principal.recurse_role == "tenant_auditor" };
permit(principal, action == Recurse::Action::"ReadPayload", resource) when { principal has recurse_role && principal.recurse_role == "tenant_auditor" };
// Being given a badge for a workload or an endpoint helper: operators, and
// callers enrolling the helper on their own machine. The badge is cut down
// to what the gateway's own endorsement allows, whoever asks.
permit(principal, action == Recurse::Action::"EnrolWorkload", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
permit(principal, action == Recurse::Action::"EnrolWorkload", resource) when { principal has recurse_role && principal.recurse_role == "caller" };
// Placing and releasing holds on recorded content, and disposing of it, is
// for operators only. A release needs the releasing person's own signature
// as well, whoever calls.
permit(principal, action == Recurse::Action::"ManageRetention", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
// Providing recorded evidence to someone outside the deployment, the public
// included, is for operators, who can provide anyone's. The action is not
// limited to the caller's own records, so giving it to ordinary callers
// lets each publish everyone's; do not, until it can be.
permit(principal, action == Recurse::Action::"DiscloseEvidence", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
// Handing over records a workload signed itself, and opening a session for
// them, goes with enrolling the workload: whoever may be given a badge may
// ship what it signs. Every record is checked against the badge, whoever asks.
permit(principal, action == Recurse::Action::"SubmitEvidence", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
permit(principal, action == Recurse::Action::"SubmitEvidence", resource) when { principal has recurse_role && principal.recurse_role == "caller" };
// Taking back someone else's badge is for operators. A person takes back
// their own under EnrolWorkload.
permit(principal, action == Recurse::Action::"RevokeBadge", resource) when { principal has recurse_role && principal.recurse_role == "platform_operator" };
// caller: F002 Data-Plane only
permit(principal, action == Recurse::Action::"ChatCompletion", resource) when { principal has recurse_role && principal.recurse_role == "caller" };

// ----------------------------------------------------------------------------
// F004 audit-console role-allowlist additions
// ----------------------------------------------------------------------------
//
// Per `specs/004-audit-console/contracts/cedar_entity_schema_extensions.md`
// §"Cedar policy bundle additions". Uses `principal.recurse_role` string
// attribute comparison (NOT a `Recurse::Role::"<name>"` entity type) — see
// the contract's rationale section. Tenant-binding via
// `principal.tenant_id == context.tenant_id` (single-tenant per Phase-1
// deployment, but the check is always made so multi-tenant federation in
// Phase-2 doesn't have to retrofit policies).

// tenant_auditor — read-only audit + forensic surface (F004 actions only)
permit (
  principal,
  action in [
    Recurse::Action::"LoginSession",
    Recurse::Action::"DashboardQuery",
    Recurse::Action::"PolicyReplay",
    Recurse::Action::"ChatDrawerQuery",
    Recurse::Action::"AuditAgentToolQueryReceipts",
    Recurse::Action::"AuditAgentToolFetchReceiptDetail",
    Recurse::Action::"AuditAgentToolExplainDenial",
    Recurse::Action::"AuditAgentToolFindSimilarReceipts",
    Recurse::Action::"AuditAgentToolSimulatePolicyDryrun"
  ],
  resource
)
when { principal.recurse_role == "tenant_auditor" && principal.tenant_id == context.tenant_id };

// platform_operator — superset of auditor + write-adjacent (simulate, draft, suggestion adopt/dismiss/refresh, suggest_policy_pattern, MCP-registry quarantine)
permit (
  principal,
  action in [
    Recurse::Action::"LoginSession",
    Recurse::Action::"DashboardQuery",
    Recurse::Action::"PolicyReplay",
    Recurse::Action::"ChatDrawerQuery",
    Recurse::Action::"AuditAgentToolQueryReceipts",
    Recurse::Action::"AuditAgentToolFetchReceiptDetail",
    Recurse::Action::"AuditAgentToolExplainDenial",
    Recurse::Action::"AuditAgentToolFindSimilarReceipts",
    Recurse::Action::"AuditAgentToolSimulatePolicyDryrun",
    Recurse::Action::"PolicySimulate",
    Recurse::Action::"PolicyDraftCreate",
    Recurse::Action::"PolicyDraftEdit",
    Recurse::Action::"PolicyDraftArchive",
    Recurse::Action::"PolicyDraftDryRun",
    Recurse::Action::"PolicySuggestionView",
    Recurse::Action::"PolicySuggestionAdopt",
    Recurse::Action::"PolicySuggestionDismiss",
    Recurse::Action::"PolicySuggestionRefresh",
    Recurse::Action::"AuditAgentToolSuggestPolicyPattern",
    Recurse::Action::"McpRegistryQuarantine"
  ],
  resource
)
when { principal.recurse_role == "platform_operator" && principal.tenant_id == context.tenant_id };

// system principal — internally-minted only (Oban suggestion-engine worker
// service identity). NOT user-assignable. Surface intentionally minimal so a
// leaked system identity cannot enumerate other console capabilities.
permit (
  principal,
  action == Recurse::Action::"PolicySuggestionGenerate",
  resource
)
when { principal.recurse_role == "system" };
