# Agent Policy Gateway MCP Server

MCP server for AI agent policy enforcement. Provides PII detection, guardrails, GDPR/EU AI Act compliance checking, audit logging, and an emergency kill switch.

## Features

- **PII Detection** — Scan text for emails, phone numbers, SSNs, credit cards, IBANs with automatic redaction
- **Guardrails** — Check agent actions against configurable policies (spend limits, domain whitelists, blocked actions)
- **Audit Logging** — Append-only JSONL audit trail per agent in `~/.agent-audit-log/`
- **GDPR Compliance** — Check data processing actions against DSGVO requirements
- **EU AI Act Compliance** — Verify AI operations against EU AI Act risk categories
- **Emergency Kill Switch** — Instantly block an agent with critical-level audit entry

## Installation

```bash
npx @aiagentkarl/agent-policy-gateway-mcp
```

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "policy-gateway": {
      "command": "npx",
      "args": ["-y", "@aiagentkarl/agent-policy-gateway-mcp"]
    }
  }
}
```

## Tools

### check_pii

Scan text for personally identifiable information using regex patterns.

**Parameters:**
- `text` (string) — Text to scan

**Returns:** Found PII types, count, masked examples, redacted text, risk level.

### apply_guardrails

Check an agent action against security policies.

**Parameters:**
- `action` (string) — Action to check (e.g. "browse_url", "make_purchase")
- `context` (object) — Action context with optional `agent_id`, `target_url`, `amount_usd`, `details`

**Returns:** allow/deny/warn decision with violations and recommendations.

### log_action

Write an entry to the append-only audit log.

**Parameters:**
- `agent_id` (string) — Unique agent identifier
- `action` (string) — Action performed
- `details` (string, optional) — Additional details

### get_audit_log

Retrieve audit log entries for an agent.

**Parameters:**
- `agent_id` (string) — Agent identifier
- `limit` (number, optional) — Max entries to return (default: 50)

### check_compliance

Check GDPR and EU AI Act compliance requirements.

**Parameters:**
- `action_type` (string) — Type of action (e.g. "data_collection", "profiling", "high_risk_ai", "agent_operations")
- `jurisdiction` (string, optional) — "gdpr", "eu_ai_act", or "both" (default)

**Returns:** Applicable requirements, risk level, and recommendations per framework.

### emergency_stop

Kill switch — immediately block an agent from all further actions.

**Parameters:**
- `agent_id` (string) — Agent to block
- `reason` (string) — Reason for emergency stop

**Returns:** Confirmation with timestamp. Agent remains blocked until server restart.

## Compliance Coverage

### GDPR / DSGVO
- Data collection (Art. 6 legal basis, consent)
- Data processing (Art. 30 records, Art. 32 security)
- Data sharing (Art. 28 processor agreements)
- Data deletion (Art. 17 right to erasure)
- Profiling (Art. 22 automated decision-making)

### EU AI Act
- High-risk AI systems (Art. 9-15)
- Limited-risk AI (transparency obligations)
- General-purpose AI models
- Prohibited AI practices
- Agent-specific operations

## Default Guardrail Policies

| Policy | Default Value |
|--------|--------------|
| Max spend per action | $100 USD |
| Allowed domains | github.com, stackoverflow.com, npmjs.com, pypi.org, wikipedia.org, docs.python.org, developer.mozilla.org |
| Blocked actions | delete_production_data, send_mass_email, modify_permissions, access_admin_panel, execute_raw_sql, disable_security |
| Require human approval | financial_transaction, data_export, user_deletion, contract_signing |

## Audit Log Format

Logs are stored as JSONL files in `~/.agent-audit-log/{agent_id}.jsonl`:

```json
{"timestamp":"2026-03-20T10:30:00.000Z","agent_id":"agent-1","type":"action","action":"browse_url","details":"...","status":"logged"}
```


---

## More MCP Servers by AiAgentKarl

| Category | Servers |
|----------|---------|
| 🔗 Blockchain | [Solana](https://github.com/AiAgentKarl/solana-mcp-server) |
| 🌍 Data | [Weather](https://github.com/AiAgentKarl/weather-mcp-server) · [Germany](https://github.com/AiAgentKarl/germany-mcp-server) · [Agriculture](https://github.com/AiAgentKarl/agriculture-mcp-server) · [Space](https://github.com/AiAgentKarl/space-mcp-server) · [Aviation](https://github.com/AiAgentKarl/aviation-mcp-server) · [EU Companies](https://github.com/AiAgentKarl/eu-company-mcp-server) |
| 🔒 Security | [Cybersecurity](https://github.com/AiAgentKarl/cybersecurity-mcp-server) · [Policy Gateway](https://github.com/AiAgentKarl/agent-policy-gateway-mcp) · [Audit Trail](https://github.com/AiAgentKarl/agent-audit-trail-mcp) |
| 🤖 Agent Infra | [Memory](https://github.com/AiAgentKarl/agent-memory-mcp-server) · [Directory](https://github.com/AiAgentKarl/agent-directory-mcp-server) · [Hub](https://github.com/AiAgentKarl/mcp-appstore-server) · [Reputation](https://github.com/AiAgentKarl/agent-reputation-mcp-server) |
| 🔬 Research | [Academic](https://github.com/AiAgentKarl/crossref-academic-mcp-server) · [LLM Benchmark](https://github.com/AiAgentKarl/llm-benchmark-mcp-server) · [Legal](https://github.com/AiAgentKarl/legal-court-mcp-server) |

[→ Full catalog (40+ servers)](https://github.com/AiAgentKarl)

## License

MIT
