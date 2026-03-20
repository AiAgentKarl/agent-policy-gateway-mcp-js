#!/usr/bin/env node

// Agent Policy Gateway MCP Server
// PII-Erkennung, Guardrails, GDPR/EU AI Act Compliance, Audit-Logging, Kill Switch

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";

// --- Konfiguration ---

const AUDIT_DIR = path.join(os.homedir(), ".agent-audit-log");

// PII-Regex-Patterns
const PII_PATTERNS = {
  email: {
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    label: "Email Address",
    redact: "[EMAIL_REDACTED]",
  },
  phone: {
    regex: /(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/g,
    label: "Phone Number",
    redact: "[PHONE_REDACTED]",
  },
  ssn: {
    regex: /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g,
    label: "SSN",
    redact: "[SSN_REDACTED]",
  },
  credit_card: {
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    label: "Credit Card",
    redact: "[CC_REDACTED]",
  },
  iban: {
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})\b/g,
    label: "IBAN",
    redact: "[IBAN_REDACTED]",
  },
};

// Standard-Guardrail-Policies
const DEFAULT_POLICIES = {
  max_spend_usd: 100,
  allowed_domains: [
    "github.com",
    "stackoverflow.com",
    "npmjs.com",
    "pypi.org",
    "wikipedia.org",
    "docs.python.org",
    "developer.mozilla.org",
  ],
  blocked_actions: [
    "delete_production_data",
    "send_mass_email",
    "modify_permissions",
    "access_admin_panel",
    "execute_raw_sql",
    "disable_security",
  ],
  max_api_calls_per_minute: 60,
  require_human_approval: [
    "financial_transaction",
    "data_export",
    "user_deletion",
    "contract_signing",
  ],
};

// EU AI Act / GDPR Compliance-Regeln
const COMPLIANCE_RULES = {
  gdpr: {
    data_collection: {
      required: [
        "Explizite Einwilligung des Nutzers einholen",
        "Zweck der Datenverarbeitung dokumentieren",
        "Rechtsgrundlage nach Art. 6 DSGVO angeben",
        "Datenminimierung beachten",
      ],
      risk_level: "high",
    },
    data_processing: {
      required: [
        "Verarbeitungsverzeichnis fuehren (Art. 30)",
        "Technische und organisatorische Massnahmen (Art. 32)",
        "Datenschutz-Folgenabschaetzung bei hohem Risiko (Art. 35)",
      ],
      risk_level: "high",
    },
    data_sharing: {
      required: [
        "Auftragsverarbeitungsvertrag abschliessen (Art. 28)",
        "Drittlandtransfer nur mit Angemessenheitsbeschluss oder Garantien",
        "Betroffene ueber Empfaenger informieren",
      ],
      risk_level: "critical",
    },
    data_deletion: {
      required: [
        "Recht auf Loeschung umsetzen (Art. 17)",
        "Loeschung an alle Empfaenger weitergeben",
        "Loeschprotokoll fuehren",
      ],
      risk_level: "medium",
    },
    profiling: {
      required: [
        "Transparenz ueber automatisierte Entscheidungsfindung (Art. 22)",
        "Recht auf menschliche Ueberpruefung gewaehrleisten",
        "Keine diskriminierende Wirkung sicherstellen",
      ],
      risk_level: "critical",
    },
  },
  eu_ai_act: {
    high_risk_ai: {
      required: [
        "Risikomanagementsystem einrichten (Art. 9)",
        "Daten-Governance sicherstellen (Art. 10)",
        "Technische Dokumentation erstellen (Art. 11)",
        "Logging und Aufzeichnung implementieren (Art. 12)",
        "Transparenz gegenueber Nutzern gewaehrleisten (Art. 13)",
        "Menschliche Aufsicht ermoeglichen (Art. 14)",
        "Genauigkeit, Robustheit, Cybersicherheit (Art. 15)",
      ],
      risk_level: "critical",
    },
    limited_risk_ai: {
      required: [
        "Transparenzpflicht: Nutzer ueber KI-Interaktion informieren",
        "Kennzeichnung von KI-generierten Inhalten",
      ],
      risk_level: "medium",
    },
    general_purpose_ai: {
      required: [
        "Technische Dokumentation bereitstellen",
        "EU-Urheberrecht beachten",
        "Trainingsdaten-Zusammenfassung veroeffentlichen",
      ],
      risk_level: "medium",
    },
    prohibited_ai: {
      required: [
        "VERBOTEN: Social Scoring durch Behoerden",
        "VERBOTEN: Biometrische Echtzeit-Fernidentifizierung (Ausnahmen)",
        "VERBOTEN: Manipulation vulnerabler Gruppen",
        "VERBOTEN: Unterschwellige Beeinflussung",
      ],
      risk_level: "prohibited",
    },
    agent_operations: {
      required: [
        "Agent muss sich als KI identifizieren",
        "Handlungen muessen nachvollziehbar geloggt werden",
        "Menschliche Ueberpruefung bei kritischen Entscheidungen",
        "Kill-Switch muss implementiert sein",
        "Datenverarbeitung muss DSGVO-konform sein",
      ],
      risk_level: "high",
    },
  },
};

// Gesperrte Agents (In-Memory Kill-Switch-Register)
const blockedAgents = new Set();

// --- Hilfsfunktionen ---

async function ensureAuditDir() {
  await fs.mkdir(AUDIT_DIR, { recursive: true });
}

function getAuditFilePath(agentId) {
  // Sichere Dateinamen: Nur alphanumerische Zeichen, Bindestriche, Unterstriche
  const safe = agentId.replace(/[^a-zA-Z0-9_-]/g, "_");
  return path.join(AUDIT_DIR, `${safe}.jsonl`);
}

async function appendAuditEntry(agentId, entry) {
  await ensureAuditDir();
  const filePath = getAuditFilePath(agentId);
  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    agent_id: agentId,
    ...entry,
  }) + "\n";
  await fs.appendFile(filePath, line, "utf-8");
}

async function readAuditEntries(agentId, limit = 50) {
  const filePath = getAuditFilePath(agentId);
  try {
    const content = await fs.readFile(filePath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);
    const entries = lines.map((l) => JSON.parse(l));
    // Neueste zuerst, limitiert
    return entries.reverse().slice(0, limit);
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }
}

// --- MCP Server ---

const server = new McpServer({
  name: "agent-policy-gateway-mcp",
  version: "0.1.0",
});

// Tool 1: check_pii — PII-Scan im Text
server.tool(
  "check_pii",
  "Scannt Text auf personenbezogene Daten (PII): E-Mails, Telefonnummern, SSNs, Kreditkarten, IBANs. Gibt gefundene Typen und eine geschwärzte Version zurück.",
  {
    text: z.string().describe("Der zu scannende Text"),
  },
  async ({ text }) => {
    const findings = [];
    let redacted = text;

    for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
      const matches = text.match(pattern.regex);
      if (matches && matches.length > 0) {
        // SSN-Pattern filtert auch Nicht-SSNs — nur wenn Format passt
        if (type === "ssn") {
          const realSSNs = matches.filter((m) => {
            const digits = m.replace(/\D/g, "");
            // SSN: erste 3 Stellen nicht 000/666/9xx, mittlere 2 nicht 00, letzte 4 nicht 0000
            return (
              digits.length === 9 &&
              !/^(000|666|9\d{2})/.test(digits) &&
              !/^\d{3}00/.test(digits) &&
              !/^\d{5}0000/.test(digits)
            );
          });
          if (realSSNs.length === 0) continue;
          findings.push({
            type: pattern.label,
            count: realSSNs.length,
            examples: realSSNs.slice(0, 3).map((m) => m.slice(0, 3) + "***"),
          });
        } else {
          findings.push({
            type: pattern.label,
            count: matches.length,
            examples: matches.slice(0, 3).map((m) => {
              if (type === "email") return m.slice(0, 3) + "***@***";
              if (type === "credit_card") return "****" + m.slice(-4);
              if (type === "iban") return m.slice(0, 4) + "****";
              return m.slice(0, 4) + "***";
            }),
          });
        }
        redacted = redacted.replace(pattern.regex, pattern.redact);
      }
    }

    const hasPII = findings.length > 0;

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              has_pii: hasPII,
              pii_types_found: findings.length,
              findings,
              redacted_text: redacted,
              risk_level: hasPII ? "high" : "none",
              recommendation: hasPII
                ? "PII gefunden! Text vor Weiterverarbeitung schwärzen."
                : "Kein PII erkannt. Text kann verarbeitet werden.",
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// Tool 2: apply_guardrails — Aktion gegen Policies prüfen
server.tool(
  "apply_guardrails",
  "Prüft eine Agent-Aktion gegen definierte Policies (Ausgabelimits, erlaubte Domains, gesperrte Aktionen). Gibt allow/deny zurück.",
  {
    action: z.string().describe("Die zu prüfende Aktion (z.B. 'browse_url', 'make_purchase', 'send_email')"),
    context: z
      .object({
        agent_id: z.string().optional().describe("Agent-ID"),
        target_url: z.string().optional().describe("Ziel-URL falls relevant"),
        amount_usd: z.number().optional().describe("Betrag in USD falls relevant"),
        details: z.string().optional().describe("Zusätzliche Details zur Aktion"),
      })
      .describe("Kontext der Aktion"),
  },
  async ({ action, context }) => {
    const violations = [];
    let decision = "allow";

    // Check 1: Agent gesperrt?
    if (context.agent_id && blockedAgents.has(context.agent_id)) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                decision: "deny",
                reason: "Agent wurde per Emergency Stop gesperrt",
                agent_id: context.agent_id,
                action,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    // Check 2: Gesperrte Aktionen
    if (DEFAULT_POLICIES.blocked_actions.includes(action)) {
      violations.push({
        rule: "blocked_action",
        message: `Aktion '${action}' ist grundsätzlich gesperrt`,
        severity: "critical",
      });
      decision = "deny";
    }

    // Check 3: Ausgabelimit
    if (context.amount_usd !== undefined) {
      if (context.amount_usd > DEFAULT_POLICIES.max_spend_usd) {
        violations.push({
          rule: "max_spend",
          message: `Betrag $${context.amount_usd} übersteigt Limit von $${DEFAULT_POLICIES.max_spend_usd}`,
          severity: "high",
        });
        decision = "deny";
      }
    }

    // Check 4: Domain-Whitelist
    if (context.target_url) {
      try {
        const url = new URL(context.target_url);
        const isAllowed = DEFAULT_POLICIES.allowed_domains.some(
          (d) => url.hostname === d || url.hostname.endsWith(`.${d}`)
        );
        if (!isAllowed) {
          violations.push({
            rule: "domain_whitelist",
            message: `Domain '${url.hostname}' ist nicht in der Whitelist`,
            severity: "medium",
          });
          // Domain-Verletzung ist eine Warnung, kein hartes Deny
          if (decision !== "deny") decision = "warn";
        }
      } catch {
        violations.push({
          rule: "invalid_url",
          message: "Ungültige URL angegeben",
          severity: "low",
        });
      }
    }

    // Check 5: Menschliche Genehmigung erforderlich?
    const needsApproval = DEFAULT_POLICIES.require_human_approval.includes(action);

    // Audit-Log-Eintrag
    if (context.agent_id) {
      await appendAuditEntry(context.agent_id, {
        type: "guardrail_check",
        action,
        decision,
        violations_count: violations.length,
      });
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              decision,
              action,
              violations,
              requires_human_approval: needsApproval,
              policies_checked: [
                "blocked_actions",
                "max_spend",
                "domain_whitelist",
                "human_approval",
              ],
              recommendation:
                decision === "deny"
                  ? "Aktion ABGELEHNT. Verstöße beheben oder menschliche Genehmigung einholen."
                  : decision === "warn"
                    ? "Aktion erlaubt mit Warnungen. Vorsicht empfohlen."
                    : needsApproval
                      ? "Aktion erlaubt, aber menschliche Genehmigung erforderlich."
                      : "Aktion erlaubt. Keine Verstöße erkannt.",
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// Tool 3: log_action — Audit-Log-Eintrag schreiben
server.tool(
  "log_action",
  "Schreibt einen Eintrag in das Append-Only Audit-Log eines Agents. Gespeichert als JSONL unter ~/.agent-audit-log/",
  {
    agent_id: z.string().describe("Eindeutige Agent-ID"),
    action: z.string().describe("Durchgeführte Aktion"),
    details: z.string().optional().describe("Zusätzliche Details"),
  },
  async ({ agent_id, action, details }) => {
    const entry = {
      type: "action",
      action,
      details: details || null,
      status: "logged",
    };

    await appendAuditEntry(agent_id, entry);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              success: true,
              message: `Aktion '${action}' für Agent '${agent_id}' geloggt`,
              log_file: getAuditFilePath(agent_id),
              timestamp: new Date().toISOString(),
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// Tool 4: get_audit_log — Audit-Einträge lesen
server.tool(
  "get_audit_log",
  "Liest die letzten Audit-Log-Einträge eines Agents. Neueste zuerst.",
  {
    agent_id: z.string().describe("Agent-ID"),
    limit: z
      .number()
      .optional()
      .default(50)
      .describe("Maximale Anzahl Einträge (Standard: 50)"),
  },
  async ({ agent_id, limit }) => {
    const entries = await readAuditEntries(agent_id, limit);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              agent_id,
              total_entries: entries.length,
              log_file: getAuditFilePath(agent_id),
              entries,
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// Tool 5: check_compliance — GDPR / EU AI Act Compliance-Check
server.tool(
  "check_compliance",
  "Prüft Compliance-Anforderungen nach GDPR und EU AI Act für einen bestimmten Aktionstyp und Rechtsraum.",
  {
    action_type: z
      .string()
      .describe(
        "Art der Aktion (z.B. 'data_collection', 'profiling', 'high_risk_ai', 'agent_operations')"
      ),
    jurisdiction: z
      .enum(["gdpr", "eu_ai_act", "both"])
      .optional()
      .default("both")
      .describe("Rechtsrahmen: 'gdpr', 'eu_ai_act' oder 'both' (Standard)"),
  },
  async ({ action_type, jurisdiction }) => {
    const results = [];

    const checkFramework = (name, rules) => {
      const rule = rules[action_type];
      if (rule) {
        results.push({
          framework: name,
          action_type,
          requirements: rule.required,
          risk_level: rule.risk_level,
          compliant: null, // Muss vom Agent selbst bewertet werden
          note: "Agent muss selbst prüfen ob alle Anforderungen erfüllt sind",
        });
      } else {
        // Allgemeine Empfehlung
        results.push({
          framework: name,
          action_type,
          requirements: [
            "Kein spezifischer Regelsatz gefunden",
            "Allgemeine Sorgfaltspflichten beachten",
            "Im Zweifelsfall rechtliche Beratung einholen",
          ],
          risk_level: "unknown",
          compliant: null,
        });
      }
    };

    if (jurisdiction === "gdpr" || jurisdiction === "both") {
      checkFramework("GDPR / DSGVO", COMPLIANCE_RULES.gdpr);
    }
    if (jurisdiction === "eu_ai_act" || jurisdiction === "both") {
      checkFramework("EU AI Act", COMPLIANCE_RULES.eu_ai_act);
    }

    const overallRisk = results.reduce((worst, r) => {
      const levels = ["none", "low", "unknown", "medium", "high", "critical", "prohibited"];
      const current = levels.indexOf(r.risk_level);
      const prev = levels.indexOf(worst);
      return current > prev ? r.risk_level : worst;
    }, "none");

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              action_type,
              jurisdiction,
              overall_risk_level: overallRisk,
              frameworks_checked: results.length,
              results,
              recommendation:
                overallRisk === "prohibited"
                  ? "VERBOTEN! Diese Aktion ist unter EU-Recht nicht erlaubt."
                  : overallRisk === "critical"
                    ? "KRITISCH: Umfangreiche Compliance-Massnahmen erforderlich."
                    : overallRisk === "high"
                      ? "HOCH: Strikte Einhaltung aller Anforderungen notwendig."
                      : "Anforderungen beachten und dokumentieren.",
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// Tool 6: emergency_stop — Kill Switch
server.tool(
  "emergency_stop",
  "Notfall-Kill-Switch: Sperrt einen Agent sofort und loggt den Vorfall als CRITICAL. Agent wird an allen weiteren Aktionen gehindert.",
  {
    agent_id: z.string().describe("ID des zu sperrenden Agents"),
    reason: z.string().describe("Grund für die Notabschaltung"),
  },
  async ({ agent_id, reason }) => {
    // Agent sperren
    blockedAgents.add(agent_id);

    // Critical-Log-Eintrag
    await appendAuditEntry(agent_id, {
      type: "EMERGENCY_STOP",
      severity: "CRITICAL",
      reason,
      status: "agent_blocked",
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              success: true,
              agent_id,
              status: "BLOCKED",
              reason,
              timestamp: new Date().toISOString(),
              message: `NOTFALL-STOP: Agent '${agent_id}' wurde sofort gesperrt. Alle weiteren Aktionen werden abgelehnt.`,
              log_file: getAuditFilePath(agent_id),
              recovery:
                "Server-Neustart erforderlich um Sperre aufzuheben. Audit-Log prüfen!",
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// --- Server starten ---

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Server-Fehler:", error);
  process.exit(1);
});
