"""
Rule definitions for the MCP security scanner.

Each rule is mapped to a risk category from Google's Secure AI Framework (SAIF)
risk taxonomy (https://saif.google/secure-ai-framework/risks), so findings can be
communicated in terms security and product teams already recognize.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str  # "critical" | "high" | "medium" | "low"
    saif_category: str
    saif_code: str
    description: str
    remediation: str


RULES = {
    "MCP001": Rule(
        rule_id="MCP001",
        title="Command injection via tool parameter",
        severity="critical",
        saif_category="Insecure Integrated Component",
        saif_code="IIC",
        description=(
            "A tool function passes a parameter into a shell command "
            "(subprocess/os.system/os.popen) without sanitization. If the value "
            "reaches the model-facing tool call unsanitized, an attacker who can "
            "influence tool arguments (directly, or indirectly via retrieved "
            "content the model acts on) can execute arbitrary commands on the "
            "host running the MCP server."
        ),
        remediation=(
            "Never build shell strings from tool parameters. Use subprocess with "
            "a fixed argument list (shell=False) and an explicit allowlist of "
            "permitted values, or avoid shelling out entirely."
        ),
    ),
    "MCP002": Rule(
        rule_id="MCP002",
        title="Path traversal via tool parameter",
        severity="high",
        saif_category="Insecure Integrated Component",
        saif_code="IIC",
        description=(
            "A tool function opens or writes a file using a path built from an "
            "unsanitized parameter, allowing an attacker to read or write files "
            "outside the intended directory (e.g. via '../' sequences)."
        ),
        remediation=(
            "Resolve the requested path, then verify it is a descendant of an "
            "explicit allowed base directory before use. Reject any path that "
            "escapes that boundary."
        ),
    ),
    "MCP003": Rule(
        rule_id="MCP003",
        title="Dynamic code execution (eval/exec) reachable from a tool",
        severity="critical",
        saif_category="Insecure Integrated Component",
        saif_code="IIC",
        description=(
            "A tool function calls eval() or exec() on data that is or may be "
            "influenced by tool parameters or model output. This is arbitrary "
            "code execution by design."
        ),
        remediation=(
            "Remove eval/exec from the code path entirely. If dynamic evaluation "
            "is required, use a narrow, purpose-built parser instead of a "
            "general-purpose interpreter."
        ),
    ),
    "MCP004": Rule(
        rule_id="MCP004",
        title="Hardcoded credential or secret",
        severity="high",
        saif_category="Sensitive Data Disclosure",
        saif_code="SDD",
        description=(
            "A credential, API key, or connection string appears to be "
            "hardcoded in source. If the server's source becomes readable "
            "through any means (misconfigured resource, debug endpoint, error "
            "message, or source disclosure via another vulnerability), these "
            "credentials are exposed directly."
        ),
        remediation=(
            "Move all credentials to environment variables or a secrets "
            "manager. Rotate any credential that has ever been committed to "
            "source control."
        ),
    ),
    "MCP005": Rule(
        rule_id="MCP005",
        title="Sensitive resource exposed without apparent access control",
        severity="high",
        saif_category="Sensitive Data Disclosure",
        saif_code="SDD",
        description=(
            "An MCP resource whose name suggests it exposes internal state "
            "(debug output, logs, admin data, internal config) is registered "
            "with no visible authorization check in its implementation. "
            "Debug/log resources are a common side channel for exfiltrating "
            "data from an otherwise blind vulnerability."
        ),
        remediation=(
            "Remove debug/diagnostic resources from production MCP servers, or "
            "gate them behind an explicit authorization check tied to the "
            "caller's identity and role."
        ),
    ),
    "MCP006": Rule(
        rule_id="MCP006",
        title="Excessive tool functionality (multiple sensitive capabilities in one tool)",
        severity="medium",
        saif_category="Rogue Actions",
        saif_code="RA",
        description=(
            "A single tool function combines multiple sensitive capabilities "
            "(e.g. filesystem access, network calls, and process execution). "
            "This increases the blast radius if the tool is invoked with "
            "unexpected arguments, whether due to a bug, a confused model, or "
            "a successful prompt injection upstream."
        ),
        remediation=(
            "Split broad tools into narrower, single-purpose tools. Grant each "
            "tool the minimum capability it needs, and require explicit "
            "confirmation for actions with real-world side effects."
        ),
    ),
    "MCP007": Rule(
        rule_id="MCP007",
        title="Deserialization of untrusted data",
        severity="high",
        saif_category="Insecure Integrated Component",
        saif_code="IIC",
        description=(
            "A tool function deserializes data (pickle, yaml.load without "
            "SafeLoader, marshal) that may originate from an untrusted source. "
            "Unpickling untrusted data is a well-known code execution vector."
        ),
        remediation=(
            "Use safe serialization formats (JSON) for anything crossing a "
            "trust boundary. If pickle/yaml is required, use yaml.safe_load "
            "and never unpickle data from an untrusted source."
        ),
    ),
}
