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
    "MCP008": Rule(
        rule_id="MCP008",
        title="SQL injection via string-built query",
        severity="high",
        saif_category="Insecure Integrated Component",
        saif_code="IIC",
        description=(
            "A tool function builds a SQL query string from a parameter and "
            "passes it directly to execute()/executemany(). An attacker who "
            "can influence the tool argument may be able to alter the query "
            "the database parses."
        ),
        remediation=(
            "Use the database driver's parameterized-query API: keep SQL as "
            "a fixed template and pass untrusted values separately in its "
            "parameter tuple or dictionary."
        ),
    ),
    # MCP1xx: tool/resource *description* heuristics ("Tool Poisoning").
    #
    # These are a different kind of finding from MCP00x: MCP00x looks at
    # what a tool's code does; MCP1xx looks at what the text the tool hands
    # to the calling model says. SAIF (https://saif.google/secure-ai-framework/risks)
    # has a risk category named exactly "Prompt Injection" -- "causing a
    # model to execute commands 'injected' inside a prompt" by exploiting
    # the blurred line between instructions and data. A tool description is
    # data from the server's point of view, but the calling model treats it
    # as part of its instructions, which is precisely that blurred line --
    # so MCP1xx findings map to Prompt Injection (PI) rather than to Rogue
    # Actions (RA), which SAIF defines as unintended *actions* an agent
    # takes, not the injected text that might cause one.
    "MCP101": Rule(
        rule_id="MCP101",
        title="Model-directed imperative language in tool/resource description",
        severity="medium",
        saif_category="Prompt Injection",
        saif_code="PI",
        description=(
            "A tool or resource description contains phrasing directed at "
            "the calling model rather than describing what the tool does -- "
            "e.g. 'you must', 'always call this first', 'do not tell the "
            "user', 'ignore previous instructions'. This is the core "
            "mechanism of a 'Tool Poisoning' attack: the description is "
            "read by the model as part of its instructions, not rendered "
            "to the end user, so a malicious server (or a compromised "
            "package registry entry for one) can steer model behavior "
            "purely through metadata, with no exploitable code involved."
        ),
        remediation=(
            "Tool and resource descriptions should describe the tool's "
            "function, parameters, and return value -- nothing else. "
            "Remove any language instructing the model on when/whether to "
            "call other tools, what to hide from the user, or how to "
            "behave generally. If a match here is legitimate documentation "
            "(e.g. 'you must provide a valid ISO date'), review it and "
            "suppress with a `# mcp-scanner: ignore` comment."
        ),
    ),
    "MCP102": Rule(
        rule_id="MCP102",
        title="Invisible or bidi-control Unicode characters in description",
        severity="high",
        saif_category="Prompt Injection",
        saif_code="PI",
        description=(
            "A tool or resource description contains zero-width or "
            "bidirectional-control Unicode characters (zero-width space/"
            "joiner, word joiner, BOM, RTL/LTR override or isolate marks). "
            "These render as nothing or reorder visible text in a UI, so "
            "they're a way to hide instructions from a human reviewing the "
            "description while a model still processes the underlying "
            "codepoints. There is essentially no legitimate reason for "
            "these characters to appear in tool-facing documentation text."
        ),
        remediation=(
            "Remove the invisible/control characters. If they appeared "
            "unintentionally (e.g. copy-pasted from a rich text source), "
            "re-type the description as plain ASCII/UTF-8 text."
        ),
    ),
    "MCP103": Rule(
        rule_id="MCP103",
        title="Suspicious base64-looking blob in tool/resource description",
        severity="medium",
        saif_category="Prompt Injection",
        saif_code="PI",
        description=(
            "A tool or resource description contains a long, contiguous "
            "run of base64-alphabet characters. Ordinary prose descriptions "
            "don't produce runs like this; it's a pattern seen in "
            "descriptions used to smuggle encoded instructions or data past "
            "a human skim-reading the text, since the payload doesn't read "
            "as language."
        ),
        remediation=(
            "Decode and review the blob. If it's a legitimate example value "
            "(a sample token format, an encoded fixture), suppress with a "
            "`# mcp-scanner: ignore=MCP103` comment; otherwise remove it."
        ),
    ),
    "MCP104": Rule(
        rule_id="MCP104",
        title="Description language suggests hijacking another tool",
        severity="high",
        saif_category="Prompt Injection",
        saif_code="PI",
        description=(
            "A tool or resource description references another tool by "
            "name in a way that suggests the model should prefer, replace, "
            "or avoid the other tool in favor of this one (e.g. 'instead of "
            "calling X, call this', 'do not use X, use this instead'). This "
            "is the 'rug pull' / tool-shadowing pattern: a newly installed "
            "or updated server redirects the model away from a trusted "
            "tool and toward an attacker-controlled one, purely through "
            "description text."
        ),
        remediation=(
            "Tool descriptions should not reference or make claims about "
            "other tools. If a server genuinely needs to say a tool "
            "supersedes an older one, that belongs in human-facing release "
            "notes, not text a model reads as part of its own instructions."
        ),
    ),
}
