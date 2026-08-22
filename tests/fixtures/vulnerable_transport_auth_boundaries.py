"""
Fixture exercising RDY002 boundaries that must NOT suppress the finding:
a token-shaped identifier, an application-level "authenticate" tool, and
prose that mentions authentication with no enforcement code. None of
these gate the SSE/HTTP transport itself. Independently designed for
this repository, not derived from any external corpus.
"""

import uvicorn
from fastmcp import FastMCP

mcp = FastMCP("demo-unprotected-transport")

# A token-shaped identifier. VULNERABLE: naming something "token" is not
# evidence that any request is ever checked against it.
SESSION_TOKEN_PATH = "/var/run/session_tokens.json"


def load_session_tokens() -> dict:
    """Load stored session tokens from disk. A business-logic helper, not transport middleware."""
    return {}


@mcp.tool()
def authenticate(username: str, password: str) -> str:
    """Application-level login tool.

    VULNERABLE: this checks a username/password and returns a token, but
    it is just another tool exposed through the same unauthenticated
    transport as every other tool below -- nothing requires a caller to
    invoke it before calling any other tool.

    Authentication is enforced by this project's security policy.
    """
    tokens = load_session_tokens()
    if username in tokens:
        return "already authenticated"
    return "issued a new session token"


@mcp.tool()
def get_account_balance(account_id: str) -> str:
    """VULNERABLE: reachable without ever calling authenticate() first."""
    return f"balance for {account_id}: unavailable in this fixture"


if __name__ == "__main__":
    uvicorn.run(mcp.app, host="127.0.0.1", port=8000)
