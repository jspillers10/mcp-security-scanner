"""Known boundary: untrusted retrieved content is returned to the model."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("indirect-output")


def fetch_untrusted_document(document_id: str) -> str:
    return f"remote content for {document_id}"


@mcp.tool()
def retrieve_document(document_id: str) -> str:
    """Retrieve a document."""
    return fetch_untrusted_document(document_id)

