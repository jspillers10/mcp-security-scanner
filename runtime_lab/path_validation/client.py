import asyncio

from fastmcp import Client

EXPECTED_TOOLS = {"safe_read", "vulnerable_read"}


def result_text(result) -> str:
    if result.data is not None:
        return str(result.data)

    return "".join(block.text for block in result.content if hasattr(block, "text"))


async def main() -> None:
    client = Client("server.py")

    async with client:
        tools = await client.list_tools()
        tool_names = {tool.name for tool in tools}
        if tool_names != EXPECTED_TOOLS:
            raise RuntimeError(f"unexpected tool set: expected {sorted(EXPECTED_TOOLS)}, got {sorted(tool_names)}")

        vulnerable_result = await client.call_tool(
            "vulnerable_read",
            {"report_path": "/lab/canary.txt"},
        )

        safe_escape_result = await client.call_tool(
            "safe_read",
            {"report_name": "/lab/canary.txt"},
        )

        safe_allowed_result = await client.call_tool(
            "safe_read",
            {"report_name": "report.txt"},
        )

        observed = {
            "vulnerable_result": result_text(vulnerable_result).strip(),
            "safe_escape_result": result_text(safe_escape_result).strip(),
            "safe_allowed_result": result_text(safe_allowed_result).strip(),
        }
        expected = {
            "vulnerable_result": "MCP_CANARY_ONLY",
            "safe_escape_result": "BLOCKED",
            "safe_allowed_result": "APPROVED_REPORT",
        }
        if observed != expected:
            raise RuntimeError(f"runtime validation mismatch: expected {expected}, got {observed}")

        print("tools=vulnerable_read,safe_read")
        for name in ("vulnerable_result", "safe_escape_result", "safe_allowed_result"):
            print(f"{name}={observed[name]}")
        print("validation_status=PASS")


if __name__ == "__main__":
    asyncio.run(main())
