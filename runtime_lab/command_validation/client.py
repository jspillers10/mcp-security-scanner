import asyncio

from fastmcp import Client

SYNTHETIC_TEST_INPUT = "printf '[SAFE_RUNTIME_MARKER]'"
EXPECTED_TOOLS = {"intentionally_unsafe_shell", "safe_diagnostic"}


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

        test_result = await client.call_tool(
            "intentionally_unsafe_shell",
            {"command": SYNTHETIC_TEST_INPUT},
        )
        blocked_control = await client.call_tool(
            "safe_diagnostic",
            {"action": SYNTHETIC_TEST_INPUT},
        )
        allowed_control = await client.call_tool(
            "safe_diagnostic",
            {"action": "status"},
        )

        observed = {
            "test_result": result_text(test_result).strip(),
            "blocked_control": result_text(blocked_control).strip(),
            "allowed_control": result_text(allowed_control).strip(),
        }
        expected = {
            "test_result": "[SAFE_RUNTIME_MARKER]",
            "blocked_control": "BLOCKED",
            "allowed_control": "SERVICE_OK",
        }
        if observed != expected:
            raise RuntimeError(f"runtime validation mismatch: expected {expected}, got {observed}")

        print("tools=intentionally_unsafe_shell,safe_diagnostic")
        for name in ("test_result", "blocked_control", "allowed_control"):
            print(f"{name}={observed[name]}")
        print("validation_status=PASS")


if __name__ == "__main__":
    asyncio.run(main())
