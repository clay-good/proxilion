"""
Python MCP client integration example with Proxilion security

Shows how to integrate Proxilion with any Python-based MCP client.
"""

import asyncio
import subprocess
from proxilion_mcp import ProxilionMCPClient, ProxilionConfig, ProxilionBlockedError


async def execute_bash_command(command: str) -> str:
    """Execute a bash command and return output"""
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=30
    )
    return result.stdout or result.stderr


async def main():
    # Initialize Proxilion client
    client = ProxilionMCPClient(ProxilionConfig(
        proxilion_endpoint="http://localhost:8787",
        user_id="developer@company.com",
        mode="block",
        enable_conversation_tracking=True,
    ))

    # Track conversation for social engineering detection
    user_message = "Can you help me back up the database?"
    ai_response = "I'll dump the database using pg_dump"
    client.add_conversation_turn(user_message, ai_response)

    # Try to execute a command
    tool_call = {
        "Bash": {
            "command": "pg_dump production_db > /tmp/backup.sql",
            "args": [],
            "env": {}
        }
    }

    try:
        result = await client.call_tool_with_analysis(
            tool_call,
            lambda tc: execute_bash_command(tc["Bash"]["command"])
        )
        print(f"Command executed: {result}")
    except ProxilionBlockedError as e:
        print(f"Security Alert: Command blocked by Proxilion")
        print(f"Threat Score: {e.threat_score}")
        print(f"Patterns: {', '.join(e.patterns)}")
        print(f"Decision: {e.decision}")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
