import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


server_params = StdioServerParameters(
    command="python",
    args=["mcp_server.py"]
)


async def main():
    incidents = [
        {
            "user": "admin",
            "source_ip": "45.83.12.10",
            "failed_attempts": 8
        },
        {
            "user": "guest",
            "source_ip": "103.22.55.9",
            "request": "/login?username=admin' OR '1'='1"
        },
        {
            "user": "guest",
            "source_ip": "88.12.44.7",
            "request": "/search?q=<script>alert(1)</script>"
        },
        {
            "user": "api_user",
            "source_ip": "91.77.10.5",
            "request_count": 250,
            "endpoint": "/api/login"
        },
        {
            "user": "john",
            "source_ip": "22.44.66.88",
            "event": "impossible travel detected",
            "session_anomaly": True
        }
    ]

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            for index, incident in enumerate(incidents, start=1):
                attack = await session.call_tool(
                    "soc_map_attack",
                    {"incident": incident}
                )

                severity = await session.call_tool(
                    "soc_calculate_severity",
                    {"incident": incident}
                )

                mitre = await session.call_tool(
                    "soc_map_mitre",
                    {"incident": incident}
                )

                actions = await session.call_tool(
                    "soc_recommend_actions",
                    {"incident": incident}
                )

                print("\n==============================")
                print(f"MCP SOC Report #{index}")
                print("==============================")
                print("User:", incident.get("user", "N/A"))
                print("Source IP:", incident.get("source_ip", "N/A"))
                print("Attack:", attack.content[0].text)
                print("Severity:", severity.content[0].text)
                print("MITRE:", mitre.content[0].text)

                print("Actions:")
                for item in actions.content:
                    print("-", item.text)


asyncio.run(main())