from mcp.server.fastmcp import FastMCP
from soc_tools import map_attack, map_mitre, calculate_severity, recommend_actions

mcp = FastMCP("AI SOC Tools MCP Server")


@mcp.tool()
def soc_map_attack(incident: dict) -> str:
    """Identify the attack type from a security incident."""
    return map_attack(incident)


@mcp.tool()
def soc_calculate_severity(incident: dict) -> str:
    """Calculate incident severity."""
    return calculate_severity(incident)


@mcp.tool()
def soc_map_mitre(incident: dict) -> str:
    """Map incident to MITRE ATT&CK technique."""
    return map_mitre(incident)


@mcp.tool()
def soc_recommend_actions(incident: dict) -> list[str]:
    """Recommend SOC remediation actions."""
    return recommend_actions(incident)


if __name__ == "__main__":
    mcp.run()