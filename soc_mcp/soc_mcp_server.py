from mcp.server.fastmcp import FastMCP
from soc_mcp.soc_tools_mcp import (
    search_mitre_tool,
    analyze_incident_tool,
    generate_summary_tool
)

mcp = FastMCP("AI SOC MCP Server")


@mcp.tool()
def search_mitre(query: str) -> dict:
    """Search MITRE ATT&CK techniques."""
    return search_mitre_tool(query)


@mcp.tool()
def analyze_incident(incident: dict) -> dict:
    """Analyze a security incident using local LLM and MITRE mapping."""
    return analyze_incident_tool(incident)


@mcp.tool()
def generate_summary(reports: list) -> dict:
    """Generate a summary from incident reports."""
    return generate_summary_tool(reports)


if __name__ == "__main__":
    mcp.run()