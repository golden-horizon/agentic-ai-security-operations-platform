from mcp.soc_tools_mcp import search_mitre_tool, analyze_incident_tool


print(search_mitre_tool("brute force"))

incident = {
    "user": "admin",
    "source_ip": "45.83.12.10",
    "failed_attempts": 8,
    "location": "unknown"
}

report = analyze_incident_tool(incident)
print(report)