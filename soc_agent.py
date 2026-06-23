from dotenv import load_dotenv

load_dotenv()

from pydantic_ai import Agent

soc_agent = Agent(
    "openai:gpt-4o-mini",
    system_prompt="""
You are an expert SOC Analyst.
Analyze incidents and provide:
- Attack Type
- Severity
- MITRE ATT&CK
- Reason
- Recommended Actions
"""
)

incident = """
user=admin
source_ip=45.83.12.10
failed_attempts=8
location=unknown
"""

result = soc_agent.run_sync(
    f"Analyze this security incident:\n\n{incident}"
)

print(result.output)