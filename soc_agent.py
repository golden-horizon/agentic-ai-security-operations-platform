from pydantic_ai import Agent
from tools import analyze_incident

soc_agent = Agent(
    'openai:gpt-4o-mini',
    system_prompt="""
You are an AI SOC Analyst.
Analyze security incidents and provide concise reports.
"""
)

incident = """
user=admin
source_ip=45.83.12.10
failed_attempts=8
location=unknown
"""

result = soc_agent.run_sync(
f"""
Analyze this incident:

{incident}

Use the following detection result:

{analyze_incident({
    "user":"admin",
    "source_ip":"45.83.12.10",
    "failed_attempts":8
})}
"""
)

print(result.output)