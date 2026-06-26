import json
import requests
from pathlib import Path

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:3b"


def make_soc_decision(intelligence_package):
    prompt = f"""
You are a senior SOC incident commander.

Your job is NOT only to summarize.
Your job is to make a clear SOC decision based on evidence.

Review this intelligence package:

{json.dumps(intelligence_package, indent=2)}

Important rules:
- Choose ONLY ONE final decision.
- Never use "/" in the final decision.
- Do not write multiple options.
- Do not invent exploitation details.
- If the raw request does not directly match the CVE, clearly say that.
- Separate direct incident evidence from enrichment evidence.
- Be conservative and accurate.

Return your answer in this exact structure:

1. Final Decision:
- Write exactly ONE of these three values:
  Escalate Immediately
  Investigate Soon
  Monitor Only

2. Confidence:
- Give a percentage from 0 to 100

3. Why This Decision:
- Explain the main reason in simple SOC language

4. Strongest Evidence:
- List the top 3 evidence points

5. Conflicting or Missing Evidence:
- Mention anything missing or uncertain

6. Next 15-Minute Actions:
- Give 5 practical actions the SOC team should take immediately

7. Business Impact:
- Explain possible impact if ignored
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
        },
        timeout=180,
    )

    response.raise_for_status()
    return response.json()["response"]


if __name__ == "__main__":
    from intelligence.intelligence_manager import build_intelligence_package

    test_incident = {
        "user": "guest",
        "source_ip": "103.22.55.9",
        "request": "/login?username=admin' OR '1'='1",
    }

    package = build_intelligence_package(test_incident)
    decision = make_soc_decision(package)

    output_file = Path("reports/soc_decision.json")
    output_file.parent.mkdir(exist_ok=True)

    report = {
        "intelligence_package": package,
        "soc_decision": decision,
    }

    output_file.write_text(json.dumps(report, indent=2))

    print("\n=== SMART AI SOC DECISION ===\n")
    print(decision)
    print(f"\nReport saved to: {output_file}")