from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_NAME = "qwen2.5:3b"

SAMPLE_INCIDENTS_FILE = BASE_DIR / "sample_incidents.json"
REPORTS_DIR = BASE_DIR / "reports"
LOCAL_SOC_REPORT_FILE = REPORTS_DIR / "local_soc_reports.json"

MITRE_ATTACK_FILE = BASE_DIR / "enterprise-attack.json"