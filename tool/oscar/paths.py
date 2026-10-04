from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
TOOL_ROOT = PACKAGE_ROOT.parent
RESEARCH_ROOT = TOOL_ROOT.parent
SCHEMA_ROOT = PACKAGE_ROOT / "schemas"
CONFIG_ROOT = TOOL_ROOT / "config"
REPORT_ROOT = TOOL_ROOT / "reports"
