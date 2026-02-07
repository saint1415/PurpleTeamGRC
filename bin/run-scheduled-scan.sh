#!/usr/bin/env bash
#
# Purple Team Portable - Scheduled Scan Runner
# Called by cron to execute scheduled assessments
# Fully portable - auto-detects installation location
#

# Auto-detect installation directory from script location
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

# Set PURPLE_TEAM_HOME to parent of bin/
export PURPLE_TEAM_HOME="$(dirname "$SCRIPT_DIR")"
export PYTHONPATH="$PURPLE_TEAM_HOME/lib:$PYTHONPATH"

ASSESSMENT_TYPE="${1:-standard}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "========================================"
echo "Purple Team Scheduled Scan"
echo "Started: $(date)"
echo "Type: $ASSESSMENT_TYPE"
echo "Location: $PURPLE_TEAM_HOME"
echo "========================================"

# Check if virtual environment exists
if [ -f "$PURPLE_TEAM_HOME/venv/bin/python3" ]; then
    PYTHON="$PURPLE_TEAM_HOME/venv/bin/python3"
else
    PYTHON="python3"
fi

# Run assessment
$PYTHON -c "
import sys
sys.path.insert(0, '$PURPLE_TEAM_HOME/lib')
sys.path.insert(0, '$PURPLE_TEAM_HOME/utilities')

from orchestrator import AssessmentOrchestrator

orchestrator = AssessmentOrchestrator()
results = orchestrator.run_full_assessment(assessment_type='$ASSESSMENT_TYPE')

print(f'\nAssessment complete!')
print(f'Session: {results.get(\"session_id\")}')
print(f'Total findings: {results.get(\"summary\", {}).get(\"total_findings\", 0)}')
"

# Generate reports
$PYTHON -c "
import sys
sys.path.insert(0, '$PURPLE_TEAM_HOME/lib')
sys.path.insert(0, '$PURPLE_TEAM_HOME/utilities')

from reporter import ReportGenerator
from config import config

reporter = ReportGenerator()
for fw in config.get_frameworks():
    try:
        reporter.generate_compliance_report(fw)
    except Exception as e:
        print(f'Report generation error for {fw}: {e}')
"

echo "========================================"
echo "Completed: $(date)"
echo "========================================"
