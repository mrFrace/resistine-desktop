#!/usr/bin/env bash
# =============================================================================
# Resistine Desktop — Test Runner
# =============================================================================
# Usage:
#   ./run_tests.sh              # Run all tests
#   ./run_tests.sh unit         # Run only unit tests
#   ./run_tests.sh integration  # Run only integration tests
#   ./run_tests.sh security     # Run only security tests
#   ./run_tests.sh platform     # Run only platform tests
#   ./run_tests.sh coverage     # Run all tests with HTML coverage report
#   ./run_tests.sh fast         # Run unit + security (skip slow integration)
#   ./run_tests.sh ci           # CI-optimised: all tests, no interactive prompts
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Colour

# ── Project root ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Python / pytest detection ────────────────────────────────────────────────
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" &>/dev/null; then
    echo -e "${RED}Error: Python not found. Set PYTHON env var or install Python 3.${NC}"
    exit 1
fi

# Check pytest installed
if ! "$PYTHON" -m pytest --version &>/dev/null; then
    echo -e "${YELLOW}pytest not found — installing test dependencies...${NC}"
    "$PYTHON" -m pip install -r scripts/requirements/requirements-test.txt
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
run_pytest() {
    local label="$1"; shift
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  Running: ${label}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    "$PYTHON" -m pytest "$@"
}

# ── Mode selection ─────────────────────────────────────────────────────────────
MODE="${1:-all}"

case "$MODE" in

  unit)
    run_pytest "Unit Tests" \
      tests/unit/ \
      -m unit \
      --timeout=30
    ;;

  integration)
    run_pytest "Integration Tests" \
      tests/integration/ \
      -m integration \
      --timeout=60
    ;;

  security)
    run_pytest "Security Tests" \
      tests/security/ \
      -m security \
      --timeout=30
    ;;

  platform)
    run_pytest "Platform Tests" \
      tests/platform/ \
      --timeout=30
    ;;

  fast)
    run_pytest "Fast Tests (unit + security)" \
      tests/unit/ tests/security/ \
      --timeout=30
    ;;

  coverage)
    run_pytest "All Tests + Coverage Report" \
      tests/ \
      --cov=plugins \
      --cov=utils \
      --cov-report=html:coverage_html \
      --cov-report=term-missing \
      --cov-report=xml:coverage.xml \
      --timeout=120
    echo ""
    echo -e "${GREEN}Coverage report: ${PROJECT_ROOT}/coverage_html/index.html${NC}"
    ;;

  ci)
    run_pytest "CI Run (all tests, parallel)" \
      tests/ \
      -x \
      --timeout=120 \
      --tb=short \
      -q
    ;;

  all | *)
    run_pytest "All Tests" \
      tests/ \
      --timeout=120
    ;;

esac

STATUS=$?

echo ""
if [ $STATUS -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed.${NC}"
else
    echo -e "${RED}✗ Some tests failed (exit code: ${STATUS}).${NC}"
fi

exit $STATUS
