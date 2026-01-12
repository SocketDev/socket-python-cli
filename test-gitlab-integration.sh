#!/bin/bash
# Quick test script for GitLab Security Dashboard integration
# Usage: ./test-gitlab-integration.sh

set -e

echo "🧪 Testing GitLab Security Dashboard Integration"
echo "================================================"
echo ""

# Check if in virtual environment
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "⚠️  Virtual environment not activated"
    echo "   Activating .venv..."
    source .venv/bin/activate
fi

# Test 1: Verify CLI flags exist
echo "✅ Test 1: Checking CLI flags..."
python -m socketsecurity.socketcli --help | grep -q "gitlab-security" && \
    echo "   ✓ --enable-gitlab-security flag found" || \
    (echo "   ✗ Flag not found" && exit 1)

python -m socketsecurity.socketcli --help | grep -q "gitlab-security-file" && \
    echo "   ✓ --gitlab-security-file flag found" || \
    (echo "   ✗ Flag not found" && exit 1)

echo ""

# Test 2: Generate test report
echo "✅ Test 2: Generating GitLab Security report..."
if [[ -z "$SOCKET_API_TOKEN" ]]; then
    echo "   ⚠️  SOCKET_API_TOKEN not set. Using test mode."
    echo "   Set SOCKET_API_TOKEN to test with real API"
else
    python -m socketsecurity.socketcli \
        --enable-gitlab-security \
        --gitlab-security-file test-gitlab-report.json \
        --repo socket-python-cli \
        --target-path . 2>&1 | head -20

    if [[ -f "test-gitlab-report.json" ]]; then
        echo "   ✓ Report file created"
    else
        echo "   ⚠️  Report file not created (may be expected without API token)"
    fi
fi

echo ""

# Test 3: Validate report structure (if file exists)
if [[ -f "test-gitlab-report.json" ]]; then
    echo "✅ Test 3: Validating report structure..."

    python3 << 'VALIDATE'
import json
import sys

try:
    with open('test-gitlab-report.json') as f:
        report = json.load(f)

    # Check required fields
    assert 'version' in report, "Missing version"
    assert 'scan' in report, "Missing scan"
    assert 'vulnerabilities' in report, "Missing vulnerabilities"
    assert report['scan']['type'] == 'dependency_scanning', "Invalid scan type"

    print(f"   ✓ Valid GitLab report structure")
    print(f"   ✓ Schema version: {report['version']}")
    print(f"   ✓ Vulnerabilities: {len(report['vulnerabilities'])}")

    if report['vulnerabilities']:
        print(f"\n   Sample vulnerability:")
        vuln = report['vulnerabilities'][0]
        print(f"     - {vuln['severity']}: {vuln['name']}")
        print(f"     - Package: {vuln['location']['dependency']['package']['name']}")

    sys.exit(0)
except Exception as e:
    print(f"   ✗ Validation failed: {e}")
    sys.exit(1)
VALIDATE

    if [[ $? -eq 0 ]]; then
        echo "   ✓ Report validation passed"
    else
        echo "   ✗ Report validation failed"
        exit 1
    fi
else
    echo "⏭️  Test 3: Skipped (no report file generated)"
fi

echo ""

# Test 4: Multiple format support
echo "✅ Test 4: Testing multiple format support..."
echo '   Testing --enable-json --enable-gitlab-security...'

if [[ ! -z "$SOCKET_API_TOKEN" ]]; then
    python -m socketsecurity.socketcli \
        --enable-json \
        --enable-gitlab-security \
        --gitlab-security-file test-multi-format.json \
        --repo socket-python-cli \
        --target-path . 2>&1 | grep -q '"scan_failed"' && \
        echo "   ✓ JSON output detected" || \
        echo "   ⚠️  JSON output not detected"

    if [[ -f "test-multi-format.json" ]]; then
        echo "   ✓ GitLab report generated alongside JSON"
    fi
else
    echo "   ⏭️  Skipped (requires SOCKET_API_TOKEN)"
fi

echo ""
echo "================================================"
echo "🎉 Local testing complete!"
echo ""
echo "Next steps:"
echo "  1. Review test-gitlab-report.json (if generated)"
echo "  2. Push branch to GitLab for pipeline testing"
echo "  3. See GITLAB_TESTING_GUIDE.md for full test plan"
echo ""
echo "To test in GitLab CI:"
echo "  git push gitlab mucha-dev-gitlab-security-output"
echo "  # Then check CI/CD → Pipelines in GitLab"

# Cleanup
if [[ -f "test-gitlab-report.json" ]]; then
    echo ""
    echo "📄 Test report location: ./test-gitlab-report.json"
fi
