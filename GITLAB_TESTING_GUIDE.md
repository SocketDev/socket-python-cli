# GitLab Security Dashboard Integration - Testing Guide

This guide explains how to test the GitLab Security Dashboard integration before merging to production.

## Prerequisites

- GitLab account with access to create pipelines
- Socket API token (`SOCKET_API_TOKEN`)
- Access to a GitLab repository (can be a fork or test repo)

## Testing Approach Options

### Option A: Test in GitLab.com (Quickest)

1. **Push branch to GitLab**:
   ```bash
   # Add GitLab remote if not already added
   git remote add gitlab git@gitlab.com:your-username/socket-python-cli.git

   # Push the feature branch
   git push gitlab mucha-dev-gitlab-security-output
   ```

2. **Configure CI/CD Variables**:
   - Go to: Settings → CI/CD → Variables
   - Add variable: `SOCKET_API_TOKEN` (masked, not protected)

3. **Create test pipeline**:
   ```bash
   # Rename the test config
   mv .gitlab-ci-test.yml .gitlab-ci.yml
   git add .gitlab-ci.yml
   git commit -m "test: add GitLab CI configuration for testing"
   git push gitlab mucha-dev-gitlab-security-output
   ```

4. **Monitor the pipeline**:
   - Go to: CI/CD → Pipelines
   - Click on the running pipeline
   - Watch the `socket_security_test` job

5. **Verify Security Dashboard**:
   - Go to: Security & Compliance → Vulnerability Report
   - Check if Socket vulnerabilities appear
   - Or go to a Merge Request → Security tab

### Option B: Test with GitLab Runner Locally

Install GitLab Runner on your machine:

```bash
# macOS
brew install gitlab-runner

# Start runner
gitlab-runner exec docker socket_security_test \
  --docker-image python:3.11 \
  --env SOCKET_API_TOKEN=$SOCKET_API_TOKEN
```

### Option C: Create a Test Project in GitLab

1. **Create a new test repository in GitLab**
2. **Add Socket CLI as dependency**:
   ```yaml
   # .gitlab-ci.yml
   socket_test:
     stage: test
     image: python:3.11
     before_script:
       - pip install git+https://github.com/SocketDev/socket-python-cli.git@mucha-dev-gitlab-security-output
     script:
       - socketcli --enable-gitlab-security --repo test-repo --target-path .
     artifacts:
       reports:
         dependency_scanning: gl-dependency-scanning-report.json
   ```

3. **Add a test manifest file** (e.g., `package.json` or `requirements.txt`)
4. **Push and run pipeline**

## What to Verify

### 1. Pipeline Success ✅

- [ ] Pipeline completes without errors
- [ ] `socket_security_test` job succeeds
- [ ] Artifacts are uploaded successfully

### 2. Report File Generation ✅

- [ ] `gl-dependency-scanning-report.json` is created
- [ ] File size is reasonable (not empty, not huge)
- [ ] JSON is valid (can be parsed)

### 3. Report Schema Validation ✅

Download and inspect the artifact:

```bash
# Download from GitLab UI: Job → Browse → Download
# Or use GitLab API
curl --header "PRIVATE-TOKEN: <your_token>" \
  "https://gitlab.com/api/v4/projects/<project_id>/jobs/<job_id>/artifacts/gl-dependency-scanning-report.json" \
  > report.json

# Validate structure
cat report.json | python3 -m json.tool

# Check required fields
cat report.json | jq 'keys'
# Should include: version, scan, vulnerabilities

# Check scan metadata
cat report.json | jq '.scan'
# Should show: analyzer, scanner, type, status

# Check vulnerabilities
cat report.json | jq '.vulnerabilities | length'
# Shows count of vulnerabilities

cat report.json | jq '.vulnerabilities[0]'
# Shows first vulnerability structure
```

### 4. Security Dashboard Integration ✅

**In GitLab UI:**

- [ ] Go to: Security & Compliance → Vulnerability Report
- [ ] Vulnerabilities from Socket appear in the list
- [ ] Severity levels display correctly (Critical, High, Medium, Low)
- [ ] Package names and versions are shown
- [ ] CVE identifiers link correctly

**In Merge Request:**

- [ ] Create a test MR from your branch
- [ ] Go to MR → Security tab
- [ ] Socket findings appear in the security widget
- [ ] Can expand to see vulnerability details

### 5. Multiple Format Testing ✅

Test that multiple formats work simultaneously:

```bash
socketcli \
  --enable-json \
  --enable-gitlab-security \
  --repo test-repo \
  --target-path .

# Verify both outputs:
ls -lh gl-dependency-scanning-report.json
# JSON should also be in stdout
```

## Validation Checklist

### Report Structure
- [ ] `version` field is "15.0.0"
- [ ] `scan.type` is "dependency_scanning"
- [ ] `scan.analyzer.id` is "socket-security"
- [ ] `scan.scanner.id` is "socket-cli"
- [ ] `scan.status` is "success"
- [ ] `vulnerabilities` is an array (can be empty)

### Vulnerability Objects (if any found)
- [ ] Each has `id`, `category`, `name`, `severity`, `message`
- [ ] Each has `identifiers` array with at least socket_alert type
- [ ] CVE identifiers included (if applicable)
- [ ] Each has `location` with `file` and `dependency` fields
- [ ] `location.dependency.direct` is boolean
- [ ] `location.dependency.package.name` is present
- [ ] `location.dependency.version` is present
- [ ] `links` array includes Socket.dev URL

### Alert Filtering
- [ ] Only error/warn level alerts are included
- [ ] Ignored alerts are excluded
- [ ] Monitor-only alerts are excluded

## Troubleshooting

### Issue: Report not appearing in Security Dashboard

**Check:**
1. Artifact is uploaded: CI/CD → Jobs → Browse artifacts
2. Artifact path matches: `reports.dependency_scanning: gl-dependency-scanning-report.json`
3. Job succeeded (failed jobs don't register reports)
4. GitLab version supports Dependency Scanning (12.0+)

**Solution:**
```yaml
artifacts:
  reports:
    dependency_scanning: gl-dependency-scanning-report.json
  # Must be at job level, not global
```

### Issue: Empty vulnerabilities array

**This is normal if:**
- No new security issues detected
- All alerts are at monitor level (not error/warn)
- All alerts are ignored by policy

**Verify:**
- Check Socket.dev dashboard for actual findings
- Review Socket policy configuration

### Issue: Schema validation errors

**Common causes:**
- Missing required fields
- Invalid severity values
- Malformed JSON

**Debug:**
```bash
# Validate JSON syntax
cat gl-dependency-scanning-report.json | python3 -m json.tool

# Check against GitLab schema
# Download schema from:
# https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/dependency-scanning-report-format.json
```

### Issue: Installation fails in pipeline

**Solution:**
```yaml
before_script:
  - pip install --upgrade pip
  - pip install git+https://github.com/SocketDev/socket-python-cli.git@mucha-dev-gitlab-security-output
  # Or install from local wheel if testing locally built package
```

## Production Deployment Checklist

Before merging to main:

- [ ] All tests pass in GitLab CI
- [ ] Report appears in Security Dashboard
- [ ] Vulnerabilities display with correct severity
- [ ] CVE links work correctly
- [ ] Multiple format support works
- [ ] Documentation is complete and accurate
- [ ] Unit tests pass (`pytest tests/unit/test_gitlab_format.py`)
- [ ] Integration tests pass
- [ ] Code review completed
- [ ] No breaking changes to existing functionality

## Example Test Results

### Successful Pipeline Output:
```
$ socketcli --enable-gitlab-security --repo test/repo
2026-01-12 12:00:00,000: Starting Socket Security CLI version 2.2.63
2026-01-12 12:00:02,000: Full scan created with ID: abc-123
2026-01-12 12:00:02,000: GitLab Security report saved to gl-dependency-scanning-report.json
✓ Job succeeded
```

### Valid Report Structure:
```json
{
  "version": "15.0.0",
  "scan": {
    "analyzer": {"id": "socket-security", "name": "Socket Security"},
    "scanner": {"id": "socket-cli", "name": "Socket CLI"},
    "type": "dependency_scanning",
    "status": "success"
  },
  "vulnerabilities": [...]
}
```

## Resources

- [GitLab Dependency Scanning Documentation](https://docs.gitlab.com/ee/user/application_security/dependency_scanning/)
- [GitLab Security Report Schemas](https://gitlab.com/gitlab-org/security-products/security-report-schemas)
- [Socket GitLab Integration Docs](https://docs.socket.dev/docs/gitlab)
- [Socket CLI Documentation](./README.md#gitlab-security-dashboard-integration)

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review GitLab CI job logs
3. Validate report structure
4. Check Socket.dev dashboard for actual findings
5. Open an issue with pipeline logs and report file
