# UAT: GitLab Commit Status Integration

## Feature
`--enable-commit-status` posts a commit status (`success`/`failed`) to GitLab after scan completes. Repo admins can then require `socket-security` as a status check on protected branches.

## Prerequisites
- GitLab project with CI/CD configured
- `GITLAB_TOKEN` with `api` scope (or `CI_JOB_TOKEN` with sufficient permissions)
- Merge request pipeline (so `CI_MERGE_REQUEST_PROJECT_ID` is set)

## Test Cases

### 1. Pass scenario (no blocking alerts)
1. Create MR with no dependency changes (or only safe ones)
2. Run: `socketcli --scm gitlab --enable-commit-status`
3. **Expected**: Commit status `socket-security` = `success`, description = "No blocking issues"
4. Verify in GitLab: **Repository > Commits > (sha) > Pipelines** or **MR > Pipeline > External** tab

### 2. Fail scenario (blocking alerts)
1. Create MR adding a package with known blocking alerts
2. Run: `socketcli --scm gitlab --enable-commit-status`
3. **Expected**: Commit status = `failed`, description = "N blocking alert(s) found"

### 3. Flag omitted (default off)
1. Run: `socketcli --scm gitlab` (no `--enable-commit-status`)
2. **Expected**: No commit status posted

### 4. Non-MR pipeline (push event without MR)
1. Trigger pipeline on a push (no MR context)
2. Run: `socketcli --scm gitlab --enable-commit-status`
3. **Expected**: Commit status skipped (no `mr_project_id`), no error

### 5. API failure is non-fatal
1. Use an invalid/revoked `GITLAB_TOKEN`
2. Run: `socketcli --scm gitlab --enable-commit-status`
3. **Expected**: Error logged ("Failed to set commit status: ..."), scan still completes with correct exit code

### 6. Non-GitLab SCM
1. Run: `socketcli --scm github --enable-commit-status`
2. **Expected**: Flag is accepted but commit status is not posted (GitHub not yet supported)

## Configuring Protected Branch Requirement
1. Go to **Settings > Repository > Protected branches**
2. Edit the target branch
3. Under **Status checks**, add `socket-security` as a required external status check
4. MRs targeting that branch will now require Socket's `success` status to merge
