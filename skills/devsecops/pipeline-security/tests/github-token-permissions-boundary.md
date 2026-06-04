# GitHub Token Permission Boundary Fixtures

These fixtures calibrate `pipeline-security` CICD-SEC-2 findings for GitHub
Actions `GITHUB_TOKEN` permissions. Missing workflow `permissions` does not
always prove read/write access; it inherits the enterprise, organization, or
repository default workflow permission.

## Vulnerable Fixture 1: Missing Permissions With Unknown Platform Default

```yaml
name: build
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

Evidence:

```text
repository_default_workflow_permission: unknown
organization_default_workflow_permission: unknown
```

Expected assessment:

- Do not assert "defaults to read-write for everything" from the YAML alone.
- Mark effective `GITHUB_TOKEN` scope as `Not Evaluable from Config`.
- Request repository or organization Actions settings, or require an explicit
  least-privilege `permissions` block to remove ambiguity.

## Vulnerable Fixture 2: Explicit Broad Write Scope

```yaml
name: release
on: push
permissions: write-all
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/publish.sh
```

Expected assessment:

- Report CICD-SEC-2 because the workflow grants every available write scope.
- Require job-level least-privilege scopes such as `contents: read` plus only
  the write permissions that the publish job actually needs.

## Vulnerable Fixture 3: `pull_request_target` Without Permission Reduction

```yaml
name: label
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr edit "$PR_URL" --add-label needs-triage
        env:
          GH_TOKEN: ${{ github.token }}
          PR_URL: ${{ github.event.pull_request.html_url }}
```

Expected assessment:

- Treat the workflow as high-risk until it explicitly scopes permissions.
- Require a top-level or job-level block such as `permissions: { pull-requests:
  write, contents: read }`, adjusted to the exact operation.
- Continue checking for PR-controlled shell interpolation and checkout of
  untrusted code in the CICD-SEC-4 path.

## Benign Fixture 1: Missing Permissions With Verified Read-Only Default

```yaml
name: build
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

Evidence:

```text
repository_default_workflow_permission: read repository contents permission
organization_default_workflow_permission: read repository contents permission
```

Expected assessment:

- Do not report this as read/write default access.
- Still recommend an explicit `permissions: contents: read` block for
  self-documenting least privilege, but grade it separately from broad write
  exposure.

## Benign Fixture 2: Explicit Least-Privilege Build

```yaml
name: build
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

Expected assessment:

- Pass CICD-SEC-2 for token scope if no job requires additional write access.
- Continue assessing branch protection, dependency chain, and PPE controls in
  their separate sections.
