# Pending CI workflow

`workflow-ci.yml.pending` is the build workflow for this repository, held here
rather than at `.github/workflows/ci.yml` because **the GitOversight GitHub App
lacks the `workflows` permission** and cannot write that path.

Confirmed by a known-answer test in both directions (2026-07-26):

- a commit whose *only* file is `.github/workflows/ci.yml` → `403 Resource not
  accessible by integration` on `POST /git/trees`
- the same commit with that file removed → `state: verified`
- 100+ other commits through the same App, same credentials, clean

The 403 fires at `/git/trees`, so it reads as a generic write denial rather than
a scope-specific one — which is why it was misdiagnosed for weeks as "the App is
not installed."

## To activate

A human, or any credential holding the `workflows` scope, moves it into place:

```bash
mkdir -p .github/workflows
git mv ci/workflow-ci.yml.pending .github/workflows/ci.yml
git rm ci/README.md
```

Then delete this directory. Until that happens the file is preserved and
version-controlled rather than stranded on a branch nobody will look at again.

Tracked as #218.
