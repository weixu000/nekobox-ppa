# Packaging maintenance

- GitHub (`origin`) is canonical. Launchpad (`launchpad`) is a one-way build
  mirror, not a development branch. Never pull changes from the mirror into
  `main` or force-push over diverged history.
- Follow [UPDATE-WORKFLOW.md](UPDATE-WORKFLOW.md) before publishing a release.
  Keep GUI and core in the same package and preserve the offline-build checks.
- CI credentials belong in GitHub Actions secrets, never in source or logs.
