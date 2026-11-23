# Packaging maintenance

- GitHub (`origin`) is canonical and stores packaging, patches and automation.
  Launchpad receives signed source uploads, builds binaries and hosts the PPA.
- Follow [UPDATE-WORKFLOW.md](UPDATE-WORKFLOW.md) before publishing a release.
  Keep GUI and core in the same package and preserve the offline-build checks.
- CI credentials belong in GitHub Actions secrets, never in source or logs.
