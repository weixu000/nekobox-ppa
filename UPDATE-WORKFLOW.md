# Stable upstream updates

GitHub is the authoritative repository; Launchpad Git is a one-way build
mirror. Changes, including imported upstream branches and tags, originate
on GitHub. The mirror must never overwrite a divergent branch.

The GitHub Actions migration is in progress. Until its end-to-end validation
passes, OpenChamber's existing daily 10:00 Asia/Shanghai check remains enabled.

Run `scripts/check-upstream.py` with the network proxy from the machine's
agent instructions. Only non-draft, non-prerelease releases with a unified
source asset qualify. A failed check is not evidence that no update exists.

For a newer candidate:

1. Start from a clean, current `main`; stop if there is concurrent work.
2. Download the source asset, compute SHA-256 and compare GitHub's asset digest
   when supplied. Inspect archive paths before extraction. Record the version,
   URL, hash, top directory and release timestamp in `upstream.env`.
3. Update `debian/changelog` and the recipe base version together. The recipe's
   `~ubuntu<version>.1` suffix must sort above the last published package.
4. Regenerate bundled notices with `scripts/collect-notices.py` and review
   dependency, build-system and licence changes. A changed dependency or
   missing notice requires investigation, not an automatic bypass.
5. Prepare source and run an offline container build for every enabled target.
   Inspect each `.deb` for the GUI, matching runnable core and notices, and
   test that its launcher starts the core in an isolated fresh profile.
6. Prepare the upstream branch with `scripts/prepare-recipe.sh`. Test the
   actual recipe from a neutral working directory with Launchpad's flags,
   including `--append-version`, before publishing.
7. Only after validation passes, commit and push packaging and the new upstream
   branch/tag to GitHub, then mirror those exact refs to Launchpad.
   Update the Launchpad recipe text and request builds
   for the validated target series, using the canonical account API URL.
8. Verify Launchpad build results and downloaded published binary contents.
   Record failures for follow-up and notify the user of a published update or
   a blocker. Do not install packages or change the host's apt sources.

Launchpad daily recipe builds stay disabled: they do not discover upstream
releases or import new release tarballs. GitHub Actions will own discovery,
validation and deployment; Launchpad will own source/binary builds and apt
publication. Scheduled Actions may be delayed.
GitHub can disable scheduled workflows after 60 days of repository inactivity;
if that happens, re-enable the workflow in the Actions tab and run it manually.

## Deployment credentials

Repository Actions secrets:

- `LP_SSH_PRIVATE_KEY`: dedicated key registered with the Launchpad account;
  used only to push validated refs to the build mirror.
- `LP_CREDENTIALS`: Launchpad API credential file; used to update the recipe
  and request builds. Keep the token out of logs and build artifacts.

The workflow's GitHub token needs repository contents write permission only
for deployment. Pull-request validation must not receive deployment secrets.
