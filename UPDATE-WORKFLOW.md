# Stable upstream updates

OpenChamber checks daily at 10:00 Asia/Shanghai in this project's setup session.
Manage the “NekoBox stable upstream updates” task in OpenChamber's scheduler.

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
   branch/tag to Launchpad. Update the Launchpad recipe text and request builds
   for the validated target series, using the canonical account API URL.
8. Verify Launchpad build results and downloaded published binary contents.
   Record failures for follow-up and notify the user of a published update or
   a blocker. Do not install packages or change the host's apt sources.

Launchpad daily recipe builds stay disabled: they do not discover upstream
releases or import new release tarballs. The release-check scheduler runs on
this machine, so checks require it and OpenChamber to be running. Source hosting
and package publication remain on Launchpad.
