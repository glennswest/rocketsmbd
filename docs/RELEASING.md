# Releasing

Releases are not built by GitHub Actions (owner, 2026-10-06, #41); they go
through the build box with `sc-build`.

1. Bump the version (`chore(release): vX.Y.Z`), tag it, push the branch and
   the tag.
2. Build the artifacts from the tag. Run this from a checkout of the branch
   that holds the tag:

   ```sh
   sc-build 'deploy/release-artifacts.sh vX.Y.Z' | tee tmp/release.log
   ```

   The script builds `git archive vX.Y.Z` (the exact tagged source): the
   static musl binaries for x86_64 and aarch64, the .deb and .rpm for each,
   and the src.rpm (`packaging/build-srpm.sh`). It checks that the shipped
   `/etc/rocketsmbd.toml` passes `--check` and is a config file in every
   package. sc-build keeps nothing, so each artifact is printed as
   `@@ARTIFACT <name> <sha256>`, then base64, then `@@END <name>`.
3. Decode the artifacts and check them against the printed sha256:

   ```sh
   mkdir -p tmp/dist && awk -v d=tmp/dist '
     /^@@ARTIFACT /{f=d"/"$2; h=$3; print h"  "f >> d"/SHA256SUMS"; next}
     /^@@END /{close(cmd); f=""; next}
     f{cmd="base64 -d >> \"" f "\""; print | cmd}' tmp/release.log
   (cd tmp/dist && sed 's#  tmp/dist/#  #' SHA256SUMS > SHA256SUMS.txt && sha256sum -c SHA256SUMS.txt)
   ```
4. Publish: `gh release create vX.Y.Z --verify-tag --notes-file <notes>
   tmp/dist/* ` (or `gh release upload` if the release exists).

crates.io, COPR and Debian uploads need the owner's tokens and are done only
when the owner asks.
