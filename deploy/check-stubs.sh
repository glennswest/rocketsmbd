#!/usr/bin/env bash
# No stubs (stormcentral#1455; owner: "stubs are lies"). Fails the build when
# a tracked file outside tests carries a stub marker: what exists works, what
# is not built is absent and filed as a `gap` issue. Copy this file into your
# component and run it from your build script, as warnings are refused:
#
#   deploy/check-stubs.sh            the checkout this script is in
#   deploy/check-stubs.sh <dir>      another checkout
#
# Not read: tests (a `test`/`tests`/`testdata`/`fixtures` directory, `*_test.rs`,
# `*.test.*`, `*.spec.*`), history (CHANGELOG, docs/work-plan*, docs/master-log/),
# vendored and lock files. A line that must quote a marker (a rule, an error
# about one) ends with `stub-sweep: allow`. stormcentral's nightly sweep
# (src/stubs.rs) reads with the same pattern and the same exclusions.
set -euo pipefail
cd "${1:-$(dirname "$0")/..}"

MARKERS='not (yet )?implemented|unimplemented!|todo!\(|not supported yet|coming soon' # stub-sweep: allow
SKIP='(^|/)(tests?|testdata|fixtures|vendor|node_modules)/|_tests?\.rs$|\.(test|spec)\.[A-Za-z]+$|(^|/)CHANGELOG|(^|/)docs/work-plan|(^|/)docs/master-log/|\.lock$'

found=$(git ls-files -z | grep -zvE "$SKIP" | xargs -0 -r grep -nIiE -- "$MARKERS" 2>/dev/null | grep -v 'stub-sweep: allow' || true)
if [[ -n "$found" ]]; then
  echo "stub markers (stormcentral#1455): what exists works; what is not built is absent and a \`gap\` issue" >&2
  echo "$found" >&2
  exit 1
fi
echo "==> no stub markers (#1455)"
