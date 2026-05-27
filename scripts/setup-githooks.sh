#!/usr/bin/env bash
# One-time setup for Evidentia's local git hooks.
#
# Activates the .githooks/ directory as git's hook path + ensures
# every hook script is executable.
#
# Re-run on a fresh clone, after a `git config --unset core.hooksPath`,
# or whenever a new hook is added to .githooks/.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

if [ ! -d ".githooks" ]; then
    echo "ERROR: .githooks/ directory not found at ${REPO_ROOT}" >&2
    exit 1
fi

echo "Activating .githooks/ as the hook directory..."
git config core.hooksPath .githooks

echo "Marking hook scripts executable..."
for hook in .githooks/*; do
    if [ -f "${hook}" ]; then
        chmod +x "${hook}"
        echo "  +x ${hook}"
    fi
done

echo
echo "Done. Verify with:"
echo "  git config core.hooksPath        # should print: .githooks"
echo "  ls -la .githooks/                # all hooks should be +x"
echo
echo "Hooks currently installed:"
ls -1 .githooks/ | sed 's/^/  /'
