#!/usr/bin/env bash
# Record the reference demo to an `asciinema` cast.
#
# Authority: spec.md §4.4 dev 2 — "asciinema is the right tool when we
# publish. Tracked as a docs-only follow-up." This script is that
# follow-up: it captures `./run.sh` (or a chosen subset of scenarios)
# into a `.cast` file that GitHub renders inline in the README, asciinema.org
# embeds via the `<asciinema-player>` web component, and the marketing
# site at site/ can ship as a static asset.
#
# Why asciinema, not mp4: the .cast file is plain JSON, ~20 KB for a
# full run, diffable in git, and the player is a 50 KB web component.
# An mp4 is 5–10 MB and can't be re-themed by the consumer. The
# headline demo is *terminal output* (the entire UX is terminal +
# Slack + email — no GUI to record), so asciinema is the right
# fidelity.
#
# Usage:
#   demo/scripts/record-demo.sh                 # full ./run.sh
#   demo/scripts/record-demo.sh 02              # just scenario 02
#   demo/scripts/record-demo.sh 02 03           # 02 and 03 in sequence
#
# Output:
#   demo/recordings/proxilion-<scenario>.cast
#
# Publish (manual; we deliberately don't auto-upload):
#   asciinema upload demo/recordings/proxilion-full.cast

set -euo pipefail

cd "$(dirname "$0")/../.."

if ! command -v asciinema >/dev/null 2>&1; then
    echo "asciinema not found. Install via:" >&2
    echo "  brew install asciinema     # macOS" >&2
    echo "  pipx install asciinema     # any platform" >&2
    echo "  apt install asciinema      # Debian / Ubuntu" >&2
    exit 1
fi

# Pick the command to record from the positional args. No args → run
# everything via the umbrella script; positional args → run just those
# scenarios in sequence.
if [ "$#" -eq 0 ]; then
    label="full"
    cmd=(bash demo/run.sh)
else
    label="$(IFS=-; echo "$*")"  # "02-03" for scenarios 02 + 03
    cmd=(bash -c '
        set -euo pipefail
        for s in "$@"; do
            script="demo/scripts/${s}-"*.sh
            for f in $script; do
                printf "\033[1;36m▶ %s\033[0m\n" "$f"
                bash "$f"
            done
        done
    ' -- "$@")
fi

mkdir -p demo/recordings
out="demo/recordings/proxilion-${label}.cast"

# `--overwrite` is intentional: a re-record should replace the prior
# cast deterministically. `--idle-time-limit=2` collapses long sleeps
# (e.g. compose health-check polling in `run.sh`) so the recording
# stays under 2 minutes even when the live demo waits 30s for
# postgres to come up. The viewer can see the 2s pause and read "we
# waited a bit" without sitting through the wall clock.
#
# `--title` is rendered by asciinema-player as the cast caption.
asciinema rec \
    --overwrite \
    --idle-time-limit=2 \
    --title "Proxilion demo — ${label}" \
    --command "$(printf '%q ' "${cmd[@]}")" \
    "$out"

echo
echo "✓ recorded → $out"
ls -lh "$out" | awk '{print "  size:", $5}'
echo
echo "Replay locally:"
echo "  asciinema play $out"
echo
echo "Embed in README / site (asciinema.org):"
echo "  asciinema upload $out"
echo "  (returns a URL like https://asciinema.org/a/<id>)"
