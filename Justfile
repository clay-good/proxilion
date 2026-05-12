# Common Proxilion dev / operator commands, runnable via `just <name>`.
#
# Why a Justfile and not a Makefile: the CI gate suite is parameter-
# rich (the three `clippy -A` flags, two `cargo deny` invocations,
# the locked test run) and `just` lets us name those without
# inventing fake POSIX-make targets. POSIX make is on every box; if
# you don't have `just` installed, every command below is a copy-
# paste shell snippet — the Justfile is purely an ergonomic.
#
# Install just: <https://just.systems> → `brew install just` /
# `cargo install just` / `apt install just`.

# List the recipes available.
default:
    @just --list --unsorted

# ---------- gates (the CI suite, runnable locally) ----------------

# Run the full CI gate suite end-to-end. What CI runs minus the
# coverage step (needs rustup-installed llvm-tools-preview, not
# Homebrew rust). Use `just ci` before pushing.
ci: fmt-check clippy test audit deny
    @echo "ok — every CI gate green locally"

# Format every crate. Idempotent. Use `just fmt-check` for the
# read-only CI gate.
fmt:
    cargo fmt --all

# CI gate: `cargo fmt --all -- --check`. Fails if any file is
# rustfmt-dirty.
fmt-check:
    cargo fmt --all -- --check

# CI gate: `cargo clippy -- -D warnings` with the three codebase-
# style allows documented in ci.yml.
clippy:
    cargo clippy --workspace --all-targets -- \
        -D warnings \
        -A clippy::type_complexity \
        -A clippy::too_many_arguments \
        -A clippy::result_large_err

# Apply auto-fixable clippy suggestions in place. Doesn't replace
# `just clippy` — manual review of the diff still required before
# commit.
clippy-fix:
    cargo clippy --workspace --all-targets --fix --allow-dirty -- \
        -D warnings \
        -A clippy::type_complexity \
        -A clippy::too_many_arguments \
        -A clippy::result_large_err

# CI gate: `cargo test --workspace --locked`. The `--locked` flag
# matches CI's exact dep graph from Cargo.lock.
test:
    cargo test --workspace --locked

# CI gate: `cargo audit --deny warnings` against the RustSec
# advisory DB. Ignores documented in .cargo/audit.toml.
audit:
    cargo audit --deny warnings

# CI gate: `cargo deny check` (advisories, bans, licenses, sources).
# Config in deny.toml.
deny:
    cargo deny check

# CI gate: release build with `-D warnings`. Slower than `cargo
# build`; use only when changing the build profile or pre-cut.
build-release:
    RUSTFLAGS="-D warnings" cargo build --workspace --release --locked

# Local coverage report. Requires rustup + llvm-tools-preview. CI's
# 60% / 60% floor lives in .github/workflows/coverage.yml.
coverage:
    cargo llvm-cov --workspace --lcov --output-path lcov.info \
        --ignore-filename-regex '(^|/)tests/'
    cargo llvm-cov report

# ---------- demo + smoke ------------------------------------------

# Bring up the full compose stack and run all four demo scenarios.
# See demo/README.md for the expected output.
demo:
    bash demo/run.sh

# Record the demo into a `.cast` file. asciinema must be installed.
record-demo *args:
    bash demo/scripts/record-demo.sh {{args}}

# Quick smoke check: bring up the minimal stack and drive the PCA_0
# mint flow. Exits non-zero on failure.
smoke:
    docker compose up -d --wait postgres trust-plane mock-okta
    bash scripts/smoke-pic.sh

# ---------- compose helpers ---------------------------------------

# Bring up the full dev stack (proxy + postgres + trust-plane +
# mock-okta + nats).
up:
    docker compose up -d --wait

# Tear it all down. Volumes survive.
down:
    docker compose down

# Tear down + wipe volumes. Use when the schema changed and you want
# postgres reset.
nuke:
    docker compose down -v

# Tail proxy logs (use `just logs proxy` etc).
logs service:
    docker compose logs -f {{service}}

# ---------- ergonomics --------------------------------------------

# `cargo install` every developer-tool needed for the CI gates.
# Idempotent — `cargo install` skips already-installed crates.
install-tools:
    cargo install cargo-audit --locked
    cargo install cargo-deny --locked
    cargo install cargo-llvm-cov --locked
