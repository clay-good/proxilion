<!--
Thanks for the PR! A few quick checks before review:

- For security fixes, do not include exploit details in the title or
  first paragraph. The full writeup can land in the PR body — that's
  reasonable once a fix is staged — but the title should be
  patch-shaped, not advisory-shaped.
- Spec changes go in the same PR as the code that motivates them.
  Drift between spec and code is the failure mode this prevents.
- Run the local gate suite before pushing (see CONTRIBUTING.md):
    cargo fmt --all
    cargo clippy --workspace --all-targets -- -D warnings \
        -A clippy::type_complexity \
        -A clippy::too_many_arguments \
        -A clippy::result_large_err
    cargo test --workspace --locked
    cargo audit --deny warnings
    cargo deny check
-->

## What's new

<!-- One paragraph. The body, not the headline. -->

## Why

<!--
Spec section, operational story, or incident this addresses. If it
closes an Open question or Deviation note in docs/specs/, link it.
If this is a new behavior not yet in the spec, say so — and add the
spec text in the same PR.
-->

## Tests

<!--
- How many test binaries pass (run `cargo test --workspace 2>&1 |
  grep -cE "^test result: ok"` — should match the prior baseline + any
  new test binaries this PR introduces).
- New tests added: file:line, what they pin.
- Anything you couldn't test locally (e.g. coverage gate without
  rustup), and why.
-->

## Deviations from the spec sketch

<!--
Anything in this PR that diverges from what the spec called for, plus
why. Empty section is fine if there are none. Document deliberate
divergences here so the next contributor doesn't re-litigate.
-->

## Checklist

- [ ] Spec updated where behavior changed
- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy -- -D warnings` clean (with the three documented allows)
- [ ] `cargo test --workspace --locked` green
- [ ] `cargo audit --deny warnings` clean
- [ ] `cargo deny check` clean
- [ ] CHANGELOG.md updated under `## [Unreleased]`
- [ ] No secrets / credentials / customer data in commits or test fixtures

<!--
Reviewers: the bar is "does this make the security posture stronger,
the operator surface easier to live with, or the upstream adapter set
more useful — without growing the binary or the configuration surface
unnecessarily." See CONTRIBUTING.md for the longer version.
-->
