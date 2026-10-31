## Context

<!-- What learner, correctness, security, dependency, or maintenance problem does this solve? -->

## What changed

<!-- Identify affected courses and learner surfaces. Map important claims to implementation and tests. -->

## Validation performed

<!-- List exact commands and results. Mark anything not run and explain why. -->

- [ ] `make validate`
- [ ] relevant focused tests
- [ ] `make notebooks` when course code or dependencies changed
- [ ] `make audit` when dependencies changed
- [ ] `make site` when Hub, quiz, assets, or deployment changed

## Deployment impact

<!-- Note Pages, dependency, migration, compatibility, secret, data, or operational impact. Write "None" when not applicable. -->

## Review focus

<!-- Direct reviewers to the highest-risk decisions, invariants, and files. -->

## Checklist

- [ ] Default execution is credential-free and uses synthetic data.
- [ ] README, notebook, lab, tests, checkpoint, quiz, and Hub remain aligned.
- [ ] New or changed claims cite primary or official sources.
- [ ] No secret, private data, generated cache, or duplicate artifact is included.
- [ ] Unrelated working-tree changes are excluded.
