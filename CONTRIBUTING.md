# Contributing to Agent Identity and Authorization

Thank you for improving the curriculum. Every change should preserve the repository as both a teaching product and an executable system.

## Before you begin

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Use synthetic data and credential-free defaults.
- Report security issues privately according to [SECURITY.md](SECURITY.md).
- Open an issue before adding or substantially reordering a course.

## Development setup

Install Python 3.12+, [uv](https://docs.astral.sh/uv/getting-started/installation/), and Node.js 24+, then run:

```bash
make setup
make validate
```

Use `make help` to see all supported workflows. The canonical environment comes from `pyproject.toml` and `uv.lock`; see [DEPENDENCIES.md](DEPENDENCIES.md) before changing versions.

## Course changes

Keep a course's learner path synchronized:

1. README chapter and authoritative references;
2. one primary notebook;
3. reusable `lab.py` implementation;
4. fixtures, policies, and focused invariant tests;
5. course-local `requirements.txt`;
6. checkpoint and full-quiz questions; and
7. Hub metadata and curriculum navigation.

The notebook must import the reusable lab, run without credentials, explain design choices before code, interpret results after code, inject at least one realistic failure, evaluate labelled cases, and distinguish teaching fixtures from production controls. Model output may propose actions; deterministic application code must validate, authorize, execute, verify, and record them.

Do not commit notebook checkpoints, local environments, generated `site/` output, secrets, production data, or duplicate files with suffixes such as ` 2` or ` 3`.

## Validation

During development, run the narrowest relevant checks. Before opening a pull request, run the complete gate:

```bash
make ci
```

That command verifies the lockfile, repository structure and local links, Hub and quiz data, all isolated course tests, all notebooks, and known dependency advisories. To build the production-equivalent Pages artifact separately:

```bash
make site
```

If a check cannot run, state exactly why in the pull request. Do not label an unexecuted check as passed.

## Pull requests

Create a focused branch and use the pull request template. The description must retain these sections:

- Context
- What changed
- Validation performed
- Deployment impact
- Review focus

Include exact commands and results. Curriculum changes should identify the affected course, learner outcome, executable evidence, negative tests, and any dependency or deployment impact. Preserve unrelated working-tree changes.

## Reporting bugs

Include the course path, commit SHA, exact command, expected result, observed result, operating system, Python version, and `uv` version. For Hub issues, include the browser and route. Never include access tokens or other secrets in an issue.
