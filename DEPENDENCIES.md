# Dependency policy

The repository has one canonical environment and 31 smaller course-local dependency slices.

## Sources of truth

- `pyproject.toml` declares supported direct dependency ranges.
- `uv.lock` records reproducible, platform- and Python-aware resolutions.
- `curriculum/<level>/<course>/requirements.txt` lists the minimum standalone slice for that course. It must accept the version selected by the canonical environment.

Use the lockfile for normal development and CI. Do not install every course requirements file into one environment; `make setup` already provides the tested union.

## Supported runtime

The project supports Python 3.12 and newer. The minimum was raised during the October 30, 2026 baseline review so the curriculum can use supported Pillow and Tornado releases and the current scientific and graph stack instead of retaining vulnerable or superseded Python 3.10 transitive dependencies. The checked-in `.python-version` keeps local `uv` commands on the tested minimum.

The direct Python 3.12 environment reviewed on October 30, 2026 includes:

| Integration | Tested version |
| --- | ---: |
| Authlib | 1.9.1 |
| CedarPy | 4.12.2 |
| cryptography | 50.0.2 |
| JupyterLab | 4.6.5 |
| LangChain | 1.4.7 |
| LangGraph | 1.2.19 |
| Matplotlib | 3.11.2 |
| MCP Python SDK | 2.3.0 |
| NetworkX | 3.7 |
| OPA Python client | 3.0.0 |
| OpenAI Agents SDK | 0.24.0 |
| OpenFGA SDK | 0.10.5 |
| OpenTelemetry | 1.45.2 |
| pandas | 3.1.0 |
| Pydantic | 2.14.2 |
| PyJWT | 2.15.1 |
| pytest | 9.2.0 |
| Hypothesis | 6.170.14 |

Run `uv tree --depth 1` for the complete direct resolution on your interpreter.

## Updating dependencies

1. Review upstream release and migration notes for security- or API-sensitive libraries.
2. Update compatible ranges in `pyproject.toml` and any affected course-local requirements.
3. Refresh and synchronize:

   ```bash
   make update
   ```

4. Run the complete gate:

   ```bash
   make ci
   ```

5. Inspect the lockfile diff. Unexpected source, index, Python-marker, or transitive-package changes require investigation.

Major updates are accepted only when all course tests and notebooks pass and the course prose still describes the exercised API. An intentional compatibility cap should include a short explanation in the affected course or pull request.

## Security and automation

`make audit` uses the pinned `pip-audit` runner to inspect the committed lockfile against published advisories. Dependabot checks Python and GitHub Actions dependencies weekly. Advisory absence does not prove safety; review changelogs, provenance, maintenance status, and transitive changes as part of every update.
