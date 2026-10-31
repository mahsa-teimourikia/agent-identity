.DEFAULT_GOAL := help

UV ?= uv
PYTHON := $(UV) run python
COURSE ?=

.PHONY: help setup sync update check-lock test notebooks repo-check hub-data hub-test validate audit ci site serve lab jupyter clean

help: ## Show the supported repository commands.
	@awk 'BEGIN {FS = ":.*## "; print "Agent Identity curriculum\n"} /^[a-zA-Z_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: sync ## Create the environment from the committed lockfile.

sync: ## Synchronize the local environment without changing locked versions.
	$(UV) sync --locked

update: ## Refresh all allowed dependencies and synchronize the environment.
	$(UV) lock --upgrade
	$(UV) sync --locked

check-lock: ## Verify pyproject.toml and uv.lock agree.
	$(UV) lock --check

test: ## Run every tracked course test suite in an isolated process.
	$(PYTHON) scripts/run_course_tests.py

notebooks: ## Validate and execute all 31 notebooks without credentials.
	$(PYTHON) scripts/validate_notebooks.py

repo-check: ## Validate course structure, links, requirements, and tracked files.
	$(PYTHON) scripts/validate_repository.py

hub-data: ## Regenerate deterministic Hub and quiz data.
	$(PYTHON) scripts/generate_hub_data.py

hub-test: hub-data ## Validate Hub data and browser-independent interactions.
	git diff --exit-code -- hub/lessons.js quiz/questions.js
	$(PYTHON) scripts/validate_hub.py
	node --test scripts/learning_hub.test.js

validate: check-lock repo-check hub-test ## Run fast repository and learner-surface checks.

audit: ## Audit every locked Python dependency against published advisories.
	$(UV) export --format requirements.txt --locked --no-dev --no-emit-project --no-annotate | $(UV)x --from pip-audit==2.10.1 pip-audit --requirement /dev/stdin --disable-pip

ci: sync validate test notebooks audit ## Run the same complete gate used by CI.

site: hub-test ## Build the production-equivalent static Pages directory.
	$(PYTHON) scripts/build_site.py

serve: site ## Build and serve the Learning Hub at http://localhost:8000.
	$(PYTHON) -m http.server 8000 --directory site

lab: ## Run one lab, for example: make lab COURSE=beginner/01-agent-identity-foundations
	@test -n "$(COURSE)" || (echo "Set COURSE=<level>/<course-directory>" >&2; exit 2)
	$(PYTHON) "curriculum/$(COURSE)/lab.py"

jupyter: ## Start JupyterLab in the synchronized environment.
	$(UV) run jupyter lab

clean: ## Remove generated local environments, site output, and caches.
	rm -rf .venv site .pytest_cache .coverage htmlcov .ruff_cache .mypy_cache
	find curriculum scripts -type d -name __pycache__ -prune -exec rm -rf {} +
