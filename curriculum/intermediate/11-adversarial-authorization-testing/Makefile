.PHONY: test python-test opa-test lab

test: python-test opa-test lab

python-test:
	pytest -q tests

opa-test:
	opa test --fail-on-empty --coverage policies/opa

lab:
	python lab.py

# Optional when the FGA CLI is installed:
# fga model test --tests policies/openfga/adversarial.fga.yaml
