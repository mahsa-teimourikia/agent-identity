.PHONY: setup sync jupyter clean

setup:
	@echo "Setting up uv environment..."
	uv venv
	uv sync

sync:
	@echo "Syncing dependencies..."
	uv sync

jupyter:
	@echo "Starting Jupyter Lab..."
	uv run jupyter lab

clean:
	@echo "Cleaning up..."
	rm -rf .venv
	rm -rf __pycache__
	rm -rf .pytest_cache
