# Contributing to Agent Identity and Authorization Labs

First off, thank you for considering contributing to this repository! It's people like you that make this curriculum better for everyone.

## Code of Conduct

By participating in this project, you are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs
If you find a bug in the curriculum, a broken link, or an issue with the local setup, please open an issue on GitHub. Include as much detail as possible, such as:
- Which module/notebook you were working on.
- The error message you received.
- Your OS and Python version.

### Suggesting Enhancements
Have an idea for a new module, or a way to improve an existing lesson? We'd love to hear it! Open an issue to discuss your ideas before writing any code.

### Pull Requests
1. **Fork the repository** and clone it locally.
2. **Set up your environment**: We use `uv` for centralized dependency management. Run `make setup` in the root directory to bootstrap your virtual environment.
3. **Make your changes**: 
   - If you are modifying curriculum notebooks (`curriculum/**/*.ipynb`), please ensure your changes are clear and educational.
   - If you are adding a new notebook, ensure it follows the structure of existing labs.
4. **Test your changes**: Run `make jupyter` to test your notebooks locally. Before committing, ensure the validation script passes by running `uv run python scripts/validate_notebooks.py`.
5. **Commit and Push**: Create a feature branch (`git checkout -b feature/your-feature-name`), commit your changes, and push them to your fork.
6. **Open a PR**: Open a Pull Request against our `main` branch. A template will automatically populate to help you describe your changes. Our CI/CD pipeline will automatically validate your notebooks.

## Development Setup

The entire repository uses a unified virtual environment managed by `uv`.

```bash
# Set up the environment and install all dependencies
make setup

# Sync dependencies if pyproject.toml changes
make sync

# Start Jupyter Lab to view/edit notebooks
make jupyter
```

Thank you for your contributions!
