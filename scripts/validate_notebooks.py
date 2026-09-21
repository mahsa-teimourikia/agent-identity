import json
import subprocess
import sys
from pathlib import Path


REQUIRED_LAB_SECTIONS = (
    'scenario',
    'evaluation',
    'failure injection',
    'reflection',
)


def execute_lab_backed_notebook(path, data):
    """Execute code cells for notebooks backed by a reusable course lab."""
    lab_path = path.parent / 'lab.py'
    if not lab_path.exists():
        return

    markdown = '\n'.join(
        ''.join(cell.get('source', []))
        for cell in data['cells']
        if cell.get('cell_type') == 'markdown'
    ).lower()
    for section in REQUIRED_LAB_SECTIONS:
        assert section in markdown, f"Missing '{section}' section in {path}"

    source = '\n\n'.join(
        ''.join(cell.get('source', []))
        for cell in data['cells']
        if cell.get('cell_type') == 'code'
    )
    assert 'lab.py' in source, f'Notebook does not use its reusable lab: {path}'

    result = subprocess.run(
        [sys.executable, '-c', source],
        cwd=path.parent,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode:
        raise AssertionError(
            f'Execution failed for {path}:\n{result.stdout}\n{result.stderr}'
        )
    print(f'executed {path}')


def main():
    files = sorted(Path('curriculum').rglob('*.ipynb'))
    assert files, 'no notebooks found'
    for path in files:
        data = json.loads(path.read_text(encoding='utf-8'))
        assert data.get('nbformat') == 4 and data.get('cells'), f"Invalid format in {path}"
        print(f'validated {path}')
        execute_lab_backed_notebook(path, data)

if __name__ == '__main__':
    main()
