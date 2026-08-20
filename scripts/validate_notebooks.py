import json
from pathlib import Path

def main():
    files = sorted(Path('curriculum').rglob('*.ipynb'))
    assert files, 'no notebooks found'
    for path in files:
        data = json.loads(path.read_text())
        assert data.get('nbformat') == 4 and data.get('cells'), f"Invalid format in {path}"
        print(f'validated {path}')

if __name__ == '__main__':
    main()
