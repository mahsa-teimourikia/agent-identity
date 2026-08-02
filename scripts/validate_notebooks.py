import json
from pathlib import Path

def main():
    files = sorted(Path('labs/notebooks').glob('*.ipynb'))
    assert files, 'no notebooks found'
    for path in files:
        data = json.loads(path.read_text())
        assert data.get('nbformat') == 4 and data.get('cells')
        source = '\n'.join(''.join(c.get('source', [])) for c in data['cells'])
        assert 'Reflection' in source and 'import runpy' in source
        print(f'validated {path}')

if __name__ == '__main__':
    main()
