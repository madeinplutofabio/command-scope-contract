.PHONY: install test lint fmt check clean

install:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v

lint:
	ruff check .

fmt:
	ruff format .

check: lint test

clean:
	python -c "import pathlib, shutil; \
	paths = ['dist', 'build', '.pytest_cache', '.ruff_cache', 'htmlcov', 'out', 'receipts']; \
	[shutil.rmtree(p, ignore_errors=True) for p in paths]; \
	[path.unlink() for path in pathlib.Path('.').glob('.coverage*') if path.is_file()]; \
	[shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__') if p.is_dir()]; \
	[shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').glob('*.egg-info') if p.is_dir()]"
