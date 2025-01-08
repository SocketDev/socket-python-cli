.PHONY: sync-deps test lint

sync-deps:
	pip-compile pyproject.toml -o requirements.txt

test:
	pytest

lint:
	ruff check .
	ruff format --check .