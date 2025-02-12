.PHONY: setup compile-deps sync-deps clean test lint init-tools local-dev first-time-setup update-deps dev-setup sync-all first-time-local-setup

# Environment variable for local SDK path (optional)
SOCKET_SDK_PATH ?= ../socket-sdk-python

# Environment variable to control local development mode
USE_LOCAL_SDK ?= false

# === High-level workflow targets ===

# First-time repo setup after cloning (using PyPI packages)
first-time-setup: clean setup

# First-time setup for local development (using local SDK)
first-time-local-setup: 
	$(MAKE) clean
	$(MAKE) USE_LOCAL_SDK=true dev-setup

# Update dependencies after changing pyproject.toml
update-deps: compile-deps sync-deps

# Setup for local development
dev-setup: clean local-dev setup

# Sync all dependencies after pulling changes
sync-all: sync-deps

# === Implementation targets ===

# Creates virtual environment and installs pip-tools
init-tools:
	python -m venv .venv
	. .venv/bin/activate && pip install pip-tools

# Installs dependencies needed for local development
# Currently: socket-sdk-python from test PyPI or local path
local-dev: init-tools
ifeq ($(USE_LOCAL_SDK),true)
	. .venv/bin/activate && pip install -e $(SOCKET_SDK_PATH)
endif

# Creates/updates requirements.txt files with locked versions based on pyproject.toml
compile-deps: local-dev
	. .venv/bin/activate && pip-compile --output-file=requirements.txt pyproject.toml
	. .venv/bin/activate && pip-compile --extra=dev --output-file=requirements-dev.txt pyproject.toml
	. .venv/bin/activate && pip-compile --extra=test --output-file=requirements-test.txt pyproject.toml

# Creates virtual environment and installs dependencies from pyproject.toml
setup: compile-deps
	. .venv/bin/activate && pip install -e ".[dev,test]"

# Installs exact versions from requirements.txt into your virtual environment
sync-deps:
	. .venv/bin/activate && pip-sync requirements.txt requirements-dev.txt requirements-test.txt
ifeq ($(USE_LOCAL_SDK),true)
	. .venv/bin/activate && pip install -e $(SOCKET_SDK_PATH)
endif

# Removes virtual environment and cache files
clean:
	rm -rf .venv
	find . -type d -name "__pycache__" -exec rm -rf {} +

test:
	pytest

lint:
	ruff check .
	ruff format --check .