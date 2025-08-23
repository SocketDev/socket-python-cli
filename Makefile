.PHONY: setup sync clean test lint update-lock local-dev first-time-setup dev-setup sync-all first-time-local-setup

# Environment variable for local SDK path (optional)
SOCKET_SDK_PATH ?= ../socketdev

# Environment variable to control local development mode
USE_LOCAL_SDK ?= false

# === High-level workflow targets ===

# First-time repo setup after cloning (using PyPI packages)
first-time-setup: clean setup

# First-time setup for local development (using local SDK)
first-time-local-setup: 
	$(MAKE) clean
	$(MAKE) USE_LOCAL_SDK=true dev-setup

# Update lock file after changing pyproject.toml
update-lock:
	uv lock

# Setup for local development
dev-setup: clean local-dev setup

# Sync all dependencies after pulling changes
sync-all: sync

# === Implementation targets ===

# Installs dependencies needed for local development
# Currently: socketdev from test PyPI or local path
local-dev:
ifeq ($(USE_LOCAL_SDK),true)
	uv add --editable $(SOCKET_SDK_PATH)
endif

# Creates virtual environment and installs dependencies from uv.lock
setup: update-lock
	uv sync --all-extras
ifeq ($(USE_LOCAL_SDK),true)
	uv add --editable $(SOCKET_SDK_PATH)
endif

# Installs exact versions from uv.lock into your virtual environment
sync:
	uv sync --all-extras
ifeq ($(USE_LOCAL_SDK),true)
	uv add --editable $(SOCKET_SDK_PATH)
endif

# Removes virtual environment and cache files
clean:
	rm -rf .venv
	find . -type d -name "__pycache__" -exec rm -rf {} +

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .