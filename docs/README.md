# 1. Clone the repo and create a virtualenv (Python 3.12+)
python3.12 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install --upgrade pip
pip install .[dev]

# 3. Set up pre-commit hooks
pre-commit install
