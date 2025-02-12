#!/bin/sh

# This script finds the latest dev version on TestPyPI, increments the dev version, and then uploads the new version to TestPyPI

# Get version from __init__.py
INIT_FILE="socketsecurity/__init__.py"
ORIGINAL_VERSION=$(grep -o "__version__.*" $INIT_FILE | awk '{print $3}' | tr -d "'")
BACKUP_FILE="${INIT_FILE}.bak"

# Get existing versions from TestPyPI
echo "Checking existing versions on TestPyPI..."
EXISTING_VERSIONS=$(curl -s https://test.pypi.org/pypi/socketsecurity/json | python -c "
import sys, json
data = json.load(sys.stdin)
versions = [v for v in data.get('releases', {}).keys() if v.startswith('$ORIGINAL_VERSION.dev')]
print('Filtered versions:', versions, file=sys.stderr)
if versions:
    versions.sort(key=lambda x: int(x.split('dev')[1]))
    print('Sorted versions:', versions, file=sys.stderr)
    print(versions[-1])
")

# Determine new version
if [ -z "$EXISTING_VERSIONS" ]; then
    VERSION="${ORIGINAL_VERSION}.dev1"
    echo "No existing dev versions found. Using ${VERSION}"
else
    LAST_DEV_NUM=$(echo $EXISTING_VERSIONS | grep -o 'dev[0-9]*' | grep -o '[0-9]*')
    NEXT_DEV_NUM=$((LAST_DEV_NUM + 1))
    VERSION="${ORIGINAL_VERSION}.dev${NEXT_DEV_NUM}"
    echo "Found existing version ${EXISTING_VERSIONS}. Using ${VERSION}"
fi

echo "Deploying version ${VERSION} to Test PyPI"

# Backup original __init__.py
cp $INIT_FILE $BACKUP_FILE

# Update version in __init__.py
sed -i.tmp "s/__version__ = '${ORIGINAL_VERSION}'/__version__ = '${VERSION}'/" $INIT_FILE
rm "${INIT_FILE}.tmp"

# Build and upload to test PyPI
python -m build --wheel --sdist > /dev/null 2>&1

# Restore original __init__.py
mv $BACKUP_FILE $INIT_FILE

# Upload to TestPyPI using python -m
if python -m twine upload --repository testpypi dist/*${VERSION}*; then
    echo
    echo "Deployed to Test PyPI. Wait a few minutes before installing the new version." 
    echo
    echo "New version:"
    echo "${VERSION}"
else
    echo
    echo "Failed to deploy to Test PyPI"
    exit 1
fi