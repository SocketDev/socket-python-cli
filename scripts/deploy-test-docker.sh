#!/bin/sh

# This script builds the Docker image tagged cli:test and cli:$CLI_VERSION-test and pushes them to docker hub

# If CLI Version and/or SDK Version are not provided, it will check TestPyPI for the latest dev versions and use that after asking the user for confirmation

CLI_VERSION=$1
SDK_VERSION=$2

get_latest_version() {
    package=$1
    curl -s https://test.pypi.org/pypi/$package/json | python -c "
import sys, json
data = json.load(sys.stdin)
versions = list(data.get('releases', {}).keys())
versions.sort(key=lambda x: (
    x.split('.dev')[0],
    int(x.split('.dev')[1]) if '.dev' in x else 0
))
print(versions[-1] if versions else '')
"
}

if [ -z "$CLI_VERSION" ]; then
    echo "No CLI version specified, checking TestPyPI for latest version..."
    CLI_VERSION=$(get_latest_version "socketsecurity")
    echo "Latest CLI version on TestPyPI is: $CLI_VERSION"
fi

if [ -z "$SDK_VERSION" ]; then
    echo "No SDK version specified, checking TestPyPI for latest version..."
    SDK_VERSION=$(get_latest_version "socketdev")
    echo "Latest SDK version on TestPyPI is: $SDK_VERSION"
fi

echo -n "Deploy with CLI=$CLI_VERSION and SDK=$SDK_VERSION? (y/n): "
read answer

case $answer in
    [Yy]* ) ;;
    * ) echo "Aborted."; exit;;
esac

echo "Building and pushing Docker image..."
docker build --no-cache \
    --build-arg CLI_VERSION=$CLI_VERSION \
    --build-arg SDK_VERSION=$SDK_VERSION \
    --build-arg PIP_INDEX_URL=https://test.pypi.org/simple \
    --build-arg PIP_EXTRA_INDEX_URL=https://pypi.org/simple \
    --platform linux/amd64,linux/arm64 \
    -t socketdev/cli:$CLI_VERSION-test . \
    && docker build --no-cache \
    --build-arg CLI_VERSION=$CLI_VERSION \
    --build-arg SDK_VERSION=$SDK_VERSION \
    --build-arg PIP_INDEX_URL=https://test.pypi.org/simple \
    --build-arg PIP_EXTRA_INDEX_URL=https://pypi.org/simple \
    --platform linux/amd64,linux/arm64 \
    -t socketdev/cli:test . \
    && docker push socketdev/cli:$CLI_VERSION-test \
    && docker push socketdev/cli:test

if [ $? -eq 0 ]; then
    echo "Successfully deployed version $CLI_VERSION"
else
    echo "Failed to deploy version $CLI_VERSION"
    exit 1
fi 