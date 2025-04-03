#!/bin/sh
VERSION=$(grep -o "__version__.*" socketsecurity/__init__.py | awk '{print $3}' | tr -d "'")
ENABLE_PYPI_BUILD=$1
STABLE_VERSION=$2

verify_package() {
    local version=$1
    local pip_index=$2
    echo "Verifying package availability..."
    
    for i in $(seq 1 30); do
        if pip install --index-url $pip_index socketsecurity==$version; then
            echo "Package $version is now available and installable"
            pip uninstall -y socketsecurity
            return 0
        fi
        echo "Attempt $i: Package not yet installable, waiting 20s... ($i/30)"
        sleep 20
    done
    
    echo "Package verification failed after 30 attempts"
    return 1
}

echo $VERSION
if [ -z $ENABLE_PYPI_BUILD ] || [ -z $STABLE_VERSION ]; then
    echo "$0 pypi-build=enable stable=true"
    echo "\tpypi-build: Build and publish a new version of the package to pypi. Options are prod or test"
    echo "\tstable: Only build and publish a new version for the stable docker tag if it has been tested and going on the changelog"
    exit
fi

if [ $ENABLE_PYPI_BUILD = "pypi-build=prod" ]; then
    echo "Doing production build"
#    if ! python -m build --wheel --sdist; then
#        echo "Build failed"
#        exit 1
#    fi
#
#    if ! twine upload dist/*$VERSION*; then
#        echo "Upload to PyPI failed"
#        exit 1
#    fi
#
#    if ! verify_package $VERSION "https://pypi.org/simple"; then
#        echo "Failed to verify package on PyPI"
#        exit 1
#    fi
    
    docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:$VERSION . \
        && docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:latest . \
        && docker push socketdev/cli:$VERSION \
        && docker push socketdev/cli:latest
fi

if [ $ENABLE_PYPI_BUILD = "pypi-build=test" ]; then
    echo "Doing test build"
    if ! python -m build --wheel --sdist; then
        echo "Build failed"
        exit 1
    fi
    
    if ! twine upload --repository testpypi dist/*$VERSION*; then
        echo "Upload to TestPyPI failed"
        exit 1
    fi
    
    if ! verify_package $VERSION "https://test.pypi.org/simple"; then
        echo "Failed to verify package on TestPyPI"
        exit 1
    fi
    
    docker build --no-cache \
        --build-arg CLI_VERSION=$VERSION \
        --build-arg PIP_INDEX_URL=https://test.pypi.org/simple \
        --build-arg PIP_EXTRA_INDEX_URL=https://pypi.org/simple \
        --platform linux/amd64,linux/arm64 \
        -t socketdev/cli:$VERSION-test . \
        && docker build --no-cache \
        --build-arg CLI_VERSION=$VERSION \
        --build-arg PIP_INDEX_URL=https://test.pypi.org/simple \
        --build-arg PIP_EXTRA_INDEX_URL=https://pypi.org/simple \
        --platform linux/amd64,linux/arm64 \
        -t socketdev/cli:test . \
        && docker push socketdev/cli:$VERSION-test \
        && docker push socketdev/cli:test
fi

if [ $STABLE_VERSION = "stable=true" ]; then
    if [ $ENABLE_PYPI_BUILD = "pypi-build=enable" ]; then
        if ! verify_package $VERSION "https://pypi.org/simple"; then
            echo "Failed to verify package on PyPI"
            exit 1
        fi
    fi
    docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:stable . \
        && docker push socketdev/cli:stable
fi

