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
    echo "$0 pypi-build=<option> stable=<true|false|prod|test>"
    echo "\tpypi-build: Options are prod, test, or local"
    echo "\t  - prod: Build and publish to production PyPI, then build Docker images"
    echo "\t  - test: Build and publish to test PyPI, then build Docker images"
    echo "\t  - local: Build Docker images only using existing PyPI package (specify prod or test via stable parameter)"
    echo "\tstable: true/false/prod/test - Also tag as stable; for local builds:"
    echo "\t  - stable=prod: Use production PyPI package"
    echo "\t  - stable=test: Use test PyPI package"
    echo "\t  - stable=false: Use local development install (pip install -e .)"
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

if [ $ENABLE_PYPI_BUILD = "pypi-build=local" ]; then
    echo "Building local version without publishing to PyPI"
    
    # Determine PyPI source based on stable parameter
    if [ $STABLE_VERSION = "stable=prod" ]; then
        echo "Using production PyPI"
        PIP_INDEX_URL="https://pypi.org/simple"
        PIP_EXTRA_INDEX_URL="https://pypi.org/simple"
        TAG_SUFFIX="local"
        USE_LOCAL_INSTALL="false"
    elif [ $STABLE_VERSION = "stable=test" ]; then
        echo "Using test PyPI"
        PIP_INDEX_URL="https://test.pypi.org/simple"
        PIP_EXTRA_INDEX_URL="https://pypi.org/simple"
        TAG_SUFFIX="local-test"
        USE_LOCAL_INSTALL="false"
    elif [ $STABLE_VERSION = "stable=false" ]; then
        echo "Using local development install (pip install -e .)"
        TAG_SUFFIX="local-dev"
        USE_LOCAL_INSTALL="true"
    else
        echo "For local builds, use stable=prod, stable=test, or stable=false"
        exit 1
    fi
    
    if [ $USE_LOCAL_INSTALL = "true" ]; then
        docker build --no-cache \
            --build-arg USE_LOCAL_INSTALL=true \
            -t socketdev/cli:$VERSION-$TAG_SUFFIX \
            -t socketdev/cli:$TAG_SUFFIX .
    else
        docker build --no-cache \
            --build-arg CLI_VERSION=$VERSION \
            --build-arg PIP_INDEX_URL=$PIP_INDEX_URL \
            --build-arg PIP_EXTRA_INDEX_URL=$PIP_EXTRA_INDEX_URL \
            -t socketdev/cli:$VERSION-$TAG_SUFFIX \
            -t socketdev/cli:$TAG_SUFFIX .
    fi
    echo "Local build complete. Tagged as socketdev/cli:$VERSION-$TAG_SUFFIX and socketdev/cli:$TAG_SUFFIX"
fi

