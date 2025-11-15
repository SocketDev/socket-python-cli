#!/bin/sh
VERSION=$(grep -o "__version__.*" socketsecurity/__init__.py | awk '{print $3}' | tr -d "'")
ENABLE_PYPI_BUILD=$1
STABLE_VERSION=$2
GO_VERSION=${GO_VERSION:-"1.21"}
JAVA_VERSION=${JAVA_VERSION:-"17"}
DOTNET_VERSION=${DOTNET_VERSION:-"8"}

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

# Function to build Docker image with language versions
build_docker_image() {
    local cli_version=$1
    local tag=$2
    local pip_index=${3:-"https://pypi.org/simple"}
    local pip_extra_index=${4:-"https://pypi.org/simple"}
    local use_local=${5:-"false"}
    local dockerfile=${6:-"Dockerfile"}
    
    echo "Building with Go $GO_VERSION, Java $JAVA_VERSION, .NET $DOTNET_VERSION"
    
    local build_args="--build-arg CLI_VERSION=$cli_version"
    build_args="$build_args --build-arg GO_VERSION=$GO_VERSION"
    build_args="$build_args --build-arg JAVA_VERSION=$JAVA_VERSION"
    build_args="$build_args --build-arg DOTNET_VERSION=$DOTNET_VERSION"
    build_args="$build_args --build-arg PIP_INDEX_URL=$pip_index"
    build_args="$build_args --build-arg PIP_EXTRA_INDEX_URL=$pip_extra_index"
    build_args="$build_args --build-arg USE_LOCAL_INSTALL=$use_local"
    
    docker build --no-cache $build_args --platform linux/amd64,linux/arm64 -t $tag -f $dockerfile .
}

echo "Socket CLI version: $VERSION"
echo "Language versions: Go $GO_VERSION, Java $JAVA_VERSION, .NET $DOTNET_VERSION"

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
    echo ""
    echo "Environment variables for language versions:"
    echo "\tGO_VERSION: Go version to install (default: 1.21, or 'system' for Alpine package)"
    echo "\tJAVA_VERSION: Java version to install (default: 17, options: 8, 11, 17, 21)"
    echo "\tDOTNET_VERSION: .NET version to install (default: 8, options: 6, 8)"
    echo ""
    echo "Examples:"
    echo "\tGO_VERSION=1.19 JAVA_VERSION=11 $0 pypi-build=local stable=prod"
    echo "\tGO_VERSION=system JAVA_VERSION=8 $0 pypi-build=local stable=false"
    exit
fi

if [ $ENABLE_PYPI_BUILD = "pypi-build=prod" ]; then
    echo "Doing production build"
    
    build_docker_image $VERSION "socketdev/cli:$VERSION"
    docker push socketdev/cli:$VERSION
    
    build_docker_image $VERSION "socketdev/cli:latest"
    docker push socketdev/cli:latest
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
    
    build_docker_image $VERSION "socketdev/cli:$VERSION-test" "https://test.pypi.org/simple" "https://pypi.org/simple"
    docker push socketdev/cli:$VERSION-test
    
    build_docker_image $VERSION "socketdev/cli:test" "https://test.pypi.org/simple" "https://pypi.org/simple"
    docker push socketdev/cli:test
fi

if [ $STABLE_VERSION = "stable=true" ]; then
    if [ $ENABLE_PYPI_BUILD = "pypi-build=enable" ]; then
        if ! verify_package $VERSION "https://pypi.org/simple"; then
            echo "Failed to verify package on PyPI"
            exit 1
        fi
    fi
    
    build_docker_image $VERSION "socketdev/cli:stable"
    docker push socketdev/cli:stable
fi

if [ $ENABLE_PYPI_BUILD = "pypi-build=local" ]; then
    echo "Building local version without publishing to PyPI"
    
    # Determine PyPI source and build parameters
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
        PIP_INDEX_URL="https://pypi.org/simple"
        PIP_EXTRA_INDEX_URL="https://pypi.org/simple"
    else
        echo "For local builds, use stable=prod, stable=test, or stable=false"
        exit 1
    fi
    
    # Create language-specific tag if non-default versions are used
    LANG_TAG=""
    if [ "$GO_VERSION" != "1.21" ] || [ "$JAVA_VERSION" != "17" ] || [ "$DOTNET_VERSION" != "8" ]; then
        LANG_TAG="-go${GO_VERSION}-java${JAVA_VERSION}-dotnet${DOTNET_VERSION}"
    fi
    
    build_docker_image $VERSION "socketdev/cli:$VERSION-$TAG_SUFFIX$LANG_TAG" $PIP_INDEX_URL $PIP_EXTRA_INDEX_URL $USE_LOCAL_INSTALL "Dockerfile.flexible"
    
    build_docker_image $VERSION "socketdev/cli:$TAG_SUFFIX$LANG_TAG" $PIP_INDEX_URL $PIP_EXTRA_INDEX_URL $USE_LOCAL_INSTALL "Dockerfile.flexible"
    
    echo "Local build complete. Tagged as:"
    echo "  - socketdev/cli:$VERSION-$TAG_SUFFIX$LANG_TAG"
    echo "  - socketdev/cli:$TAG_SUFFIX$LANG_TAG"
fi