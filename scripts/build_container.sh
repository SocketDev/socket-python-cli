#!/bin/sh

check_pypi_version() {
    local version=$1
    local repo=$2
    local url="https://test.pypi.org/pypi/socketsecurity/$version/json"

    if [ "$repo" = "prod" ]; then
        url="https://pypi.org/pypi/socketsecurity/$version/json"
    fi

    if curl --output /dev/null --silent --head --fail "$url"; then
        return 0
    else
        return 1
    fi
}

build_and_push_docker() {
    local version=$1
    local tags=$2
    local dry_run=$3
    local is_test=$4

    local pip_index="https://pypi.org/simple"
    if [ "$is_test" = "true" ]; then
        pip_index="https://test.pypi.org/simple --extra-index-url https://pypi.org/simple"
    fi

    if [ "$dry_run" = "dry-run=true" ]; then
        echo "[DRY RUN] Would execute the following commands:"
        echo "  docker buildx create --use --name multi-platform-builder"
        echo "  docker buildx build --push --no-cache \\"
        echo "    --build-arg CLI_VERSION=$version \\"
        echo "    --build-arg PIP_INDEX_URL=\"$pip_index\" \\"
        echo "    --platform linux/amd64,linux/arm64 \\"
        echo "    $tags ."
        echo "  docker buildx rm multi-platform-builder"
    else
        echo "Building docker image for version $version with tags: $tags"
        docker buildx create --use --name multi-platform-builder
        docker buildx build --push --no-cache \
            --build-arg CLI_VERSION=$version \
            --build-arg PIP_INDEX_URL="$pip_index" \
            --platform linux/amd64,linux/arm64 \
            $tags .
        docker buildx rm multi-platform-builder
    fi
}

wait_for_pypi_version() {
    local version=$1
    local repo=$2
    local timeout=300  # 5 minutes
    local interval=10  # 10 seconds
    local elapsed=0

    echo "Waiting for version $version to be available on ${repo}PyPI..."
    while [ $elapsed -lt $timeout ]; do
        if check_pypi_version "$version" "$repo"; then
            echo "Version $version is now available!"
            return 0
        fi
        echo "Version not available yet, waiting ${interval} seconds... (${elapsed}s/${timeout}s)"
        sleep $interval
        elapsed=$((elapsed + interval))
    done

    echo "Timeout waiting for version to appear on PyPI after ${timeout} seconds"
    return 1
}

VERSION=$(grep -o "__version__.*" socketsecurity/__init__.py | awk '{print $3}' | tr -d "'")
ENABLE_PYPI_BUILD=$1
STABLE_VERSION=$2
DRY_RUN=$3

if [ -z $ENABLE_PYPI_BUILD ] || [ -z $STABLE_VERSION ]; then
    echo "$0 pypi-build=enable stable=true [dry-run=true]"
    echo "\tpypi-build: Build and publish a new version $VERSION of the package to pypi. Options are prod or test"
    echo "\tstable: Only build and publish a new version for the stable docker tag if it has been tested and going on the changelog"
    echo "\tdry-run: Optional. If true, only print commands without executing"
    exit 1
fi

echo "Running with: ENABLE_PYPI_BUILD=$ENABLE_PYPI_BUILD STABLE_VERSION=$STABLE_VERSION DRY_RUN=$DRY_RUN"

case $ENABLE_PYPI_BUILD in
    "pypi-build=prod")
        echo "Doing production build"
        if ! check_pypi_version "$VERSION" "prod"; then
            if [ "$DRY_RUN" = "dry-run=true" ]; then
                echo "[DRY RUN] Would execute: python -m build --wheel --sdist && twine upload dist/*$VERSION*"
            else
                if python -m build --wheel --sdist && twine upload dist/*$VERSION*; then
                    if wait_for_pypi_version "$VERSION" "prod"; then
                        build_and_push_docker "$VERSION" "-t socketdev/cli:$VERSION -t socketdev/cli:latest" "$DRY_RUN" "false"
                        if [ "$STABLE_VERSION" = "stable=true" ]; then
                            build_and_push_docker "$VERSION" "-t socketdev/cli:stable" "$DRY_RUN" "false"
                        fi
                    else
                        echo "Failed to verify package on PyPI"
                        exit 1
                    fi
                else
                    echo "Failed to build or upload to PyPI"
                    exit 1
                fi
            fi
        else
            echo "Version $VERSION already exists on PyPI, skipping upload"
            build_and_push_docker "$VERSION" "-t socketdev/cli:$VERSION -t socketdev/cli:latest" "$DRY_RUN" "false"
            if [ "$STABLE_VERSION" = "stable=true" ]; then
                build_and_push_docker "$VERSION" "-t socketdev/cli:stable" "$DRY_RUN" "false"
            fi
        fi
        ;;

    "pypi-build=test")
        echo "Doing test build"
        if ! check_pypi_version "$VERSION" "test"; then
            if [ "$DRY_RUN" = "dry-run=true" ]; then
                echo "[DRY RUN] Would execute: python -m build --wheel --sdist && twine upload --repository testpypi dist/*$VERSION*"
            else
                if python -m build --wheel --sdist && twine upload --repository testpypi dist/*$VERSION*; then
                    if wait_for_pypi_version "$VERSION" "test"; then
                        build_and_push_docker "$VERSION" "-t socketdev/cli:$VERSION-test -t socketdev/cli:test" "$DRY_RUN" "true"
                    else
                        echo "Failed to verify package on TestPyPI"
                        exit 1
                    fi
                else
                    echo "Failed to build or upload to TestPyPI"
                    exit 1
                fi
            fi
        else
            echo "Version $VERSION already exists on TestPyPI, skipping upload"
            build_and_push_docker "$VERSION" "-t socketdev/cli:$VERSION-test -t socketdev/cli:test" "$DRY_RUN" "true"
        fi
        ;;
esac
