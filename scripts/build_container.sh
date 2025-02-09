#!/bin/sh
VERSION=$(grep -o "__version__.*" socketsecurity/__init__.py | awk '{print $3}' | tr -d "'")
ENABLE_PYPI_BUILD=$1
STABLE_VERSION=$2
echo $VERSION
if [ -z $ENABLE_PYPI_BUILD ] || [ -z $STABLE_VERSION ]; then
  echo "$0 pypi-build=enable stable=true"
  echo "\tpypi-build: Build and publish a new version of the package to pypi. Options are prod or test"
  echo "\tstable: Only build and publish a new version for the stable docker tag if it has been tested and going on the changelog"
  exit
fi

if [ $ENABLE_PYPI_BUILD = "pypi-build=prod" ]; then
  echo "Doing production build"
  python -m build --wheel --sdist
  twine upload dist/*$VERSION*
  sleep 120
  docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:$VERSION . \
    && docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:latest . \
    && docker push socketdev/cli:$VERSION \
    && docker push socketdev/cli:latest
fi

if [ $ENABLE_PYPI_BUILD = "pypi-build=test" ]; then
  echo "Doing test build"
  python -m build --wheel --sdist
  twine upload --repository testpypi dist/*$VERSION*
  sleep 120
  docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:$VERSION-test . \
    && docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:test . \
    && docker push socketdev/cli:$VERSION-test \
    && docker push socketdev/cli:test
fi


if [ $STABLE_VERSION = "stable=true" ]; then
    if [ $ENABLE_PYPI_BUILD = "pypi-build=enable" ]; then
        sleep 120
    fi
    docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:stable . \
      && docker push socketdev/cli:stable
  fi

