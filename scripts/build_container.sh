#!/bin/sh
VERSION=$(grep -o "__version__.*" socketsecurity/__init__.py | awk '{print $3}' | tr -d "'")
BYPASS_PYPI_BUILD=$1
echo $VERSION

if [ -z $BYPASS_PYPI_BUILD ] || [ $BYPASS_PYPI_BUILD -eq 0 ]; then
  python -m build --wheel --sdist
  twine upload dist/*$VERSION*
  sleep 180
fi

docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:$VERSION . \
&& docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:latest . \
&& docker push socketdev/cli:$VERSION \
&& docker push socketdev/cli:latest