#!/bin/sh
VERSION=$(grep -o "__version__.*" socketsecurity/__init__.py | awk '{print $3}' | tr -d "'")

echo $VERSION
python -m build --wheel --sdist
twine upload dist/*$VERSION*
sleep 120
docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:$VERSION . && docker build --no-cache --build-arg CLI_VERSION=$VERSION --platform linux/amd64,linux/arm64 -t socketdev/cli:latest .
docker push socketdev/cli:$VERSION && docker push socketdev/cli:latest