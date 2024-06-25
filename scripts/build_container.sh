#!/bin/sh
VERSION=$1
if [ -z $VERSION ]; then
  echo "version in the format of 0.0.0 needed"
  exit 1
fi
docker build --no-cache --platform linux/amd64,linux/arm64 -t socketdev/cli:$VERSION . && docker build --no-cache --platform linux/amd64,linux/arm64 -t socketdev/cli:latest .