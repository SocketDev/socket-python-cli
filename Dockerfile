# Node.js from the official Alpine image instead of Alpine's nodejs package, which
# lags Node's security releases. Match the major version to what reachability needs
# and the Alpine release to the python:3-alpine base below.
FROM node:24-alpine3.24 AS node

FROM python:3-alpine
LABEL org.opencontainers.image.authors="socket.dev"

# Language version arguments with defaults
ARG GO_VERSION=system
ARG JAVA_VERSION=17
ARG DOTNET_VERSION=8

# CLI and SDK arguments
ARG CLI_VERSION
ARG SDK_VERSION
ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_EXTRA_INDEX_URL=https://pypi.org/simple
ARG USE_LOCAL_INSTALL=false

# Install base packages first
# ca-certificates must be 20261020-r0 or newer, which drops the roots the
# compromised eMudhra intermediates chain to. The base image ships an older
# one, and `apk add` does not upgrade installed packages, so upgrade it here.
RUN apk update && apk add --no-cache \
        git curl wget \
        ruby ruby-dev build-base strace && \
    apk upgrade --no-cache ca-certificates && \
    [ "$(apk version -t "$(apk list -I ca-certificates | awk '{print $1}' | sed 's/^ca-certificates-//')" 20261020-r0)" != "<" ]

# pip uses its own vendored CA bundle, not the system store, and the base image's
# pip trusts the compromised eMudhra intermediates. 26.2.2 vendors certifi
# 2026.10.19. Upgrade it against the system store fixed above.
RUN python -m pip install --no-cache-dir --cert /etc/ssl/certs/ca-certificates.crt --upgrade "pip>=26.2.2" && \
    python -c 'import sys, pip; sys.exit(tuple(map(int, pip.__version__.split(".")[:3])) < (26, 2, 2))'

# npm, npx and yarn are symlinks in the node image. COPY would dereference them
# into flat files and break their relative requires, so recreate the links.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=node /opt /opt
# Node rejects the compromised eMudhra intermediates from 24.22.1.
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \
    ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx && \
    ln -s ../lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack && \
    ln -s /opt/yarn-v*/bin/yarn /usr/local/bin/yarn && \
    ln -s /opt/yarn-v*/bin/yarnpkg /usr/local/bin/yarnpkg && \
    node -e 'const [a,b,c]=process.versions.node.split(".").map(Number); process.exit(a>24||(a===24&&(b>22||(b===22&&c>=1)))?0:1)'

# Install Go with version control
RUN if [ "$GO_VERSION" = "system" ]; then \
        apk add --no-cache go && \
        echo "/usr/lib/go" > /etc/goroot; \
    else \
        cd /tmp && \
        ARCH=$(uname -m) && \
        case $ARCH in \
            x86_64) GOARCH=amd64 ;; \
            aarch64) GOARCH=arm64 ;; \
            *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
        esac && \
        wget https://golang.org/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz && \
        tar -C /usr/local -xzf go${GO_VERSION}.linux-${GOARCH}.tar.gz && \
        rm go${GO_VERSION}.linux-${GOARCH}.tar.gz && \
        echo "/usr/local/go" > /etc/goroot; \
    fi

# Install Java with version control
RUN if [ "$JAVA_VERSION" = "8" ]; then \
        apk add --no-cache openjdk8-jdk; \
    elif [ "$JAVA_VERSION" = "11" ]; then \
        apk add --no-cache openjdk11-jdk; \
    elif [ "$JAVA_VERSION" = "17" ]; then \
        apk add --no-cache openjdk17-jdk; \
    elif [ "$JAVA_VERSION" = "21" ]; then \
        apk add --no-cache openjdk21-jdk; \
    else \
        echo "Unsupported Java version: $JAVA_VERSION. Supported: 8, 11, 17, 21" && exit 1; \
    fi

# Install .NET with version control
RUN if [ "$DOTNET_VERSION" = "6" ]; then \
        apk add --no-cache dotnet6-sdk; \
    elif [ "$DOTNET_VERSION" = "8" ]; then \
        apk add --no-cache dotnet8-sdk; \
    else \
        echo "Unsupported .NET version: $DOTNET_VERSION. Supported: 6, 8" && exit 1; \
    fi

# Install PyPy (Alpine-compatible build for x86_64 only)
# PyPy is an alternative Python interpreter that makes the Python reachability analysis faster.
# This is a custom build of PyPy3.12 for Alpine on x86-64.
ARG TARGETARCH  # Passed by Docker buildx
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        PYPY_URL="https://github.com/BarrensZeppelin/alpine-pypy/releases/download/alp3.24.2-pypy3.12-8.0.1/pypy3.12-v8.0.1-linux64-alpine3.24.tar.gz" && \
        PYPY_SHA256="b6d5dd429c6394f1710a52e3e20d5c9198547caff9528547c457d3f2ed37db09" && \
        curl -L -o /tmp/pypy.tar.gz "$PYPY_URL" && \
        echo "$PYPY_SHA256  /tmp/pypy.tar.gz" | sha256sum -c - && \
        mkdir -p /opt/pypy && \
        tar -xz --strip-components=1 -C /opt/pypy -f /tmp/pypy.tar.gz && \
        rm /tmp/pypy.tar.gz && \
        ln -s /opt/pypy/bin/pypy3 /bin/pypy3 && \
        pypy3 --version; \
    fi

# Install additional tools
RUN npm install socket -g && \
    gem install bundler && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . ~/.cargo/env && \
    rustup component add rustfmt clippy

# Set environment paths
ENV PATH="/usr/local/go/bin:/usr/lib/go/bin:/root/.cargo/bin:${PATH}"
ENV GOPATH="/go"

# Install uv (0.13.4+ ships the patched webpki-roots)
COPY --from=ghcr.io/astral-sh/uv:0.13.4 /uv /usr/local/bin/uv

# Install pyenv
# pyenv lets us build/install arbitrary Python versions on demand. We install
# the build dependencies needed to compile CPython on Alpine, then install
# pyenv itself. We deliberately only symlink the `pyenv` binary onto the PATH
# and do NOT add pyenv's shims directory, so its shims don't shadow the system
# Python that the CLI runs on.
RUN apk add --no-cache \
        bash \
        bzip2-dev \
        ca-certificates \
        libffi-dev \
        libxslt-dev \
        linux-headers \
        ncurses-dev \
        openssl-dev \
        readline-dev \
        sqlite-dev \
        xz-dev \
        zlib-dev
RUN curl -L https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | PYENV_GIT_TAG="v2.7.1" bash && \
    ln -s ~/.pyenv/bin/pyenv /bin/pyenv && \
    pyenv --version

# Install Python dependencies from the lockfile with hash verification so the
# image never resolves loose versions from PyPI at build time.
COPY pyproject.toml uv.lock /tmp/socket-cli-lock/
# Index flags are passed explicitly (always production PyPI) so the
# PIP_INDEX_URL/PIP_EXTRA_INDEX_URL ARGs used to point CLI/SDK preview installs
# at TestPyPI don't leak into the locked dependency install via pip's env vars.
RUN uv export --directory /tmp/socket-cli-lock --frozen --no-dev --no-emit-project \
        --format requirements-txt -o /tmp/socket-cli-lock/requirements.txt && \
    pip install --require-hashes --no-deps \
        --index-url https://pypi.org/simple --extra-index-url https://pypi.org/simple \
        -r /tmp/socket-cli-lock/requirements.txt

# Install CLI based on build mode
RUN if [ "$USE_LOCAL_INSTALL" = "true" ]; then \
        echo "Using local development install"; \
    else \
        cli_installed=false; \
        for i in $(seq 1 10); do \
            echo "Attempt $i/10: Installing socketsecurity==$CLI_VERSION"; \
            if pip install --no-deps --index-url ${PIP_INDEX_URL} --extra-index-url ${PIP_EXTRA_INDEX_URL} socketsecurity==$CLI_VERSION; then \
                cli_installed=true; \
                break; \
            fi; \
            if [ "$i" -lt 10 ]; then \
                echo "Install failed, waiting 30s before retry..."; \
                sleep 30; \
            fi; \
        done; \
        if [ "$cli_installed" != "true" ]; then \
            echo "Failed to install socketsecurity==$CLI_VERSION after 10 attempts"; \
            exit 1; \
        fi; \
        pip check || exit 1; \
        if [ ! -z "$SDK_VERSION" ]; then \
            pip install --index-url ${PIP_INDEX_URL} --extra-index-url ${PIP_EXTRA_INDEX_URL} socketdev==${SDK_VERSION}; \
        fi; \
    fi

# Copy local source and install in editable mode if USE_LOCAL_INSTALL is true
COPY . /app
WORKDIR /app
RUN if [ "$USE_LOCAL_INSTALL" = "true" ]; then \
        pip install --no-deps -e . && pip check; \
    fi

# Create workspace directory with proper permissions
RUN mkdir -p /go/src && chmod -R 777 /go

# Copy and setup entrypoint script
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
