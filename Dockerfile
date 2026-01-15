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
RUN apk update && apk add --no-cache \
        git nodejs npm yarn curl wget \
        ruby ruby-dev build-base

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
# This is a custom build of PyPy3.11 for Alpine on x86-64.
ARG TARGETARCH  # Passed by Docker buildx
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        PYPY_URL="https://github.com/BarrensZeppelin/alpine-pypy/releases/download/alp3.23.1-pypy3.11-7.3.20/pypy3.11-v7.3.20-linux64-alpine3.21.tar.bz2" && \
        PYPY_SHA256="60847fea6ffe96f10a3cd4b703686e944bb4fbcc01b7200c044088dd228425e1" && \
        curl -L -o /tmp/pypy.tar.bz2 "$PYPY_URL" && \
        echo "$PYPY_SHA256  /tmp/pypy.tar.bz2" | sha256sum -c - && \
        mkdir -p /opt/pypy && \
        tar -xj --strip-components=1 -C /opt/pypy -f /tmp/pypy.tar.bz2 && \
        rm /tmp/pypy.tar.bz2 && \
        ln -s /opt/pypy/bin/pypy3 /bin/pypy3 && \
        pypy3 --version; \
    fi

# Install additional tools
RUN npm install @coana-tech/cli socket -g && \
    gem install bundler && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . ~/.cargo/env && \
    rustup component add rustfmt clippy

# Set environment paths
ENV PATH="/usr/local/go/bin:/usr/lib/go/bin:/root/.cargo/bin:${PATH}"
ENV GOPATH="/go"

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install CLI based on build mode
RUN if [ "$USE_LOCAL_INSTALL" = "true" ]; then \
        echo "Using local development install"; \
    else \
        for i in $(seq 1 10); do \
            echo "Attempt $i/10: Installing socketsecurity==$CLI_VERSION"; \
            if pip install --index-url ${PIP_INDEX_URL} --extra-index-url ${PIP_EXTRA_INDEX_URL} socketsecurity==$CLI_VERSION; then \
                break; \
            fi; \
            echo "Install failed, waiting 30s before retry..."; \
            sleep 30; \
        done && \
        if [ ! -z "$SDK_VERSION" ]; then \
            pip install --index-url ${PIP_INDEX_URL} --extra-index-url ${PIP_EXTRA_INDEX_URL} socketdev==${SDK_VERSION}; \
        fi; \
    fi

# Copy local source and install in editable mode if USE_LOCAL_INSTALL is true
COPY . /app
WORKDIR /app
RUN if [ "$USE_LOCAL_INSTALL" = "true" ]; then \
        pip install --upgrade -e .; \
        pip install --upgrade socketdev; \
    fi

# Create workspace directory with proper permissions
RUN mkdir -p /go/src && chmod -R 777 /go

# Copy and setup entrypoint script
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
