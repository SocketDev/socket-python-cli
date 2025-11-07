FROM python:3-alpine
LABEL org.opencontainers.image.authors="socket.dev"
ARG CLI_VERSION
ARG SDK_VERSION
ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_EXTRA_INDEX_URL=https://pypi.org/simple
ARG USE_LOCAL_INSTALL=false

RUN apk update \
    && apk add --no-cache git nodejs npm yarn curl \
    && npm install @coana-tech/cli -g

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

# ENTRYPOINT ["socketcli"]