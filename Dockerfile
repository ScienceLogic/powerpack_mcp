# The Python base image. Internal CI passes a Docker Hub proxy of the same image; anyone else gets
# it from Docker Hub.
ARG PYTHON_IMAGE=python:3.12-slim

################################################################################
# System Dependencies
FROM ${PYTHON_IMAGE} AS sys

ARG UV_VERSION=0.12.17

# git lets setuptools-scm read the version from the repository during `uv sync`. libatomic1 is
# needed by the Node.js binary the pyright package downloads for the lint checks. The service runs
# as an unprivileged user with a fixed uid, which the cache mounts below rely on.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git libatomic1 \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "uv==${UV_VERSION}" \
    && useradd --uid 65532 --user-group --create-home --shell /bin/bash nonroot \
    && install -d -o 65532 -g 65532 /app

USER 65532

################################################################################
# Dev Environment
FROM sys AS dev

ARG UV_LOCKED=1
ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_LOCKED=${UV_LOCKED} \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv.container \
    PATH=/app/.venv.container/bin:${PATH}

WORKDIR /app
COPY --chown=65532:65532 . .

RUN --mount=type=cache,id=powerpack-mcp-uv-cache-dev,target=/tmp/uv-cache,uid=65532,gid=65532 \
    git config --global --add safe.directory /app \
    && uv sync --all-extras --dev

ENTRYPOINT ["/bin/bash", "-c"]

################################################################################
# Build
FROM sys AS build

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_LOCKED=1 \
    UV_NO_EDITABLE=1 \
    UV_NO_DEV=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv.container \
    PATH=/app/.venv.container/bin:${PATH}

WORKDIR /app
COPY --chown=65532:65532 . .

RUN --mount=type=cache,id=powerpack-mcp-uv-cache-build,target=/tmp/uv-cache,uid=65532,gid=65532 \
    git config --global --add safe.directory /app \
    && uv sync

################################################################################
# Production / Release Container
#
# The same base image as the build stage, so the venv's interpreter symlink resolves.
FROM ${PYTHON_IMAGE} AS runtime

RUN useradd --uid 65532 --user-group --no-create-home --shell /usr/sbin/nologin nonroot

WORKDIR /app
COPY --from=build /app/.venv.container /app/.venv.container

ENV PATH=/app/.venv.container/bin:${PATH}
USER 65532
ENTRYPOINT ["python", "-m", "powerpack_mcp.main"]
