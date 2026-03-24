# CSC Hardened Mode Container Image
#
# Provides the runtime environment for hardened-mode execution:
# - bubblewrap (bwrap): namespace/filesystem isolation
# - setpriv: --no-new-privs (always), privilege drop (when configured)
# - prlimit: resource limits
# - Python 3.11+ with csc-runner installed
#
# Expected usage:
#   docker build -t csc-hardened .
#   docker run --network=none --rm csc-hardened \
#     run contract.json policy.yaml \
#       --mode hardened --sign --signing-key /keys/key.pem --key-id prod-01
#
# The container MUST be started with --network=none to satisfy the
# hardened-mode network-disabled preflight check. bwrap additionally
# creates its own network namespace (--unshare-net) inside the sandbox.
#
# Privilege model:
#   The container runs as a non-root user (csc-runner). This means
#   setpriv --reuid/--regid/--clear-groups is NOT supported in this
#   image — the runner process lacks permission to switch UIDs/GIDs.
#   SandboxConfig run_as_uid/run_as_gid should be left as None.
#   --no-new-privs is always applied regardless.
#   --clear-groups is only applied when run_as_uid/run_as_gid are
#   configured, which this image does not support under the default
#   non-root container user.
#   To enable inner UID/GID switching, start the container as root
#   (not recommended for the Stage 2 pilot).
#
# Runtime dependencies:
#   bubblewrap requires the host/container runtime to allow the
#   namespace features it needs (user namespaces, mount namespaces,
#   etc.). Installing the package is necessary but not sufficient —
#   successful hardened execution depends on the runtime environment.
#   Some container runtimes (e.g. restrictive seccomp profiles,
#   disabled user namespaces) may prevent bwrap from functioning.
#   The hardened-mode integration tests verify this end-to-end.
#
# This is a dev/test image (includes test dependencies). A minimal
# runtime image should install without [dev] extras and copy only
# the necessary source files.

FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

# Install sandbox tools.
# bubblewrap: mount/pid/network namespace isolation
# util-linux: provides setpriv and prlimit
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bubblewrap \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

# Verify tools are available.
RUN bwrap --version && setpriv --version && prlimit --version

# Create a non-root user for the runner process.
RUN useradd --create-home --shell /bin/bash csc-runner

# Install csc-runner.
WORKDIR /app
COPY pyproject.toml README.md ./
COPY csc_runner/ ./csc_runner/
COPY schemas/ ./schemas/
# examples/ contains sample contracts and policies used by CLI tests.
COPY examples/ ./examples/
RUN pip install --no-cache-dir -e ".[dev]"

# Create workspace directory for sandbox bind mounts.
RUN mkdir -p /workspace && chown csc-runner:csc-runner /workspace

# Switch to non-root user.
USER csc-runner

ENTRYPOINT ["csc"]
