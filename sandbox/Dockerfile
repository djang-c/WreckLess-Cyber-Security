# Exploit-as-test enclave image for OpenShell: Python + pytest, nothing else.
# Build: sg docker -c "docker build -t wreckless-sandbox:py312 sandbox/"
# No USER line needed: OpenShell's supervisor runs every exec as uid 1000, not root.
# Base pinned to the digest every gate/test run so far used (recorded on the GB10, 2026-10-25).
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
RUN pip install --no-cache-dir "pytest==9.1.1" && rm -rf /root/.cache
