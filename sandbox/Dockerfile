# Exploit-as-test enclave image for OpenShell: Python + pytest, nothing else.
# Build: sg docker -c "docker build -t wreckless-sandbox:py312 sandbox/"
# No USER line needed: OpenShell's supervisor runs every exec as uid 1000, not root.
# TODO: pin the base by digest (python:3.12-slim@sha256:...) once recorded from the built image.
FROM python:3.12-slim
RUN pip install --no-cache-dir "pytest==9.1.1" && rm -rf /root/.cache
