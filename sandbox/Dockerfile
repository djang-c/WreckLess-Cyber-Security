# Exploit-as-test enclave image for OpenShell: Python + pytest, nothing else.
# Build: sg docker -c "docker build -t wreckless-sandbox:py312 sandbox/"
FROM python:3.12-slim
RUN pip install --no-cache-dir "pytest>=8" && rm -rf /root/.cache
