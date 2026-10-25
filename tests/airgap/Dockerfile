# Throwaway Linux box for exercising scripts/airgap_lockdown.sh (never run it on the host).
# The repo is bind-mounted read-only at /repo by tests/airgap/run_in_container.sh.
FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iptables curl ca-certificates python3 dnsutils procps \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /repo
CMD ["bash", "/repo/tests/airgap/run_in_container.sh", "--inside"]
