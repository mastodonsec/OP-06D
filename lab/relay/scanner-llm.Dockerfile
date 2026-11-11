# RC-47: Lab model relay: let the sealed scanner reach the planner model for lab runs
#
# The overlay's scanner: the RC-19 scanner image unchanged, plus the anthropic
# SDK (op06d's llm-anthropic extra) so `op06d run --planner llm` can use the
# hosted provider. Pins and hashes come from uv.lock via
# scanner-llm-requirements.txt. Built only by the model-relay overlays; the base
# lab never uses this image.
#
# BUILD needs internet (PyPI) and the base image already built:
#   docker compose -f lab/docker-compose.yml build scanner

ARG BASE_IMAGE=op06d-lab-scanner:nmap-7.93-nuclei-3.11.1-templates-10.5.1
FROM ${BASE_IMAGE}

COPY scanner-llm-requirements.txt /tmp/scanner-llm-requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: \
      -r /tmp/scanner-llm-requirements.txt \
 && rm /tmp/scanner-llm-requirements.txt \
 && /opt/venv/bin/pip freeze | grep -iE '^(anthropic|httpx2|pydantic|pyyaml)==' | sort > /opt/lab-llm-versions.txt \
 && grep -q '^anthropic==' /opt/lab-llm-versions.txt
