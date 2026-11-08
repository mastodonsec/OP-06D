# OP-06D lab scanner image (RC-19).
#
# Real nmap and nuclei at PINNED versions, plus the curated nuclei template set
# pinned to a release tag. Everything downloaded here is verified against a
# SHA-256 recorded below. This image is BUILT with internet access (apt, GitHub,
# PyPI) but is RUN only on the internal, no-egress lab network (docker-compose.yml).
#
# Pins (also recorded in lab/RUNBOOK.md):
#   base image   debian:bookworm-slim @ sha256:734a72b3...
#   nmap         7.93+dfsg1-1   (Debian bookworm package, exact version)
#   nuclei       v3.11.1        (release zip, sha256 below)
#   templates    v10.5.1        (nuclei-templates tag tarball, sha256 below)
#
# If a checksum fails at build time, STOP and investigate before re-pinning:
# GitHub can regenerate tag tarballs, but a mismatch must be reviewed, not waved through.

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

ARG NMAP_VERSION=7.93+dfsg1-1
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_ZIP_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG TEMPLATES_VERSION=v10.5.1
ARG TEMPLATES_TARBALL_SHA256=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb

LABEL org.op06d.lab.nmap="${NMAP_VERSION}" \
      org.op06d.lab.nuclei="${NUCLEI_VERSION}" \
      org.op06d.lab.nuclei-templates="${TEMPLATES_VERSION}"

# Tools for the scans plus the isolation checks (curl, ping, ip, getent, nc, bash)
# and python for running the OP-06D code inside the lab.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap=${NMAP_VERSION} \
      ca-certificates curl unzip iputils-ping iproute2 netcat-openbsd procps \
      python3 python3-venv python3-pip \
 && rm -rf /var/lib/apt/lists/*

# nuclei: pinned release, checksum verified.
RUN curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
 && echo "${NUCLEI_ZIP_SHA256}  /tmp/nuclei.zip" | sha256sum -c - \
 && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin \
 && chmod 0755 /usr/local/bin/nuclei \
 && rm /tmp/nuclei.zip

# Curated template set: pinned tag, checksum verified, made read-only. The
# wrapper only ever passes this directory as -t and never updates it.
RUN curl -fsSL -o /tmp/templates.tgz \
      "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${TEMPLATES_VERSION}.tar.gz" \
 && echo "${TEMPLATES_TARBALL_SHA256}  /tmp/templates.tgz" | sha256sum -c - \
 && mkdir -p /opt/nuclei-templates \
 && tar -xzf /tmp/templates.tgz -C /opt/nuclei-templates --strip-components=1 \
 && rm /tmp/templates.tgz \
 && chmod -R a-w /opt/nuclei-templates

# Python environment for the OP-06D code (mounted read-only at /op06d).
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# An unprivileged user, used to document nmap's behavior without root.
RUN useradd --create-home --uid 1000 --shell /bin/bash scanner \
 && mkdir -p /captures \
 && chmod 0777 /captures

# Record exactly what was installed (written from build args, nothing is executed).
RUN printf 'nmap=%s\nnuclei=%s\nnuclei-templates=%s\nbase=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc\n' \
      "${NMAP_VERSION}" "${NUCLEI_VERSION}" "${TEMPLATES_VERSION}" > /opt/lab-versions.txt

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH="/op06d/src" \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /op06d
CMD ["sleep", "infinity"]
