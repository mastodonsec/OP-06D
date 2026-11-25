# SPDX-License-Identifier: AGPL-3.0-or-later
#
# OP-06D container image: OP-06D with the toolchain validated in the lab.
#
#   base image   debian:bookworm-slim, pinned by digest
#   nmap         7.93+dfsg1-1   (Debian bookworm package, exact version)
#   nuclei       v3.11.1        (release zip per architecture, sha256 verified)
#   templates    v10.5.1        (nuclei-templates tag tarball, sha256 verified, read-only)
#   OP-06D       this checkout, Python dependencies hash-pinned from uv.lock
#
# Architectures: linux/amd64 and linux/arm64. Build:
#   docker buildx build --platform linux/amd64,linux/arm64 -t op06d .
# The lab scanner is the `lab` stage below (the product image plus test tools).
#
# BUILD needs internet (apt, GitHub, PyPI). RUN fetches nothing: nuclei's
# update check is disabled by the wrapper and the template set is read-only.
# If a checksum fails, STOP and investigate before re-pinning.

# The base image is written out on every FROM line, not taken from a build
# argument, so Dependabot can read and bump its digest (it rewrites FROM lines
# only, all of them together). BASE_IMAGE records the same reference in the
# toolchain file; tests/test_container_image.py fails while they disagree.
ARG BASE_IMAGE=debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

# --- fetch: nuclei and the template set, checksum verified -------------------
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS fetch
ARG TARGETARCH
ARG NUCLEI_VERSION=3.11.1
# From nuclei_3.11.1_checksums.txt on the v3.11.1 GitHub release.
ARG NUCLEI_ZIP_SHA256_AMD64=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
ARG NUCLEI_ZIP_SHA256_ARM64=8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07
ARG TEMPLATES_VERSION=v10.5.1
ARG TEMPLATES_TARBALL_SHA256=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*
RUN case "${TARGETARCH}" in \
      amd64) sha="${NUCLEI_ZIP_SHA256_AMD64}" ;; \
      arm64) sha="${NUCLEI_ZIP_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: '${TARGETARCH}' (build with BuildKit for linux/amd64 or linux/arm64)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
 && echo "${sha}  /tmp/nuclei.zip" | sha256sum -c - \
 && mkdir -p /out/bin /out/licenses \
 && unzip -q /tmp/nuclei.zip nuclei LICENSE.md -d /tmp/nuclei \
 && install -m 0755 /tmp/nuclei/nuclei /out/bin/nuclei \
 && cp /tmp/nuclei/LICENSE.md /out/licenses/nuclei-LICENSE.md
RUN curl -fsSL -o /tmp/templates.tgz \
      "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/${TEMPLATES_VERSION}.tar.gz" \
 && echo "${TEMPLATES_TARBALL_SHA256}  /tmp/templates.tgz" | sha256sum -c - \
 && mkdir -p /out/nuclei-templates \
 && tar -xzf /tmp/templates.tgz -C /out/nuclei-templates --strip-components=1 \
 && cp /out/nuclei-templates/LICENSE.md /out/licenses/nuclei-templates-LICENSE.md \
 && chmod -R a-w /out/nuclei-templates

# --- build: OP-06D and its dependencies in a venv ---------------------------
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*
COPY docker/requirements.txt docker/build-requirements.txt /tmp/req/
RUN python3 -m venv /opt/op06d \
 && /opt/op06d/bin/pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: \
      -r /tmp/req/requirements.txt \
 && python3 -m venv /opt/build \
 && /opt/build/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: \
      -r /tmp/req/build-requirements.txt
COPY pyproject.toml LICENSE /src/
COPY src /src/src
RUN /opt/build/bin/pip wheel --no-cache-dir --no-deps --no-build-isolation -w /tmp/wheel /src \
 && /opt/op06d/bin/pip install --no-cache-dir --no-deps /tmp/wheel/op06d-*.whl \
 && /opt/op06d/bin/pip check

# --- product: what users pull and run ----------------------------------------
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS product
ARG BASE_IMAGE
ARG NMAP_VERSION=7.93
ARG NMAP_PACKAGE=7.93+dfsg1-1
ARG NUCLEI_VERSION=3.11.1
ARG TEMPLATES_VERSION=v10.5.1
ARG OP06D_VERSION=0.0.3
ARG REVISION=unknown
ARG SOURCE=https://github.com/mastodonsec/OP-06D

LABEL org.opencontainers.image.title="op06d" \
      org.opencontainers.image.description="OP-06D: reconnaissance with nmap and nuclei behind a guardrail gate" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${OP06D_VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.op06d.nmap="${NMAP_VERSION}" \
      org.op06d.nmap-package="${NMAP_PACKAGE}" \
      org.op06d.nuclei="${NUCLEI_VERSION}" \
      org.op06d.nuclei-templates="${TEMPLATES_VERSION}"

# nmap (the plain binary) and python3. weasyprint (PDF reports) needs pango
# and a font. libcap2-bin is only for setcap/getcap below and is removed again.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap=${NMAP_PACKAGE} python3 ca-certificates \
      libpango-1.0-0 libpangoft2-1.0-0 fonts-dejavu-core \
      libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

COPY --from=fetch /out/bin/nuclei /usr/local/bin/nuclei
COPY --from=fetch /out/nuclei-templates /opt/nuclei-templates
COPY --from=build /opt/op06d /opt/op06d

# A second nmap carrying raw-socket file capabilities, for non-root SYN scans.
# OP-06D runs it (with NMAP_PRIVILEGED=1) only when the container was started
# with --cap-add NET_RAW --cap-add NET_ADMIN and without no-new-privileges;
# otherwise the plain /usr/bin/nmap runs (connect scan, reported as degraded).
# Starting a binary whose file capabilities exceed the container's capability
# set fails outright, which is why the plain nmap has none.
RUN mkdir -p /usr/lib/op06d \
 && cp /usr/bin/nmap /usr/lib/op06d/nmap-raw \
 && setcap cap_net_raw,cap_net_admin+eip /usr/lib/op06d/nmap-raw \
 && getcap /usr/lib/op06d/nmap-raw | grep -q 'cap_net_admin,cap_net_raw=eip' \
 && apt-get purge -y --auto-remove libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

# Third-party licenses: AGPL-3.0-or-later for OP-06D, NPSL for nmap (Debian's
# copyright file), MIT for nuclei and the templates. Python dependency licenses
# stay in their dist-info directories under /opt/op06d.
COPY LICENSE NOTICE /usr/share/doc/op06d/
COPY --from=fetch /out/licenses/ /usr/share/doc/op06d/licenses/
RUN chmod 0644 /usr/share/doc/op06d/LICENSE /usr/share/doc/op06d/NOTICE \
 && install -m 0644 /usr/share/doc/nmap/copyright /usr/share/doc/op06d/licenses/nmap-copyright \
 && install -m 0644 /usr/share/doc/op06d/LICENSE /usr/share/doc/op06d/licenses/op06d-LICENSE

# The baked toolchain, recorded from the build arguments and checked against the
# installed binaries, so the report never claims a version that is not here.
# (nmap-raw is compared by checksum: it cannot start during the build, which has
# no NET_ADMIN.)
RUN /usr/bin/nmap --version | grep -q "^Nmap version ${NMAP_VERSION} " \
 && [ "$(sha256sum < /usr/bin/nmap)" = "$(sha256sum < /usr/lib/op06d/nmap-raw)" ] \
 && /usr/local/bin/nuclei -version -disable-update-check 2>&1 | grep -q "v${NUCLEI_VERSION}" \
 && mkdir -p /usr/share/op06d \
 && printf '{"nmap": "%s", "nmap_package": "%s", "nuclei": "%s", "templates_pin": "%s", "template_dir": "/opt/nuclei-templates", "base_image": "%s", "nmap_raw": "/usr/lib/op06d/nmap-raw"}\n' \
      "${NMAP_VERSION}" "${NMAP_PACKAGE}" "${NUCLEI_VERSION}" "${TEMPLATES_VERSION}" "${BASE_IMAGE}" \
      > /usr/share/op06d/toolchain.json \
 && /opt/op06d/bin/python -c "import json; json.load(open('/usr/share/op06d/toolchain.json'))"

RUN useradd --uid 10001 --user-group --no-create-home --home-dir /work --shell /usr/sbin/nologin op06d \
 && mkdir -p /work /out \
 && chown op06d:op06d /work /out

ENV PATH="/opt/op06d/bin:${PATH}" \
    OP06D_TOOLCHAIN=/usr/share/op06d/toolchain.json \
    OP06D_NMAP_RAW=/usr/lib/op06d/nmap-raw \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["op06d"]
CMD ["--help"]

# --- lab: the lab scanner (product image + isolation-check tools + pytest) ---
# Only lab/docker-compose.yml builds this. The toolchain and OP-06D are the
# product's, unchanged; the lab mounts the working tree at /op06d for
# development (PYTHONPATH below puts it ahead of the installed copy).
FROM product AS lab
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl iputils-ping iproute2 netcat-openbsd procps \
 && rm -rf /var/lib/apt/lists/*
COPY docker/requirements-lab.txt /tmp/requirements-lab.txt
RUN /opt/op06d/bin/pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: \
      -r /tmp/requirements-lab.txt \
 && rm /tmp/requirements-lab.txt \
 && /opt/op06d/bin/pip check
# An unprivileged user, used to document nmap's behavior without root.
RUN useradd --create-home --uid 1000 --shell /bin/bash scanner \
 && mkdir -p /captures \
 && chmod 0777 /captures
# The RUNBOOK's version step (Step 5) reads this key=value file.
RUN /opt/op06d/bin/python -c "import json; t = json.load(open('/usr/share/op06d/toolchain.json')); \
print(f\"nmap={t['nmap_package']}\nnuclei={t['nuclei']}\nnuclei-templates={t['templates_pin']}\nbase={t['base_image']}\")" \
      > /opt/lab-versions.txt
ENV PYTHONPATH="/op06d/src"
WORKDIR /op06d
ENTRYPOINT []
CMD ["sleep", "infinity"]

# --- default target: the product image ---------------------------------------
FROM product
