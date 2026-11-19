# Releasing the OP-06D image

A release is a git tag `v<version>` on `main`. The tag starts
`.github/workflows/release.yml`, which builds `linux/amd64` and `linux/arm64`,
pushes `ghcr.io/mastodonsec/op06d:<version>` and
`ghcr.io/mastodonsec/op06d:<version>-nmap7.93-nuclei3.11.1-tpl10.5.1`, attaches
an SBOM and build provenance, and signs the image keyless with cosign.

Every pull request and push to `main` already runs `.github/workflows/ci.yml`:
the repository hygiene guard (`scripts/check_repo_hygiene.py`), the test suite,
and an image build and check for each architecture (never pushed).

## 1. Bump the pins (when the toolchain changes)

All pins are in the repository `Dockerfile`:

| Pin | Where it comes from |
|---|---|
| `BASE_IMAGE` digest | `docker buildx imagetools inspect debian:bookworm-slim` |
| `NMAP_PACKAGE`, `NMAP_VERSION` | the Debian bookworm package version |
| `NUCLEI_VERSION`, `NUCLEI_ZIP_SHA256_AMD64`, `NUCLEI_ZIP_SHA256_ARM64` | the release's `nuclei_<version>_checksums.txt` |
| `TEMPLATES_VERSION`, `TEMPLATES_TARBALL_SHA256` | `sha256sum` of the nuclei-templates tag tarball |

The template set is pinned, so it only gets newer templates through this step:
re-pin it at each release to keep detection current. When the templates
change, also:

- regenerate the write-method exclusion list
  (`scripts/generate_nuclei_write_method_exclusions.py`, run against the new
  set) and review the ids it adds or removes;
- update the toolchain tag (`TOOLCHAIN_TAG` in
  `.github/workflows/release.yml`), the pins in
  `scripts/check_image.py` (`EXPECTED_PINS`) and the lab's
  `--templates-pin`/version flags in `lab/model_relay.py`.

When Python dependencies change (`uv.lock`), regenerate the image's
requirement files (`docker/requirements.txt`, `docker/requirements-lab.txt`,
`docker/build-requirements.txt`):

```bash
uv run python scripts/update_docker_requirements.py
```

CI's `requirements` job runs the same script with `--check` and fails while
they disagree with `uv.lock`. setuptools (the wheel's build backend) is not in
`uv.lock`; bump it with `--setuptools <version>`.

Dependabot (`.github/dependabot.yml`) opens pull requests for `uv.lock`, the
workflows' pinned actions and the base image digest. Its uv entry excludes
`docker/`, so a uv pull request only touches `pyproject.toml` and `uv.lock`,
and every one of them fails the `requirements` job until you run the command
above on its branch, commit the result with `git commit -s` and push; the job
then passes. pydantic and pydantic-core arrive together in one grouped pull
request, because pydantic pins pydantic-core exactly. Security updates come
the same way and take the same regenerate step. On a base image pull request,
also set `ARG BASE_IMAGE` in the `Dockerfile` to the new `FROM` reference
(`tests/test_container_image.py` fails until it matches).

Set the new version in `pyproject.toml` (`[project] version`). The release
workflow refuses a tag that does not match it.

## 2. Rebuild

```bash
docker buildx build --platform linux/amd64 --load -t op06d:local .
python3 scripts/check_image.py op06d:local
```

A checksum mismatch fails the build: investigate it, never wave it through.

## 3. Run the lab against the new image

Follow [lab/RUNBOOK.md](../lab/RUNBOOK.md): rebuild the scanner
(`docker compose -f lab/docker-compose.yml build scanner`), pass the isolation
gate (Step 4), and run the repeatability test and an `op06d run` with the
installed copy (`OP06D_LAB_CODE=./installed-only`, see "Mounted code and the
installed copy"). A new template pin changes what nuclei finds: if the
repeatability baseline does not match, reconcile it deliberately before
releasing.

## 4. Tag

On `main`, after the pull request has merged and its CI passed:

```bash
git tag -s v<version> -m "OP-06D <version>"
git push origin v<version>
```

## 5. Verify the published image

Take the digest from the release workflow's summary, then run the commands
in [container.md](container.md#verify-the-image): `cosign verify` with the
release workflow's identity, and the SBOM and provenance with
`docker buildx imagetools inspect`. Then pull it on the target hosts and run
`docker run --rm ghcr.io/mastodonsec/op06d@sha256:<digest> version`.
