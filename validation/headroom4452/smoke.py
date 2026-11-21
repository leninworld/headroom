#!/usr/bin/env python3
"""Non-counted preparation-only smoke for Headroom #4452 attempt 26.

Builds each lane image from the frozen PR head and runs version probes only.
It never applies a patch and never runs project tests.
"""
import sys

if sys.flags.optimize:
    raise SystemExit("OPTIMIZE_FORBIDDEN")
sys.dont_write_bytecode = True

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402

HERE = Path(__file__).resolve().parent
SPEC_PATH = HERE / "spec.json"
LANES = ("source-gates", "python-proof", "rust-workspace", "ci-python-commitlint")
BOOKWORM_APT_PACKAGES = frozenset({
    "build-essential", "ca-certificates", "cmake", "curl", "git", "make", "nodejs", "npm",
    "patchelf", "pkg-config",
})


class Stop(RuntimeError):
    pass


def need(value, message):
    if not value:
        raise Stop(message)


def strict_json(path):
    def reject(value):
        raise ValueError("non-finite JSON: " + value)
    return json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=reject)


def save(path, value):
    text = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    json.loads(text)
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def bounded(argv, *, timeout, cap=64 * 1024 * 1024):
    begin = time.monotonic()
    proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout, check=False)
    need(len(proc.stdout) <= cap, "OUTPUT_CAP")
    return {"argv": argv, "exit": proc.returncode,
            "elapsed_monotonic_seconds": time.monotonic() - begin,
            "output": proc.stdout.decode("utf-8", "replace")}


def validate_bookworm_apt_packages(text):
    marker = "apt-get install -y --no-install-recommends "
    lines = [line for line in text.splitlines() if marker in line]
    need(len(lines) == 1, "APT_INSTALL_FORM")
    requested = frozenset(lines[0].split(marker, 1)[1].split("&&", 1)[0].strip().split())
    missing = sorted(requested - BOOKWORM_APT_PACKAGES)
    need(not missing, "APT_PACKAGE_NOT_IN_BOOKWORM " + ",".join(missing))
    need(requested == BOOKWORM_APT_PACKAGES, "APT_PACKAGE_SET")
    return sorted(requested)


def dockerfile(spec):
    enc = json.dumps(spec["tiktoken_encodings"])
    model = spec["model"]
    text = f'''FROM {spec["rust_image"]} AS rust-toolchain
RUN rustup component add rustfmt clippy --toolchain 1.95.0 \\
 && rustc --version | grep -E '^rustc {spec["rust"]} \\([0-9a-f]+ [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}\\)$' \\
 && cargo --version && rustfmt --version && cargo clippy --version

FROM {spec["container_image"]}
ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 \\
    PATH=/usr/local/cargo/bin:/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \\
    RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates cmake curl git make nodejs npm patchelf pkg-config && rm -rf /var/lib/apt/lists/*
RUN rustc --version | grep -E '^rustc {spec["rust"]} \\([0-9a-f]+ [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}\\)$' \\
 && cargo --version && rustfmt --version && cargo clippy --version \\
 && node_major="$(node --version | sed -E 's/^v([0-9]+).*/\\1/')" && test "$node_major" -ge 18 \\
 && npm --version
WORKDIR /src
COPY . /src
RUN uv venv /opt/venv --python 3.12 && UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --extra dev --extra langchain --extra proxy --no-install-project && uv pip install --python /opt/venv/bin/python "maturin>=1.5,<2.0" && /opt/venv/bin/maturin --version
RUN /opt/venv/bin/python - <<'PY'
import pathlib
import onnxruntime

version = tuple(int(part) for part in onnxruntime.__version__.split('.')[:2])
assert version >= (1, 24), onnxruntime.__version__
capi = pathlib.Path(onnxruntime.__file__).parent / "capi"
libs = sorted(capi.glob("libonnxruntime.so*"))
assert libs, capi
target = pathlib.Path("/opt/onnxruntime")
target.mkdir()
(target / "libonnxruntime.so").symlink_to(libs[0])
print(f"onnxruntime {{onnxruntime.__version__}} -> {{libs[0]}}")
PY
ENV ORT_DYLIB_PATH=/opt/onnxruntime/libonnxruntime.so
RUN cargo fetch --locked
RUN mkdir -p /opt/hf /opt/tiktoken /opt/precommit /opt/npm-cache /opt/work && HOME=/opt/work PRE_COMMIT_HOME=/opt/precommit /opt/venv/bin/pre-commit install-hooks
RUN npm_config_cache=/opt/npm-cache npx --yes --package=@commitlint/cli@{spec["commitlint"]} --package=@commitlint/config-conventional@{spec["commitlint"]} -- commitlint --version
RUN HF_HOME=/opt/hf HF_HUB_DISABLE_TELEMETRY=1 HF_HUB_DISABLE_IMPLICIT_TOKEN=1 /opt/venv/bin/python - <<'PY'
from huggingface_hub import snapshot_download
path = snapshot_download({model["repo"]!r}, revision={model["revision"]!r})
assert path.endswith({model["revision"]!r}), path
PY
RUN TIKTOKEN_CACHE_DIR=/opt/tiktoken /opt/venv/bin/python - <<'PY'
import tiktoken
for name in {enc}:
    tiktoken.get_encoding(name)
PY
'''
    validate_bookworm_apt_packages(text)
    return text


def inspect_image(reference):
    result = bounded(["docker", "image", "inspect", reference, "--format", "{{json .}}"], timeout=30)
    need(result["exit"] == 0, "IMAGE_INSPECT " + reference)
    info = json.loads(result["output"])
    image_id = info.get("Id")
    repo_digests = info.get("RepoDigests", [])
    need(isinstance(image_id, str) and image_id.startswith("sha256:"), "IMAGE_ID " + reference)
    need(isinstance(repo_digests, list) and all(isinstance(x, str) for x in repo_digests),
         "REPO_DIGESTS " + reference)
    return {"reference": reference, "id": image_id, "repo_digests": sorted(repo_digests)}


def resolved_images(spec, lane_tag):
    images = {
        "rust_base": inspect_image(spec["rust_image"]),
        "container_base": inspect_image(spec["container_image"]),
        "lane": inspect_image(lane_tag),
    }
    for key in ("rust_base", "container_base"):
        digest = images[key]["reference"].rsplit("@", 1)[1]
        need(any(value.endswith("@" + digest) for value in images[key]["repo_digests"]),
             "PINNED_REPO_DIGEST " + key)
    return images


def rust_component_versions(output):
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    rustfmt = next((line for line in lines if line.startswith("rustfmt ")), None)
    clippy = next((line for line in lines if line.startswith("clippy ")), None)
    need(rustfmt is not None and clippy is not None, "RUST_COMPONENT_VERSION_EVIDENCE")
    return {"rustfmt": rustfmt, "clippy": clippy}


def run(args):
    spec = strict_json(SPEC_PATH)
    need(args.lane in LANES and spec["lanes"] == list(LANES), "LANE")
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    try:
        dockerfile_path = evidence / "Dockerfile"
        dockerfile_path.write_text(dockerfile(spec), encoding="utf-8")
        tag = "headroom4452-a26b-smoke-" + args.lane
        prep = bounded(["docker", "build", "--pull", "--network", "default", "-f",
                        str(dockerfile_path), "-t", tag, str(Path(args.source))], timeout=50 * 60)
        (evidence / "preparation.log").write_text(prep.pop("output"), encoding="utf-8")
        save(evidence / "preparation.json", prep)
        need(prep["exit"] == 0, "P0_PREPARATION")
        images = resolved_images(spec, tag)
        save(evidence / "resolved-images.json", {"lane": args.lane, "images": images})
        probe = bounded(["docker", "run", "--rm", "--network", "none", tag, "bash", "-lc",
                         "rustc --version && cargo --version && rustfmt --version && "
                         "cargo clippy --version && node --version && npm --version && "
                         "npx --offline --yes --package=@commitlint/cli@19.8.1 "
                         "--package=@commitlint/config-conventional@19.8.1 -- commitlint --version && "
                         "python --version && uv --version && pre-commit --version && "
                         "maturin --version"], timeout=5 * 60)
        probe_output = probe.pop("output")
        component_versions = rust_component_versions(probe_output)
        (evidence / "version-probes.log").write_text(probe_output, encoding="utf-8")
        save(evidence / "version-probes.json", probe)
        need(probe["exit"] == 0, "VERSION_PROBES")
        save(evidence / "smoke-summary.json", {"schema": "headroom4452-a26b-smoke-lane/1",
             "lane": args.lane, "status": "PASS", "counted_attempt": False,
             "project_tests_run": False, "candidate_patch_applied": False,
             "resolved_images": images,
             "rust_components": component_versions,
             "elapsed_monotonic_seconds": time.monotonic() - started})
        return 0
    except (Stop, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        save(evidence / "smoke-summary.json", {"schema": "headroom4452-a26b-smoke-lane/1",
             "lane": args.lane, "status": "FAIL", "counted_attempt": False,
             "project_tests_run": False, "candidate_patch_applied": False,
             "error": type(exc).__name__ + ": " + str(exc)[:2000],
             "elapsed_monotonic_seconds": time.monotonic() - started})
        return 4


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lane", required=True, choices=LANES)
    parser.add_argument("--source", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
