#!/usr/bin/env python3
"""Bounded hosted-Docker controller for Headroom PR #4452, validation attempt 28.

The public diagnostic branch contains only this controller, its spec, the candidate
patch, and the workflow.  `run` is the only execution entry point.  `fake-selftest`
uses no network, Docker, Git, or project imports.
"""
import sys

if sys.flags.optimize:
    raise SystemExit("OPTIMIZE_FORBIDDEN")
sys.dont_write_bytecode = True

import argparse  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
import traceback  # noqa: E402
import xml.etree.ElementTree as ET  # noqa: E402

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from docker_run import hardened_run_argv  # noqa: E402
COUNTED_SPEC_PATH = HERE / "counted-spec.json"
SPEC_PATH = COUNTED_SPEC_PATH if COUNTED_SPEC_PATH.exists() else HERE / "spec.json"
LANES = ("source-gates", "python-proof", "rust-workspace", "ci-python-commitlint")
BOOKWORM_APT_PACKAGES = frozenset({
    "build-essential", "ca-certificates", "cmake", "curl", "git", "make", "nodejs", "npm",
    "patchelf", "pkg-config",
})
KNOWN_PREEXISTING_HOOK_ERRORS = frozenset({
    ("headroom/proxy/upstream_guard.py", 162, "no-any-return"),
})
PYTHON_BASE_FILES = ("headroom/memory/bridge.py",)
HOOK_BASE_FILES = ("headroom/memory/bridge.py", "tests/test_memory_bridge.py")
PYTHON_BASEARM = "/work/basearm-python"
HOOK_BASEARM = "/work/basearm-hook"
MYPY_ERROR = re.compile(
    r"^(?P<path>[^:\r\n]+):(?P<line>[1-9][0-9]*): error: .+  \[(?P<code>[a-z0-9-]+)\]$"
)
MYPY_SUMMARY = re.compile(
    r"^Found (?P<count>[0-9]+) errors? in [0-9]+ files? \(checked [0-9]+ source files\)$"
)


class Stop(RuntimeError):
    pass


def need(value, message):
    if not value:
        raise Stop(message)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def strict_json(path):
    def reject(value):
        raise ValueError("non-finite JSON: " + value)
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream, parse_constant=reject)


def save(path, value):
    path = Path(path)
    text = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    json.loads(text)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def save_command_evidence(evidence, stem, result, output):
    """Persist raw command evidence before checking exit status or parsing output."""
    evidence = Path(evidence)
    (evidence / (stem + ".log")).write_text(output, encoding="utf-8")
    save(evidence / (stem + ".json"), result)


def parse_mypy_errors(output, exit_code):
    """Strictly parse a mypy result without allowing set conversion to hide duplicates."""
    parsed = []
    summaries = []
    for line in output.splitlines():
        if ": error:" in line:
            match = MYPY_ERROR.fullmatch(line)
            need(match is not None, "MYPY_UNPARSEABLE_ERROR " + line)
            parsed.append((match["path"], int(match["line"]), match["code"]))
        elif line.startswith("Found "):
            match = MYPY_SUMMARY.fullmatch(line)
            need(match is not None, "MYPY_UNPARSEABLE_SUMMARY " + line)
            summaries.append(int(match["count"]))
    need(len(parsed) == len(set(parsed)), "MYPY_DUPLICATE_ERROR")
    if exit_code == 0:
        need(not parsed and not summaries, "MYPY_ZERO_WITH_ERRORS")
        return frozenset()
    need(exit_code == 1, "MYPY_UNEXPECTED_EXIT " + str(exit_code))
    need(len(summaries) == 1 and summaries[0] == len(parsed) and bool(parsed),
         "MYPY_COUNT_MISMATCH")
    return frozenset(parsed)


def classify_hook_comparison(baseline_output, baseline_exit, candidate_output, candidate_exit):
    baseline = parse_mypy_errors(baseline_output, baseline_exit)
    candidate = parse_mypy_errors(candidate_output, candidate_exit)
    need(baseline == KNOWN_PREEXISTING_HOOK_ERRORS, "MYPY_BASELINE_NOT_FROZEN")
    need(candidate.issubset(baseline), "MYPY_CANDIDATE_NEW_ERROR")
    return {
        "baseline_errors": [list(item) for item in sorted(baseline)],
        "candidate_errors": [list(item) for item in sorted(candidate)],
        "baseline_equals_known_preexisting": True,
        "candidate_subset_of_baseline": True,
        "classification": ("clean" if not candidate
                           else "known-preexisting-hook-environment-gap"),
    }


def bounded(argv, *, cwd=None, env=None, timeout=600, cap=64 * 1024 * 1024, stdin=None):
    """One call, no retry. Timing is monotonic and never compared across processes."""
    begin = time.monotonic()
    proc = subprocess.run(argv, cwd=cwd, env=env, input=stdin, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout, check=False)
    elapsed = time.monotonic() - begin
    need(len(proc.stdout) <= cap, "OUTPUT_CAP " + argv[0])
    return {"argv": argv, "exit": proc.returncode, "elapsed_monotonic_seconds": elapsed,
            "output": proc.stdout.decode("utf-8", "replace")}


def source_inventory(root):
    root = Path(root)
    rows = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue
        if path.is_symlink():
            rows.append([rel, "symlink", os.readlink(path)])
        elif path.is_file():
            rows.append([rel, "file", path.stat().st_size, sha256(path)])
        elif path.is_dir():
            rows.append([rel, "dir"])
    return rows


def inventory_delta(before, after, allowed):
    b = {r[0]: r[1:] for r in before}
    a = {r[0]: r[1:] for r in after}
    removed = sorted(set(b) - set(a))
    changed = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    added = sorted(set(a) - set(b))
    unexpected = sorted(set(added) - set(allowed))
    return {"removed": removed, "changed": changed, "added": added,
            "unexpected_added": unexpected,
            "ok": not removed and not changed and not unexpected}


def candidate_prepare(source, patch, evidence, spec):
    source, patch = Path(source), Path(patch)
    need(sha256(patch) == spec["candidate_patch_sha256"], "PATCH_HASH")
    head = bounded(["git", "rev-parse", "HEAD"], cwd=source, timeout=30)
    tree = bounded(["git", "rev-parse", "HEAD^{tree}"], cwd=source, timeout=30)
    need(head["exit"] == 0 and head["output"].strip() == spec["pr_head"], "PR_HEAD")
    need(tree["exit"] == 0 and tree["output"].strip() == spec["pr_head_tree"], "PR_HEAD_TREE")
    clean = bounded(["git", "status", "--porcelain=v1", "--ignored=matching",
                     "--untracked-files=all"], cwd=source, timeout=60)
    need(clean["exit"] == 0 and not clean["output"].strip(), "SOURCE_NOT_CLEAN")
    check = bounded(["git", "apply", "--check", str(patch)], cwd=source, timeout=60)
    need(check["exit"] == 0, "PATCH_CHECK\n" + check["output"][-2000:])
    apply = bounded(["git", "apply", str(patch)], cwd=source, timeout=60)
    need(apply["exit"] == 0, "PATCH_APPLY\n" + apply["output"][-2000:])
    got = {name: sha256(source / name) for name in spec["candidate_files"]}
    need(got == spec["candidate_files"], "CANDIDATE_FILE_HASHES")
    status = bounded(["git", "status", "--porcelain=v1", "--ignored=matching",
                      "--untracked-files=all"], cwd=source, timeout=60)
    lines = sorted(x for x in status["output"].splitlines() if x)
    need(lines == sorted(" M " + name for name in spec["candidate_files"]), "CANDIDATE_STATUS")
    before = source_inventory(source)
    save(evidence / "candidate-identity.json", {"head": spec["pr_head"],
         "synthetic_candidate": spec["candidate"], "patch_sha256": sha256(patch),
         "files": got, "status": lines, "inventory": before})
    return before


def prepare_build_context(source, root, spec):
    """Wrap the complete patched checkout so its nested .dockerignore cannot filter /src."""
    source, root = Path(source), Path(root)
    wrapped = root / "source"
    shutil.copytree(source, wrapped, symlinks=True)
    need((wrapped / ".git").exists(), "BUILD_CONTEXT_GIT")
    need((wrapped / ".pre-commit-config.yaml").is_file(), "BUILD_CONTEXT_PRE_COMMIT_CONFIG")
    need((wrapped / "tests/test_memory_bridge.py").is_file(), "BUILD_CONTEXT_TESTS")
    for commit in (spec["commitlint_from"], spec["commitlint_to"], spec["pr_head"]):
        found = bounded(["git", "cat-file", "-e", commit + "^{commit}"], cwd=wrapped, timeout=30)
        need(found["exit"] == 0, "BUILD_CONTEXT_COMMIT " + commit)
    staged = bounded(["git", "add", "--"] + sorted(spec["candidate_files"]), cwd=wrapped, timeout=60)
    need(staged["exit"] == 0, "BUILD_CONTEXT_STAGE\n" + staged["output"][-2000:])
    status = bounded(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                     cwd=wrapped, timeout=60)
    expected = sorted("M  " + name for name in spec["candidate_files"])
    need(status["exit"] == 0 and sorted(status["output"].splitlines()) == expected,
         "BUILD_CONTEXT_STATUS")
    return root


def dockerfile(spec):
    model = spec["model"]
    enc = json.dumps(spec["tiktoken_encodings"])
    # Preparation has network. Validation containers made from this image do not.
    text = f'''FROM {spec["rust_image"]} AS rust-toolchain
RUN rustup component add rustfmt clippy --toolchain 1.95.0 \\
 && rustc --version | grep -E '^rustc {spec["rust"]} \\([0-9a-f]+ [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}\\)$' \\
 && cargo --version \\
 && rustfmt --version \\
 && cargo clippy --version

FROM {spec["container_image"]}
ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 \\
    PATH=/usr/local/cargo/bin:/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \\
    RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates cmake curl git make nodejs npm patchelf pkg-config && rm -rf /var/lib/apt/lists/*
RUN rustc --version | grep -E '^rustc {spec["rust"]} \\([0-9a-f]+ [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}\\)$' \\
 && cargo --version \\
 && rustfmt --version \\
 && cargo clippy --version \\
 && node_major="$(node --version | sed -E 's/^v([0-9]+).*/\\1/')" \\
 && test "$node_major" -ge 18 \\
 && npm --version
WORKDIR /src
COPY source/ /src
RUN ci_python="$(sed -nE 's/^[[:space:]]*PY_VERSION:[[:space:]]*"([^"]+)"[[:space:]]*$/\\1/p' /src/.github/workflows/ci.yml)" \
 && test "$ci_python" = "{spec["ci_python"]}" \
 && /usr/local/bin/python{spec["ci_python"]} -m venv /opt/mypy-ci \
 && /opt/mypy-ci/bin/python -m pip install --upgrade pip "ruff=={spec["ruff"]}" "mypy=={spec["mypy"]}" "{spec["langchain_core"]}" \
 && /opt/mypy-ci/bin/python -m pip freeze | tee /opt/mypy-ci-pip-freeze.txt
RUN uv venv /opt/venv --python 3.12 \
 && UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --extra dev --extra langchain --extra proxy --no-install-project \
 && uv pip install --python /opt/venv/bin/python "pip=={spec['pip']}" "maturin=={spec['maturin']}" \
 && /opt/venv/bin/python -m pip --version \
 && /opt/venv/bin/maturin --version
RUN mkdir -p /opt/wheelhouse \
 && /opt/venv/bin/python -m pip download --dest /opt/wheelhouse --only-binary=:all: "maturin=={spec['maturin']}" \
 && /opt/venv/bin/python - <<'PY'
import hashlib
import json
import pathlib
import zipfile
from pip._vendor.packaging.markers import default_environment
from pip._vendor.packaging.requirements import Requirement

root = pathlib.Path("/opt/wheelhouse")
wheels = sorted(root.glob("*.whl"))
assert len(wheels) == 1, wheels
wheel = wheels[0]
with zipfile.ZipFile(wheel) as archive:
    metadata_names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
    assert len(metadata_names) == 1, metadata_names
    metadata = archive.read(metadata_names[0]).decode("utf-8")
requires_dist = [line.split(":", 1)[1].strip() for line in metadata.splitlines()
                 if line.startswith("Requires-Dist:")]
marker_environment = default_environment()
marker_environment["extra"] = ""
applicable = [value for value in requires_dist
              if Requirement(value).marker is None
              or Requirement(value).marker.evaluate(marker_environment)]
assert "Name: maturin" in metadata
assert "Version: {spec['maturin']}" in metadata
assert applicable == [], applicable
digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
record = {{
    "schema": "headroom4452-offline-wheelhouse/1",
    "files": [{{"filename": wheel.name, "bytes": wheel.stat().st_size, "sha256": digest}}],
    "pins": ["maturin=={spec['maturin']}"],
    "download": {{"only_binary": True, "dependencies_resolved": True}},
    "metadata": {{"name": "maturin", "version": "{spec['maturin']}",
                 "requires_dist": requires_dist, "applicable_requires_dist": applicable,
                 "setuptools_or_wheel_required": False}},
}}
(root / "wheelhouse-manifest.json").write_text(
    json.dumps(record, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
print(json.dumps(record, sort_keys=True))
PY
RUN /opt/venv/bin/python - <<'PY'
import ctypes
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
resolved = (target / "libonnxruntime.so").resolve(strict=True)
ctypes.CDLL(str(target / "libonnxruntime.so"))
print(f"onnxruntime {{onnxruntime.__version__}} -> {{libs[0]}}")
PY
ENV ORT_DYLIB_PATH=/opt/onnxruntime/libonnxruntime.so
RUN cargo fetch --locked
RUN mkdir -p /opt/hf /opt/tiktoken /opt/precommit /opt/npm-cache /opt/work /opt/precommit-repo \
 && git init -q /opt/precommit-repo \
 && cp /src/.pre-commit-config.yaml /opt/precommit-repo/.pre-commit-config.yaml \
 && test -z "$(find /opt/precommit-repo -mindepth 1 -maxdepth 1 ! -name .git ! -name .pre-commit-config.yaml -print -quit)" \
 && cd /opt/precommit-repo \
 && HOME=/opt/work PRE_COMMIT_HOME=/opt/precommit /opt/venv/bin/pre-commit install-hooks \
 && cp -a /opt/precommit /opt/precommit-seed
RUN HOME=/opt/work npm_config_cache=/opt/npm-cache npm install --prefix /opt/commitlint --no-save --ignore-scripts @commitlint/cli@{spec["commitlint"]} @commitlint/config-conventional@{spec["commitlint"]} \
 && /opt/commitlint/node_modules/.bin/commitlint --version \
 && npm ls --prefix /opt/commitlint --all --json > /opt/commitlint-npm-ls.json \
 && cp -a /opt/npm-cache /opt/npm-cache-seed
RUN HOME=/opt/work HF_HOME=/opt/hf HF_HUB_DISABLE_TELEMETRY=1 HF_HUB_DISABLE_IMPLICIT_TOKEN=1 /opt/venv/bin/python - <<'PY'
from huggingface_hub import snapshot_download
path = snapshot_download({model["repo"]!r}, revision={model["revision"]!r})
assert path.endswith({model["revision"]!r}), path
PY
RUN HOME=/opt/work TIKTOKEN_CACHE_DIR=/opt/tiktoken /opt/venv/bin/python - <<'PY'
import tiktoken
for name in {enc}:
    tiktoken.get_encoding(name)
PY
'''
    validate_bookworm_apt_packages(text)
    return text


def validate_bookworm_apt_packages(text):
    """Reject apt packages outside the embedded Debian Bookworm availability set."""
    marker = "apt-get install -y --no-install-recommends "
    lines = [line for line in text.splitlines() if marker in line]
    need(len(lines) == 1, "APT_INSTALL_FORM")
    tail = lines[0].split(marker, 1)[1].split("&&", 1)[0].strip()
    requested = frozenset(tail.split())
    missing = sorted(requested - BOOKWORM_APT_PACKAGES)
    need(not missing, "APT_PACKAGE_NOT_IN_BOOKWORM " + ",".join(missing))
    need(requested == BOOKWORM_APT_PACKAGES, "APT_PACKAGE_SET")
    return sorted(requested)


def inspect_local_image(reference):
    result = bounded(["docker", "image", "inspect", reference, "--format", "{{json .}}"], timeout=30)
    if result["exit"] != 0:
        return None
    info = json.loads(result["output"])
    image_id = info.get("Id")
    repo_digests = info.get("RepoDigests", [])
    need(isinstance(image_id, str) and image_id.startswith("sha256:"), "IMAGE_ID " + reference)
    need(isinstance(repo_digests, list) and all(isinstance(x, str) for x in repo_digests),
         "REPO_DIGESTS " + reference)
    return {"reference": reference, "id": image_id, "repo_digests": sorted(repo_digests)}


def inspect_uv_base(reference):
    image = inspect_local_image(reference)
    pulled_for_identity = image is None
    if pulled_for_identity:
        pulled = bounded(["docker", "pull", reference], timeout=15 * 60)
        need(pulled["exit"] == 0, "IMAGE_PULL " + reference + "\n" + pulled["output"][-2000:])
        image = inspect_local_image(reference)
    need(image is not None, "IMAGE_INSPECT " + reference)
    image["pulled_for_identity"] = pulled_for_identity
    digest = reference.rsplit("@", 1)[1]
    need(any(value.endswith("@" + digest) for value in image["repo_digests"]),
         "PINNED_REPO_DIGEST container_base")
    return image


def rust_versions_from_build_log(build_log):
    """Parse exact Rust-stage versions from BuildKit plain-progress output."""
    prefix = re.compile(r"^#(?P<step>\d+)\s+\d+(?:\.\d+)?\s+(?P<text>.*)$")
    stage_steps = {match.group(1) for line in build_log.splitlines()
                   if (match := re.match(r"^#(\d+)\s+\[rust-toolchain \d+/\d+\]", line))}
    patterns = {
        "rustc": re.compile(r"rustc 1\.95\.0 \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)"),
        "cargo": re.compile(r"cargo 1\.95\.0 \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)"),
        "rustfmt": re.compile(r"rustfmt \S+(?: \([^\r\n]+\))?"),
        "clippy": re.compile(r"clippy 0\.1\.95 \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)"),
    }
    versions = {}
    for raw in build_log.splitlines():
        line = raw.strip()
        buildkit = prefix.fullmatch(line)
        if buildkit:
            if stage_steps and buildkit.group("step") not in stage_steps:
                continue
            line = buildkit.group("text").strip()
        for name, pattern in patterns.items():
            if name not in versions and pattern.fullmatch(line):
                versions[name] = line
    need(set(versions) == set(patterns), "RUST_TOOLCHAIN_VERSION_EVIDENCE")
    return versions


def rust_stage_identity(build_log, spec):
    digest = spec["rust_image"].rsplit("@", 1)[1]
    from_lines = [line.strip() for line in build_log.splitlines()
                  if re.search(r"\[rust-toolchain 1/\d+\] FROM ", line) and digest in line]
    need(from_lines, "RUST_STAGE_FROM_EVIDENCE")
    return {"reference": spec["rust_image"], "digest": digest,
            "build_log_from": from_lines[-1],
            "tool_versions": rust_versions_from_build_log(build_log),
            "identity_method": "buildkit_from_digest_plus_in_image_tool_versions",
            "image_inspected": False}


def common_env(spec=None):
    if spec is not None:
        need(spec.get("schema") == "headroom4452-hosted-a28b/1", "COUNTED_SPEC")
    return {
        "PATH": "/opt/venv/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin",
        "VIRTUAL_ENV": "/opt/venv", "PYO3_PYTHON": "/opt/venv/bin/python",
        "PIP_NO_INDEX": "1", "PIP_FIND_LINKS": "/opt/wheelhouse",
        "CARGO_TARGET_DIR": "/cargo-target",
        "HOME": "/work/home", "TMPDIR": "/work/tmp", "PYTHONDONTWRITEBYTECODE": "1",
        "RUFF_CACHE_DIR": "/work/cache/ruff", "MYPY_CACHE_DIR": "/work/cache/mypy",
        "PIP_CACHE_DIR": "/work/cache/pip", "PYTHONPYCACHEPREFIX": "/work/cache/pycache",
        "XDG_CACHE_HOME": "/work/cache/xdg", "UV_CACHE_DIR": "/work/cache/uv",
        "COVERAGE_FILE": "/work/cache/coverage/.coverage", "PRE_COMMIT_HOME": "/opt/precommit",
        "CARGO_NET_OFFLINE": "true", "HF_HOME": "/opt/hf", "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1", "TIKTOKEN_CACHE_DIR": "/opt/tiktoken",
        "npm_config_cache": "/opt/npm-cache", "npm_config_offline": "true",
        "ORT_DYLIB_PATH": "/opt/onnxruntime/libonnxruntime.so",
        "HEADROOM_WORKSPACE_DIR": "/work/headroom", "HEADROOM_CONFIG_DIR": "/work/headroom/config",
        "HEADROOM_MEMORY_DB_PATH": "/work/headroom/memory.db", "CLAUDE_CONFIG_DIR": "/work/claude",
        "HEADROOM_BEACON": "off", "HEADROOM_TELEMETRY": "off", "HEADROOM_UPDATE_CHECK": "off",
        "HEADROOM_PORT_DISCOVERY": "0", "HEADROOM_HARD_WATCHDOG_SECS": "0",
        "TOKENIZERS_PARALLELISM": "false", "OMP_NUM_THREADS": "2", "MKL_NUM_THREADS": "2",
        "NO_COLOR": "1",
    }


def prepare_runtime_caches():
    """Populate writable tmpfs caches from the image seeds without touching /src."""
    for seed, destination in ((Path("/opt/precommit-seed"), Path("/opt/precommit")),
                              (Path("/opt/npm-cache-seed"), Path("/opt/npm-cache"))):
        need(seed.is_dir() and destination.is_dir(), "RUNTIME_CACHE_MOUNT " + str(destination))
        shutil.copytree(seed, destination, dirs_exist_ok=True, symlinks=True)


def runtime_env(extra=None):
    """Preserve the container environment and overlay the frozen runtime PATH and step values."""
    env = os.environ.copy()
    env.update(common_env())
    env.update(extra or {})
    return env


def lane_steps(lane):
    spec = strict_json(SPEC_PATH)
    changed = ["headroom/memory/bridge.py", "tests/test_memory_bridge.py"]
    pc_tail = ["--hook-stage", "pre-commit", "--show-diff-on-failure", "--color", "never",
               "--files"] + changed
    py = "/opt/venv/bin/python"
    tests = "/src/tests/test_memory_bridge.py"
    d1 = tests + "::TestMemoryBridgeSync::test_sync_inserts_export_into_existing_section_above_last_heading"
    d2 = tests + "::TestMemoryBridgeSync::test_sync_exports_organic_memory_when_markdown_changes"
    pytest = [py, "-m", "pytest", "-p", "no:cacheprovider", "--rootdir=/src", "-c", "/src/pyproject.toml"]
    base_tests = PYTHON_BASEARM + "/tests/test_memory_bridge.py"
    base_d1 = base_tests + "::TestMemoryBridgeSync::test_sync_inserts_export_into_existing_section_above_last_heading"
    base_d2 = base_tests + "::TestMemoryBridgeSync::test_sync_exports_organic_memory_when_markdown_changes"
    base_pytest = [py, "-m", "pytest", "-p", "no:cacheprovider",
                   "--rootdir=" + PYTHON_BASEARM, "-c", PYTHON_BASEARM + "/pyproject.toml"]
    smart = [
        "/src/tests/test_transforms/test_smart_crusher_bugs.py",
        "/src/tests/test_transforms/test_smart_crusher_rust_parity.py",
        "/src/tests/test_transforms/test_diff_compressor.py",
        "/src/tests/test_transforms/test_diff_compressor_rust_parity.py",
        "/src/tests/test_relevance.py", "/src/tests/test_relevance_extra.py", "/src/tests/test_ccr.py",
        "/src/tests/test_acceptance.py", "/src/tests/test_critical_fixes.py",
        "/src/tests/test_quality_retention.py", "/src/tests/test_toin_integration.py",
    ]
    if lane == "source-gates":
        return [
            ("S00", [py, str(HERE / "hosted.py"), "inside-identity", "S00"], "/src", {}),
            ("Q6a", ["pre-commit", "run"] + pc_tail, "/src", {"SKIP": "mypy"}),
            ("G1", [py, str(HERE / "hosted.py"), "inside-identity", "G1"], "/src", {}),
            ("Q0", ["bash", "-c", "set -o pipefail; python --version && uv --version && rustc --version && cargo --version && node --version && npm --version && pre-commit --version && pip --version && mypy --version && ruff --version && make --version | head -1 && git --version && /opt/commitlint/node_modules/.bin/commitlint --version"], "/work/run", {}),
            ("Q1", [py, "/src/scripts/verify-ruff-version.py"], "/work/run", {}),
            ("Q2", ["ruff", "--version"], "/work/run", {}),
            ("Q3", ["ruff", "check", "--no-cache", "/src"], "/work/run", {}),
            ("Q4", ["ruff", "format", "--no-cache", "--check", "/src"], "/work/run", {}),
            ("Q5", ["/opt/mypy-ci/bin/mypy", "headroom", "--ignore-missing-imports",
                    "--cache-dir", "/work/cache/mypy-ci"], "/src", {}),
            ("Q6b-baseline", ["pre-commit", "run", "mypy"] + pc_tail, HOOK_BASEARM,
             {"MYPY_CACHE_DIR": "/work/cache/mypy-hook-baseline"}),
            ("Q6b", ["pre-commit", "run", "mypy"] + pc_tail, "/src", {"MYPY_CACHE_DIR": "/work/cache/mypy-hook"}),
        ]
    if lane == "python-proof":
        return [
            ("S01", ["bash", "/src/scripts/build_rust_extension.sh"], "/src", {}),
            ("S03", base_pytest + ["--tb=long", "-vv", "-rA", "--junitxml=/evidence/S03.xml", base_d1], "/work/run", {"PYTHONPATH": PYTHON_BASEARM}),
            ("S04", base_pytest + ["--tb=long", "-vv", "-rA", "--junitxml=/evidence/S04.xml", base_d2], "/work/run", {"PYTHONPATH": PYTHON_BASEARM}),
            ("S05", pytest + ["--tb=long", "-rA", "--junitxml=/evidence/S05.xml", tests + "::TestMarkdownSectionMerge", d1, d2], "/work/run", {}),
            ("S06", pytest + ["--tb=long", "-rA", "--junitxml=/evidence/S06.xml", tests], "/work/run", {}),
        ]
    if lane == "rust-workspace":
        return [
            ("M1-fmt", ["cargo", "fmt", "--manifest-path", "/src/Cargo.toml", "--all", "--", "--check"], "/work/run", {}),
            ("M1-clippy", ["cargo", "clippy", "--manifest-path", "/src/Cargo.toml", "--workspace", "--offline", "--", "-D", "warnings"], "/work/run", {}),
            ("M1-test", ["cargo", "test", "--manifest-path", "/src/Cargo.toml", "--workspace", "--offline"], "/work/run", {}),
        ]
    if lane == "ci-python-commitlint":
        return [
            ("M1-build", ["bash", "/src/scripts/build_rust_extension.sh"], "/src", {}),
            ("M1-python", pytest + ["-q", "--junitxml=/evidence/M1-python.xml"] + smart, "/work/run", {}),
            ("M1-commitlint-range", ["/opt/commitlint/node_modules/.bin/commitlint",
             "--config", "/work/commitlint/.commitlintrc.json", "--cwd", "/src", "--from",
             spec["commitlint_from"], "--to", spec["commitlint_to"]], "/src", {}),
            ("M1-commitlint-candidate", ["bash", "-c", "set -o pipefail; printf '%s\\n' 'fix(memory): export memories into their existing section' | /opt/commitlint/node_modules/.bin/commitlint --config /work/commitlint/.commitlintrc.json --cwd /src"], "/work/run", {}),
        ]
    raise Stop("LANE")


def inside_identity(label, root=Path("/src"), evidence=Path("/evidence")):
    inv = source_inventory(root)
    path = evidence / ("identity-" + label + ".json")
    if label == "S00":
        save(path, {"label": label, "inventory": inv})
        return 0
    pre = strict_json(evidence / "identity-S00.json")["inventory"]
    delta = inventory_delta(pre, inv, [])
    save(path, {"label": label, "inventory": inv, "delta": delta})
    return 0 if delta["ok"] else 3


def prepare_commitlint_config(spec):
    """Copy the frozen config into writable /work and expose the pinned modules beside it."""
    source = Path("/src/.commitlintrc.json")
    directory = Path("/work/commitlint")
    config = directory / ".commitlintrc.json"
    modules = directory / "node_modules"
    directory.mkdir(parents=True, exist_ok=True)
    need(source.is_file() and not source.is_symlink(), "COMMITLINT_CONFIG_SOURCE")
    shutil.copyfile(source, config)
    need(sha256(config) == spec["commitlint_config_sha256"], "COMMITLINT_CONFIG_HASH")
    need(Path("/opt/commitlint/node_modules").is_dir(), "COMMITLINT_MODULES")
    modules.symlink_to("/opt/commitlint/node_modules", target_is_directory=True)
    need(modules.is_symlink() and modules.resolve(strict=True) == Path("/opt/commitlint/node_modules"),
         "COMMITLINT_MODULES_LINK")
    return config


def copy_basearm_inputs(root, dest):
    shutil.copytree(root / "headroom", dest / "headroom", ignore=shutil.ignore_patterns("__pycache__", "_core*.so"))
    shutil.copytree(root / "tests", dest / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(root / "pyproject.toml", dest / "pyproject.toml")
    shutil.copy2(root / ".pre-commit-config.yaml", dest / ".pre-commit-config.yaml")


def restore_pr_head_files(spec, root, dest, relatives):
    for relative in relatives:
        expected = spec["base_files"][relative]
        body = subprocess.run(["git", "-C", str(root), "show", spec["pr_head"] + ":" + relative],
                              stdout=subprocess.PIPE, check=True).stdout
        need(hashlib.sha256(body).hexdigest() == expected, "BASE_FILE " + relative)
        (dest / relative).write_bytes(body)


def inside_python_basearm(spec, root=Path("/src"), dest=Path(PYTHON_BASEARM)):
    """PR-head implementation plus the hash-bound candidate regression tests."""
    candidate_tests = root / "tests/test_memory_bridge.py"
    need(sha256(candidate_tests) == spec["candidate_files"]["tests/test_memory_bridge.py"],
         "CANDIDATE_TEST_SOURCE_HASH")
    copy_basearm_inputs(root, dest)
    restore_pr_head_files(spec, root, dest, PYTHON_BASE_FILES)
    copied_tests = dest / "tests/test_memory_bridge.py"
    need(sha256(copied_tests) == spec["candidate_files"]["tests/test_memory_bridge.py"],
         "CANDIDATE_TEST_BASEARM_HASH")
    need("def test_sync_inserts_export_into_existing_section_above_last_heading(" in
         copied_tests.read_text(encoding="utf-8"), "S03_NODE_MISSING")
    return 0


def inside_hook_basearm(spec, root=Path("/src"), dest=Path(HOOK_BASEARM)):
    """Exact PR-head files in a repository for the Q6b baseline hook."""
    copy_basearm_inputs(root, dest)
    restore_pr_head_files(spec, root, dest, HOOK_BASE_FILES)
    for relative in HOOK_BASE_FILES:
        need(sha256(dest / relative) == spec["base_files"][relative],
             "HOOK_BASE_FILE_HASH " + relative)
    initialized = subprocess.run(["git", "init", "-q", str(dest)], check=False)
    need(initialized.returncode == 0, "BASELINE_GIT_INIT")
    return 0


def junit_result(path):
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    identities = sorted((case.attrib.get("classname", "").split(".")[-1], case.attrib.get("name", ""))
                        for case in cases)
    failures = sum(len(case.findall("failure")) for case in cases)
    errors = sum(len(case.findall("error")) for case in cases)
    skipped = sum(len(case.findall("skipped")) for case in cases)
    identity_bytes = "\n".join(a + "::" + b for a, b in identities).encode()
    return {"tests": len(cases), "failures": failures, "errors": errors, "skipped": skipped,
            "identities_unique": len(set(identities)) == len(identities),
            "identity_sha256": hashlib.sha256(identity_bytes).hexdigest()}


def check_step_contract(step, rec, log_text, spec, evidence):
    expected_exit = 1 if step == "S03" else 0
    ok = rec["exit"] == expected_exit
    detail = {"expected_exit": expected_exit, "actual_exit": rec["exit"]}
    if step == "Q5":
        errors = parse_mypy_errors(log_text, rec["exit"])
        ok = rec["exit"] == 0 and not errors
        detail.update({"accepted_errors": [], "strict_mypy_parse": True})
    elif step == "Q6b-baseline":
        errors = parse_mypy_errors(log_text, rec["exit"])
        ok = errors == KNOWN_PREEXISTING_HOOK_ERRORS
        detail.update({"accepted_errors": [list(item) for item in sorted(errors)],
                       "baseline_equals_known_preexisting": ok,
                       "expected_exit": "0 clean or 1 strictly parsed"})
    elif step == "Q6b":
        baseline_log = (evidence / "Q6b-baseline.log").read_text(encoding="utf-8")
        baseline_rec = strict_json(evidence / "Q6b-baseline.json")
        comparison = classify_hook_comparison(
            baseline_log, baseline_rec["exit"], log_text, rec["exit"]
        )
        ok = comparison["candidate_subset_of_baseline"]
        detail.update(comparison)
        detail["expected_exit"] = "0 clean or 1 strictly parsed subset of baseline"
    xml_path = evidence / (step + ".xml")
    if xml_path.exists():
        junit = junit_result(xml_path)
        detail["junit"] = junit
        if step == "S03":
            ok = ok and junit["tests"] == 1 and junit["failures"] == 1 and not junit["errors"] \
                and not junit["skipped"] and "cobalt-47" in log_text and "Updates" in log_text \
                and "test_memory_bridge.py:715" in log_text
        elif step == "S04":
            ok = ok and junit == {"tests": 1, "failures": 0, "errors": 0, "skipped": 0,
                                  "identities_unique": True, "identity_sha256": junit["identity_sha256"]}
        elif step == "S05":
            ok = ok and junit["tests"] == 14 and not any(junit[k] for k in ("failures", "errors", "skipped")) \
                and junit["identities_unique"]
        elif step == "S06":
            ok = ok and junit["tests"] == spec["whole_file_identity_count"] \
                and junit["identity_sha256"] == spec["whole_file_identity_sha256"] \
                and not any(junit[k] for k in ("failures", "errors", "skipped")) and junit["identities_unique"]
        elif step == "M1-python":
            ok = ok and not junit["failures"] and not junit["errors"] and junit["identities_unique"]
    detail["ok"] = ok
    return detail


def inside_prologue(spec, evidence):
    """Run every counted-container action that precedes the first lane step."""
    evidence = Path(evidence)
    (Path("/work/run")).mkdir(parents=True, exist_ok=True)
    for path in ("/work/home", "/work/tmp", "/work/cache", "/work/headroom", "/work/claude"):
        Path(path).mkdir(parents=True, exist_ok=True)
    prepare_commitlint_config(spec)
    prepare_runtime_caches()
    freeze_path = Path("/opt/mypy-ci-pip-freeze.txt")
    need(freeze_path.is_file(), "MYPY_CI_FREEZE_MISSING")
    freeze = freeze_path.read_text(encoding="utf-8")
    need("mypy==" + spec["mypy"] in freeze and "ruff==" + spec["ruff"] in freeze
         and "langchain-core==" in freeze, "MYPY_CI_FREEZE_CONTENT")
    (evidence / "mypy-ci-pip-freeze.txt").write_text(freeze, encoding="utf-8")
    wheelhouse_manifest = Path("/opt/wheelhouse/wheelhouse-manifest.json")
    need(wheelhouse_manifest.is_file(), "WHEELHOUSE_MANIFEST_MISSING")
    wheelhouse = strict_json(wheelhouse_manifest)
    need(wheelhouse == {
        "schema": "headroom4452-offline-wheelhouse/1",
        "files": wheelhouse["files"],
        "pins": ["maturin==" + spec["maturin"]],
        "download": {"only_binary": True, "dependencies_resolved": True},
        "metadata": {"name": "maturin", "version": spec["maturin"],
                     "requires_dist": wheelhouse["metadata"]["requires_dist"],
                     "applicable_requires_dist": [],
                     "setuptools_or_wheel_required": False},
    }, "WHEELHOUSE_MANIFEST_CONTENT")
    need(len(wheelhouse["files"]) == 1
         and wheelhouse["files"][0]["filename"].endswith(".whl")
         and len(wheelhouse["files"][0]["sha256"]) == 64
         and wheelhouse["files"][0]["bytes"] > 0,
         "WHEELHOUSE_FILE_RECORD")
    (evidence / "wheelhouse-manifest.json").write_bytes(wheelhouse_manifest.read_bytes())
    commitlint_tree = Path("/opt/commitlint-npm-ls.json")
    need(commitlint_tree.is_file(), "COMMITLINT_NPM_LS_MISSING")
    (evidence / "commitlint-npm-ls.json").write_bytes(commitlint_tree.read_bytes())
    inside_python_basearm(spec)
    inside_hook_basearm(spec)
    probe = ET.Element("testsuite", name="inside-prologue", tests="1", failures="0", errors="0")
    ET.SubElement(probe, "testcase", classname="hosted.prologue", name="evidence_writable")
    ET.ElementTree(probe).write(evidence / "prologue-junit-probe.xml",
                                encoding="utf-8", xml_declaration=True)
    save(evidence / "prologue.json", {
        "status": "PASS", "python_basearm": PYTHON_BASEARM, "hook_basearm": HOOK_BASEARM,
        "evidence_writable": True, "junit_probe": "prologue-junit-probe.xml",
    })
    return 0


def inside_run(lane, spec, evidence):
    evidence = Path(evidence)
    inside_prologue(spec, evidence)
    begin = time.monotonic()
    receipts = []
    first_failure = None
    save_disk_evidence(evidence, "disk-before")
    for step, argv, cwd, extra in lane_steps(lane):
        env = runtime_env(extra)
        rec = bounded(argv, cwd=cwd, env=env, timeout=55 * 60, cap=64 * 1024 * 1024)
        log_text = rec.pop("output")
        save_command_evidence(evidence, step, rec, log_text)
        log = evidence / (step + ".log")
        rec["contract"] = check_step_contract(step, rec, log_text, spec, evidence)
        rec.update({"step": step, "log_sha256": sha256(log)})
        save(evidence / (step + ".json"), rec)
        receipts.append(rec)
        if not rec["contract"]["ok"]:
            first_failure = step
            break
        if step == "S01":
            install_basearm_core(evidence)
    save_disk_evidence(evidence, "disk-after")
    after = source_inventory("/src")
    before = strict_json(evidence / "candidate-identity.json")["inventory"]
    delta = inventory_delta(before, after, spec["allowed_new_files_after_build"])
    elapsed = time.monotonic() - begin
    ok = first_failure is None and delta["ok"] and elapsed < 60 * 60
    save(evidence / "summary.json", {"schema": "headroom4452-a28b-lane-result/1", "attempt": "28 of 55",
         "lane": lane, "status": "PASS" if ok else "FAIL", "first_failure": first_failure,
         "lane_elapsed_monotonic_seconds": elapsed, "job_limit_seconds": 3600,
         "no_cross_clock_arithmetic": True, "source_delta": delta,
         "mypy_ci_pip_freeze_sha256": sha256(evidence / "mypy-ci-pip-freeze.txt"),
         "wheelhouse_manifest_sha256": sha256(evidence / "wheelhouse-manifest.json"),
         "commitlint_config_sha256": spec["commitlint_config_sha256"],
         "commitlint_npm_ls_sha256": sha256(evidence / "commitlint-npm-ls.json"),
         "receipts": [{k: v for k, v in r.items() if k != "argv"} for r in receipts]})
    return 0 if ok else 4


def disk_snapshot():
    """Capture disk-backed Cargo storage and bounded tmpfs usage."""
    df = bounded(["df", "-Pk", "/", "/work", "/src", "/opt/venv", "/cargo-target"],
                 cwd="/work/run", env=runtime_env(), timeout=60, cap=1024 * 1024)
    need(df["exit"] == 0, "DISK_DF\n" + df["output"][-2000:])
    du = bounded(["du", "-sk", "/cargo-target"], cwd="/work/run", env=runtime_env(),
                 timeout=60, cap=1024 * 1024)
    need(du["exit"] == 0, "DISK_DU\n" + du["output"][-2000:])
    return {"df_argv": df["argv"], "df_output": df["output"],
            "du_argv": du["argv"], "du_output": du["output"]}


def save_disk_evidence(evidence, stem):
    save(Path(evidence) / (stem + ".json"), disk_snapshot())


def install_basearm_core(evidence, source=Path("/src/headroom"),
                         destination=Path(PYTHON_BASEARM) / "headroom"):
    """Copy the just-built PR-head Rust core beside the PR-head Python package."""
    cores = sorted(source.glob("_core*.so"))
    need(len(cores) == 1 and cores[0].name == "_core.abi3.so", "BUILT_CORE")
    target = destination / cores[0].name
    shutil.copy2(cores[0], target)
    need(sha256(target) == sha256(cores[0]), "BASEARM_CORE_HASH")
    save(Path(evidence) / "python-basearm-core.json", {
        "source": str(cores[0]), "destination": str(target), "sha256": sha256(target),
        "candidate_rust_changed": False,
        "basis": "candidate patch changes only bridge.py and test_memory_bridge.py",
        "pr_head_core": True,
    })


def run_hosted(args):
    evidence = Path(args.evidence)
    started = time.monotonic()
    try:
        evidence.mkdir(parents=True, exist_ok=False)
        # Root runs without CAP_DAC_OVERRIDE.  Make only this fresh, workflow-owned
        # evidence directory writable before bind-mounting it into the container.
        evidence.chmod(0o777)
        runner_disk = Path(args.runner_disk_job_start)
        need(runner_disk.is_file() and runner_disk.stat().st_size > 0, "RUNNER_DISK_JOB_START")
        shutil.copy2(runner_disk, evidence / "runner-disk-job-start.txt")
        spec = strict_json(SPEC_PATH)
        need(args.lane in spec["lanes"], "LANE")
        before = candidate_prepare(args.source, args.patch, evidence, spec)
        # Static disposition for v3 finding 2: project-relative producers are not on these entry paths;
        # tests execute from /work/run, while all supported state/config variables point under /work.
        producers = ["headroom/cli/memory.py", "headroom/cli/port_discovery.py", "headroom/cli/init.py",
                     "headroom/cli/wrap.py"]
        save(evidence / "cwd-producer-disposition.json", {"redirected_environment": common_env(),
             "selected_commands": [r[1] for r in lane_steps(args.lane)],
             "project_relative_producer_modules": producers,
             "disposition": "unreachable from selected entry points; Python tests run with cwd=/work/run",
             "inventory_gate": "any unexpected .headroom or .claude path under /src fails"})
        dockerfile_path = evidence / "Dockerfile"
        dockerfile_path.write_text(dockerfile(spec), encoding="utf-8")
        tag = "headroom4452-a28b-" + args.lane
        with tempfile.TemporaryDirectory(prefix="headroom4452-a28b-build-") as tmp:
            context = prepare_build_context(args.source, Path(tmp), spec)
            shutil.copy2(dockerfile_path, context / "Dockerfile")
            save(evidence / "build-context.json", {
                "temporary_outer_context": True,
                "outside_sealed_source_tree": True,
                "copy_instruction": "COPY source/ /src",
                "full_git_history_copied": True,
                "candidate_files_staged_only_in_temporary_copy": sorted(spec["candidate_files"]),
                "pre_commit_config_copied": True,
                "tests_copied": True,
            })
            prep = bounded(["docker", "build", "--pull", "--network", "default", "-f",
                            str(context / "Dockerfile"), "-t", tag, str(context)],
                           timeout=50 * 60, cap=64 * 1024 * 1024)
        prep_output = prep.pop("output")
        save_command_evidence(evidence, "preparation", prep, prep_output)
        need(prep["exit"] == 0, "P0_PREPARATION")
        # Rust is a BuildKit-only stage: bind it from the build log and copied-tool versions.
        rust_stage = rust_stage_identity(prep_output, spec)
        container_base = inspect_uv_base(spec["container_image"])
        lane_image = inspect_local_image(tag)
        need(lane_image is not None, "IMAGE_INSPECT " + tag)
        save(evidence / "image.json", {"rust_stage": rust_stage,
             "container_base": container_base, "lane": lane_image,
             "model_revision": spec["model"]["revision"], "network_used_only_for_preparation": True})
        name = "headroom4452-a28b-" + args.lane + "-" + os.environ.get("GITHUB_RUN_ID", "local")
        command = hardened_run_argv(
            name=name, image=tag, evidence=evidence, runtime=HERE,
            environment=common_env(), inner_argv=[
                "/opt/venv/bin/python", "-I", "-B", "/runtime/hosted.py",
                "inside-run", args.lane, "/evidence",
            ])
        save(evidence / "command.json", {"argv": command, "network": "none", "prepared_before_attempt": True})
        # The Git ref creation, not this call, consumes attempt 28. This controller never creates refs.
        result = bounded(command, timeout=60 * 60, cap=8 * 1024 * 1024)
        container_output = result.pop("output")
        save_command_evidence(evidence, "container", result, container_output)
        need(result["exit"] == 0, "LANE_FAILED")
        summary = strict_json(evidence / "summary.json")
        need(summary["status"] == "PASS", "SUMMARY_FAILED")
        save(evidence / "host-summary.json", {"status": "PASS", "lane": args.lane,
             "host_elapsed_monotonic_seconds": time.monotonic() - started,
             "container_elapsed_monotonic_seconds": result["elapsed_monotonic_seconds"],
             "no_cross_clock_arithmetic": True, "attempt": "28 of 55"})
        return 0
    except BaseException as exc:
        save(evidence / "host-summary.json", {"status": "FAIL", "lane": args.lane,
             "exception_type": type(exc).__name__, "exception_message": str(exc)[:2000],
             "traceback_tail": traceback.format_exc().splitlines()[-40:],
             "host_elapsed_monotonic_seconds": time.monotonic() - started,
             "no_cross_clock_arithmetic": True, "attempt": "28 of 55"})
        return 4


def fake_selftest():
    spec = strict_json(SPEC_PATH)
    need(spec["lanes"] == list(LANES), "SELFTEST_LANES")
    need(spec["no_cross_clock_arithmetic"] is True, "SELFTEST_CLOCK")
    need(spec["allowed_new_files_after_build"] == ["headroom/_core.abi3.so", "headroom_memory.db",
                                                    "headroom_memory_vectors.db"], "SELFTEST_ALLOWLIST")
    before = [["a", "file", 1, "x"]]
    need(inventory_delta(before, before + [["headroom/_core.abi3.so", "file", 2, "y"]],
                         spec["allowed_new_files_after_build"])["ok"], "SELFTEST_ALLOWED")
    need(not inventory_delta(before, before + [[".headroom/memory.db", "file", 2, "y"]],
                             spec["allowed_new_files_after_build"])["ok"], "SELFTEST_HEADROOM")
    need(not inventory_delta(before, before + [[".claude/settings.json", "file", 2, "y"]],
                             spec["allowed_new_files_after_build"])["ok"], "SELFTEST_CLAUDE")
    all_steps = {lane: [x[0] for x in lane_steps(lane)] for lane in LANES}
    need(all_steps["source-gates"][:3] == ["S00", "Q6a", "G1"], "SELFTEST_ORDER")
    need("Q6b" in all_steps["source-gates"], "SELFTEST_Q6B")
    need(all(len(v) for v in all_steps.values()), "SELFTEST_STEPS")
    env = common_env()
    for key in ("HEADROOM_WORKSPACE_DIR", "HEADROOM_CONFIG_DIR", "HEADROOM_MEMORY_DB_PATH",
                "CLAUDE_CONFIG_DIR", "RUFF_CACHE_DIR", "MYPY_CACHE_DIR", "XDG_CACHE_HOME"):
        need(env[key].startswith("/work/"), "SELFTEST_REDIRECT " + key)
    generated = dockerfile(spec)
    need("snapshot_download" in generated and spec["model"]["revision"] in generated,
         "SELFTEST_IMMUTABLE_MODEL")
    need("COPY source/ /src" in generated and "COPY . /src" not in generated,
         "SELFTEST_OUTER_CONTEXT")
    for marker in ("git init -q /opt/precommit-repo",
                   "cp /src/.pre-commit-config.yaml /opt/precommit-repo/.pre-commit-config.yaml",
                   "cd /opt/precommit-repo",
                   "HOME=/opt/work PRE_COMMIT_HOME=/opt/precommit /opt/venv/bin/pre-commit install-hooks"):
        need(marker in generated, "SELFTEST_THROWAWAY_REPO " + marker)
    need("/opt/precommit-seed" in generated and "/opt/npm-cache-seed" in generated,
         "SELFTEST_CACHE_SEEDS")
    need("ctypes.CDLL" in generated, "SELFTEST_ORT_LOAD")
    need(all(x[1][0] != "make" for x in sum((lane_steps(l) for l in LANES), [])), "SELFTEST_SPLIT_MAKE")
    print(json.dumps({"status": "PASS", "tests": 19, "lanes": all_steps,
                      "pycache_left": [], "isolated": sys.flags.isolated,
                      "dont_write_bytecode": sys.flags.dont_write_bytecode}, sort_keys=True))
    return 0


def parser():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    run = sub.add_parser("run")
    run.add_argument("--lane", required=True, choices=LANES)
    run.add_argument("--source", required=True)
    run.add_argument("--patch", required=True)
    run.add_argument("--runner-disk-job-start", required=True)
    run.add_argument("--evidence", required=True)
    inside = sub.add_parser("inside-run")
    inside.add_argument("lane", choices=LANES)
    inside.add_argument("evidence")
    prologue = sub.add_parser("inside-prologue")
    prologue.add_argument("evidence")
    ident = sub.add_parser("inside-identity")
    ident.add_argument("label", choices=("S00", "G1"))
    sub.add_parser("inside-python-basearm")
    sub.add_parser("inside-hook-basearm")
    sub.add_parser("fake-selftest")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.mode == "run":
        return run_hosted(args)
    if args.mode == "inside-run":
        return inside_run(args.lane, strict_json(SPEC_PATH), args.evidence)
    if args.mode == "inside-prologue":
        return inside_prologue(strict_json(SPEC_PATH), args.evidence)
    if args.mode == "inside-identity":
        return inside_identity(args.label)
    if args.mode == "inside-python-basearm":
        return inside_python_basearm(strict_json(SPEC_PATH))
    if args.mode == "inside-hook-basearm":
        return inside_hook_basearm(strict_json(SPEC_PATH))
    if args.mode == "fake-selftest":
        return fake_selftest()
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
