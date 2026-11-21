#!/usr/bin/env python3
"""Non-counted hardened prologue smoke for Headroom #4452 attempt 27.

Builds each counted candidate image and runs the counted harness prologue plus
prepared-asset probes offline.  It never runs the upstream pytest or Cargo suites.
"""
import sys

if sys.flags.optimize:
    raise SystemExit("OPTIMIZE_FORBIDDEN")
sys.dont_write_bytecode = True

import argparse  # noqa: E402
import ctypes  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import sqlite3  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402

import hosted as counted_harness  # noqa: E402
from docker_run import hardened_run_argv  # noqa: E402

HERE = Path(__file__).resolve().parent
SPEC_PATH = HERE / "spec.json"
LANES = ("source-gates", "python-proof", "rust-workspace", "ci-python-commitlint")
BOOKWORM_APT_PACKAGES = frozenset({
    "build-essential", "ca-certificates", "cmake", "curl", "git", "make", "nodejs", "npm",
    "patchelf", "pkg-config",
})
WORK_FILE_ENV_KEYS = frozenset({"COVERAGE_FILE", "HEADROOM_MEMORY_DB_PATH"})
PROBE_EXTRA_WORK_DIRECTORIES = ("/work/cache/mypy-hook",)
KNOWN_PREEXISTING_HOOK_ERRORS = frozenset({
    ("headroom/proxy/upstream_guard.py", 162, "no-any-return"),
})
MYPY_ERROR = re.compile(
    r"^(?P<path>[^:\r\n]+):(?P<line>[1-9][0-9]*): error: .+  \[(?P<code>[a-z0-9-]+)\]$"
)
MYPY_SUMMARY = re.compile(
    r"^Found (?P<count>[0-9]+) errors? in [0-9]+ files? \(checked [0-9]+ source files\)$"
)
# Schema for any unavoidable future drift: key -> {"hosted": value,
# "smoke": value, "reason": nonempty explanation}.  Empty today because the
# smoke must exercise the counted environment without value differences.
PROBE_ENV_COMMON_EXCEPTIONS = {}


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


def save_command_evidence(evidence, stem, result, output):
    """Persist raw command evidence before checking exit status or parsing output."""
    evidence = Path(evidence)
    (evidence / (stem + ".log")).write_text(output, encoding="utf-8")
    save(evidence / (stem + ".json"), result)


def checked_probe_evidence(evidence, probe, output):
    """Save the complete probe result before checking or parsing any inner evidence."""
    probe_record = dict(probe)
    probe_record["output"] = output
    save_command_evidence(evidence, "version-probes", probe_record, output)
    need(probe["exit"] == 0,
         "VERSION_PROBES exit=%d\n%s" % (probe["exit"], output[-2000:]))
    markers = [line.split(" ", 1)[1] for line in output.splitlines()
               if line.startswith("OFFLINE_MYPY_CLASSIFICATION ")]
    need(len(markers) == 1, "OFFLINE_MYPY_CLASSIFICATION_COUNT")
    classification = json.loads(markers[0])
    need(classification.get("accepted") is True, "OFFLINE_MYPY_CLASSIFICATION_REJECTED")
    return {"rust_toolchain_versions": rust_toolchain_versions(output),
            "mypy_classification": classification}


def parse_mypy_errors(output, exit_code):
    """Strictly parse mypy errors and cross-check its terminal error count."""
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


def hook_result_accepted(output, exit_code):
    errors = parse_mypy_errors(output, exit_code)
    need(not errors or errors == KNOWN_PREEXISTING_HOOK_ERRORS, "MYPY_HOOK_ERROR_SET")
    return errors


def precommit_mypy_python(pre_commit_home):
    """Resolve mirrors-mypy from pre-commit's SQLite database and actual environment layout."""
    home = Path(pre_commit_home)
    database = home / "db.db"
    need(database.is_file(), "PRE_COMMIT_DB")
    with sqlite3.connect(database) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(repos)")]
        need({"repo", "ref", "path"}.issubset(columns), "PRE_COMMIT_DB_SCHEMA")
        rows = list(connection.execute(
            "SELECT repo, ref, path FROM repos WHERE repo LIKE ?",
            ("%pre-commit/mirrors-mypy%",),
        ))
    need(len(rows) == 1, "PRE_COMMIT_MYPY_DB_ROW")
    repo, ref, stored_path = rows[0]
    repo_path = Path(stored_path)
    if not repo_path.is_absolute():
        repo_path = home / repo_path
    hooks = repo_path / ".pre-commit-hooks.yaml"
    need(hooks.is_file() and re.search(r"(?m)^\s*-?\s*id:\s*mypy\s*$", hooks.read_text()),
         "PRE_COMMIT_MYPY_HOOK")
    interpreters = sorted(repo_path.glob("py_env-*/bin/python"))
    need(len(interpreters) == 1 and interpreters[0].is_file(), "PRE_COMMIT_MYPY_PYTHON")
    return {"database": str(database), "repo": repo, "ref": ref,
            "repo_path": str(repo_path), "python": str(interpreters[0])}


def httpx_environment_diagnostic(env):
    location = precommit_mypy_python(env["PRE_COMMIT_HOME"])
    hook = bounded([location["python"], "-I", "-B", "-c", "import httpx"],
                   cwd="/src", env=env, timeout=60)
    full = bounded(["/opt/venv/bin/python", "-I", "-B", "-c", "import httpx"],
                   cwd="/src", env=env, timeout=60)
    need(hook["exit"] != 0 and "httpx" in hook["output"] and "ModuleNotFoundError" in hook["output"],
         "HOOK_HTTPX_UNEXPECTED")
    need(full["exit"] == 0, "FULL_ENV_HTTPX_UNEXPECTED\n" + full["output"][-2000:])
    return {"location": location, "hook_env": hook, "full_env": full,
            "cause_proved": True}


def bounded(argv, *, timeout, cap=64 * 1024 * 1024, cwd=None, env=None):
    begin = time.monotonic()
    proc = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
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


def prepare_build_context(source, root, spec, evidence):
    """Use an outer context so the checkout's nested .dockerignore filters nothing."""
    source, root = Path(source), Path(root)
    wrapped = root / "source"
    shutil.copytree(source, wrapped, symlinks=True)
    need((wrapped / ".git").exists(), "BUILD_CONTEXT_GIT")
    need((wrapped / ".pre-commit-config.yaml").is_file(), "BUILD_CONTEXT_PRE_COMMIT_CONFIG")
    need((wrapped / "tests/test_memory_bridge.py").is_file(), "BUILD_CONTEXT_TESTS")
    for commit in (spec["commitlint_from"], spec["commitlint_to"], spec["pr_head"]):
        found = bounded(["git", "cat-file", "-e", commit + "^{commit}"], cwd=wrapped, timeout=30)
        need(found["exit"] == 0, "BUILD_CONTEXT_COMMIT " + commit)
    clean = bounded(["git", "status", "--porcelain=v1", "--ignored=matching",
                     "--untracked-files=all"], cwd=wrapped, timeout=60)
    need(clean["exit"] == 0 and not clean["output"].strip(), "BUILD_CONTEXT_NOT_CLEAN")
    counted_harness.candidate_prepare(wrapped, HERE / "candidate.patch", evidence, spec)
    staged = bounded(["git", "add", "--"] + sorted(spec["candidate_files"]),
                     cwd=wrapped, timeout=60)
    need(staged["exit"] == 0, "BUILD_CONTEXT_STAGE")
    return root


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
COPY source/ /src
RUN ci_python="$(sed -nE 's/^[[:space:]]*PY_VERSION:[[:space:]]*"([^"]+)"[[:space:]]*$/\\1/p' /src/.github/workflows/ci.yml)" \
 && test "$ci_python" = "{spec["ci_python"]}" \
 && /usr/local/bin/python{spec["ci_python"]} -m venv /opt/mypy-ci \
 && /opt/mypy-ci/bin/python -m pip install --upgrade pip "ruff=={spec["ruff"]}" "mypy=={spec["mypy"]}" "{spec["langchain_core"]}" \
 && /opt/mypy-ci/bin/python -m pip freeze | tee /opt/mypy-ci-pip-freeze.txt
RUN uv venv /opt/venv --python 3.12 && UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --extra dev --extra langchain --extra proxy --no-install-project && uv pip install --python /opt/venv/bin/python "maturin>=1.5,<2.0" && /opt/venv/bin/maturin --version
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
    """Ensure the final-stage base is in the local image store before inspecting it."""
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


def resolved_images(spec, lane_tag, rust_stage):
    """Inspect only images that are expected in the local store; Rust is a build stage."""
    lane = inspect_local_image(lane_tag)
    need(lane is not None, "IMAGE_INSPECT " + lane_tag)
    images = {
        "rust_stage": rust_stage,
        "container_base": inspect_uv_base(spec["container_image"]),
        "lane": lane,
    }
    return images


def rust_toolchain_versions(output):
    """Parse exact tool versions, accepting bare or BuildKit plain-progress lines."""
    prefix = re.compile(r"^#(?P<step>\d+)\s+\d+(?:\.\d+)?\s+(?P<text>.*)$")
    stage_steps = {match.group(1) for line in output.splitlines()
                   if (match := re.match(r"^#(\d+)\s+\[rust-toolchain \d+/\d+\]", line))}
    patterns = {
        "rustc": re.compile(r"rustc 1\.95\.0 \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)"),
        "cargo": re.compile(r"cargo 1\.95\.0 \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)"),
        "rustfmt": re.compile(r"rustfmt \S+(?: \([^\r\n]+\))?"),
        "clippy": re.compile(r"clippy 0\.1\.95 \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)"),
    }
    versions = {}
    for raw in output.splitlines():
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
    """Bind the BuildKit-only Rust stage to its FROM digest and copied-tool probes."""
    digest = spec["rust_image"].rsplit("@", 1)[1]
    from_lines = [line.strip() for line in build_log.splitlines()
                  if re.search(r"\[rust-toolchain 1/\d+\] FROM ", line) and digest in line]
    need(from_lines, "RUST_STAGE_FROM_EVIDENCE")
    return {"reference": spec["rust_image"], "digest": digest,
            "build_log_from": from_lines[-1],
            "tool_versions": rust_toolchain_versions(build_log),
            "identity_method": "buildkit_from_digest_plus_in_image_tool_versions",
            "image_inspected": False}


def probe_env():
    env = os.environ.copy()
    env.update(counted_harness.common_env())
    return env


def probe_work_directories(env):
    """Return every directory named by a /work environment value."""
    directories = list(PROBE_EXTRA_WORK_DIRECTORIES)
    for key, value in sorted(env.items()):
        if value != "/work" and not value.startswith("/work/"):
            continue
        path = Path(value).parent if key in WORK_FILE_ENV_KEYS else Path(value)
        directories.append(str(path))
    return sorted(set(directories))


def create_probe_work_directories(env):
    """Create every directory named by a /work environment value before probes."""
    directories = probe_work_directories(env)
    for value in directories:
        path = Path(value)
        path.mkdir(parents=True, exist_ok=True)
    return directories


def prepare_commitlint_config(spec):
    """Copy the frozen config into writable /work and expose the pinned modules beside it."""
    source = Path("/src/.commitlintrc.json")
    directory = Path("/work/commitlint")
    config = directory / ".commitlintrc.json"
    modules = directory / "node_modules"
    directory.mkdir(parents=True, exist_ok=True)
    need(source.is_file() and not source.is_symlink(), "COMMITLINT_CONFIG_SOURCE")
    shutil.copyfile(source, config)
    need(hashlib.sha256(config.read_bytes()).hexdigest() == spec["commitlint_config_sha256"],
         "COMMITLINT_CONFIG_HASH")
    need(Path("/opt/commitlint/node_modules").is_dir(), "COMMITLINT_MODULES")
    modules.symlink_to("/opt/commitlint/node_modules", target_is_directory=True)
    need(modules.is_symlink() and modules.resolve(strict=True) == Path("/opt/commitlint/node_modules"),
         "COMMITLINT_MODULES_LINK")
    return str(config)


def inside_probe():
    """Exercise every prepared cache with networking disabled by the outer Docker call."""
    spec = strict_json(SPEC_PATH)
    env = probe_env()
    prologue = bounded(["/opt/venv/bin/python", "-I", "-B", "/runtime/hosted.py",
                        "inside-prologue", "/evidence"],
                       cwd="/src", env=env, timeout=10 * 60)
    need(prologue["exit"] == 0, "COUNTED_PROLOGUE\n" + prologue["output"][-2000:])
    commitlint_config = "/work/commitlint/.commitlintrc.json"
    changed = ["headroom/memory/bridge.py", "tests/test_memory_bridge.py"]
    tail = ["--hook-stage", "pre-commit", "--show-diff-on-failure", "--color", "never",
            "--files"] + changed
    commands = [
        ("tool-versions", ["bash", "-c", "rustc --version && cargo --version && rustfmt --version && cargo clippy --version && node --version && npm --version && python --version && uv --version && pre-commit --version && maturin --version"]),
        ("git-repository", ["git", "rev-parse", "--is-inside-work-tree"]),
        ("commitlint-from", ["git", "cat-file", "-e", spec["commitlint_from"] + "^{commit}"]),
        ("pre-commit", ["pre-commit", "run"] + tail),
        ("pre-commit-mypy", ["pre-commit", "run", "mypy"] + tail),
        ("httpx-environment-diagnostic", None),
        ("ci-equivalent-mypy", ["/opt/mypy-ci/bin/mypy", "headroom",
                                 "--ignore-missing-imports", "--cache-dir",
                                 "/work/cache/mypy-ci"]),
        ("commitlint-range", ["/opt/commitlint/node_modules/.bin/commitlint",
         "--config", commitlint_config, "--cwd", "/src", "--from", spec["commitlint_from"],
         "--to", spec["commitlint_to"]]),
    ]
    outputs = []
    hook_errors = None
    httpx_diagnostic = None
    for label, argv in commands:
        command_env = env.copy()
        if label == "pre-commit":
            command_env["SKIP"] = "mypy"
        elif label == "pre-commit-mypy":
            command_env["MYPY_CACHE_DIR"] = "/work/cache/mypy-hook"
        if label == "httpx-environment-diagnostic":
            httpx_diagnostic = httpx_environment_diagnostic(command_env)
            result = {"exit": 0, "output": json.dumps(httpx_diagnostic, sort_keys=True)}
        else:
            result = bounded(argv, cwd="/src", env=command_env, timeout=10 * 60)
        record = "OFFLINE_PROBE_STEP %s exit=%d\n%s" % (label, result["exit"], result["output"])
        print(record, flush=True)
        outputs.append(record)
        if label == "pre-commit-mypy":
            hook_errors = hook_result_accepted(result["output"], result["exit"])
        elif label == "ci-equivalent-mypy":
            need(result["exit"] == 0, "CI_EQUIVALENT_MYPY_EXIT\n" + result["output"][-2000:])
            need(not parse_mypy_errors(result["output"], result["exit"]),
                 "CI_EQUIVALENT_MYPY_ERRORS")
        else:
            need(result["exit"] == 0,
                 "OFFLINE_PROBE_STEP %s exit=%d\n%s" %
                 (label, result["exit"], result["output"][-2000:]))
    need(hook_errors is not None and httpx_diagnostic is not None, "MYPY_CLASSIFICATION_INPUTS")
    classification = {
        "accepted": True,
        "hook_errors": [list(item) for item in sorted(hook_errors)],
        "hook_condition": ("exit-0-clean" if not hook_errors
                           else "exact-known-preexisting-error-set"),
        "ci_equivalent_exit": 0,
        "httpx_environment_gap_proved": httpx_diagnostic["cause_proved"],
        "classification": ("clean" if not hook_errors
                           else "known-preexisting-hook-environment-gap"),
    }
    print("OFFLINE_MYPY_CLASSIFICATION " + json.dumps(classification, sort_keys=True), flush=True)
    os.environ.update(env)
    from huggingface_hub import snapshot_download
    model = spec["model"]
    snapshot = snapshot_download(model["repo"], revision=model["revision"], local_files_only=True)
    need(snapshot.endswith(model["revision"]), "OFFLINE_HF_SNAPSHOT")
    import tiktoken
    for name in spec["tiktoken_encodings"]:
        tiktoken.get_encoding(name)
    ctypes.CDLL(env["ORT_DYLIB_PATH"])
    outputs.append(json.dumps({"offline_hf": model["revision"],
                               "offline_tiktoken": spec["tiktoken_encodings"],
                               "offline_ort": env["ORT_DYLIB_PATH"],
                               "offline_pre_commit": True,
                               "offline_commitlint_range": [spec["commitlint_from"],
                                                             spec["commitlint_to"]]}, sort_keys=True))
    print("OFFLINE_PROBE_ASSETS " + outputs[-1], flush=True)
    return 0


def run(args):
    spec = strict_json(SPEC_PATH)
    need(args.lane in LANES and spec["lanes"] == list(LANES), "LANE")
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=False)
    evidence.chmod(0o777)
    started = time.monotonic()
    try:
        dockerfile_path = evidence / "Dockerfile"
        dockerfile_path.write_text(counted_harness.dockerfile(spec), encoding="utf-8")
        tag = "headroom4452-a27-smoke-" + args.lane
        with tempfile.TemporaryDirectory(prefix="headroom4452-a27-smoke-build-") as tmp:
            context = prepare_build_context(args.source, Path(tmp), spec, evidence)
            shutil.copy2(dockerfile_path, context / "Dockerfile")
            save(evidence / "build-context.json", {
                "temporary_outer_context": True,
                "outside_sealed_source_tree": True,
                "copy_instruction": "COPY source/ /src",
                "full_git_history_copied": True,
                "pre_commit_config_copied": True,
                "tests_copied": True,
            })
            prep = bounded(["docker", "build", "--pull", "--network", "default", "-f",
                            str(context / "Dockerfile"), "-t", tag, str(context)], timeout=50 * 60)
        prep_output = prep.pop("output")
        save_command_evidence(evidence, "preparation", prep, prep_output)
        need(prep["exit"] == 0, "P0_PREPARATION")
        tool_versions = rust_toolchain_versions(prep_output)
        # The executable version/offline probe deliberately precedes identity bookkeeping.
        name = "headroom4452-a27-smoke-" + args.lane + "-" + os.environ.get("GITHUB_RUN_ID", "local")
        command = hardened_run_argv(
            name=name, image=tag, evidence=evidence, runtime=HERE,
            environment=counted_harness.common_env(), inner_argv=[
                "/opt/venv/bin/python", "-I", "-B", "/runtime/smoke.py", "--inside-probe",
            ])
        save(evidence / "command.json", {"argv": command, "network": "none",
                                          "counted_runtime_contract": True})
        probe = bounded(command, timeout=15 * 60)
        probe_output = probe.pop("output")
        probe_evidence = checked_probe_evidence(evidence, probe, probe_output)
        probe_versions = probe_evidence["rust_toolchain_versions"]
        need(probe_versions == tool_versions, "RUST_TOOLCHAIN_PROBE_MISMATCH")
        rust_stage = rust_stage_identity(prep_output, spec)
        images = resolved_images(spec, tag, rust_stage)
        save(evidence / "resolved-images.json", {"lane": args.lane, "images": images})
        save(evidence / "smoke-summary.json", {"schema": "headroom4452-a27-smoke-lane/1",
             "lane": args.lane, "status": "PASS", "counted_attempt": False,
             "project_tests_run": False, "candidate_patch_applied": True,
             "offline_preparation_assets_probed": True,
             "commitlint_config_sha256": spec["commitlint_config_sha256"],
             "commitlint_npm_ls_sha256": hashlib.sha256(
                 (evidence / "commitlint-npm-ls.json").read_bytes()).hexdigest(),
             "mypy_ci_pip_freeze_sha256": hashlib.sha256(
                 (evidence / "mypy-ci-pip-freeze.txt").read_bytes()).hexdigest(),
             "mypy_hook_classification": probe_evidence["mypy_classification"],
             "resolved_images": images,
             "rust_toolchain_versions": tool_versions,
             "elapsed_monotonic_seconds": time.monotonic() - started})
        return 0
    except (Stop, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        save(evidence / "smoke-summary.json", {"schema": "headroom4452-a27-smoke-lane/1",
             "lane": args.lane, "status": "FAIL", "counted_attempt": False,
             "project_tests_run": False, "candidate_patch_applied": True,
             "error": type(exc).__name__ + ": " + str(exc)[:2000],
             "elapsed_monotonic_seconds": time.monotonic() - started})
        return 4


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lane", choices=LANES)
    parser.add_argument("--source")
    parser.add_argument("--evidence")
    parser.add_argument("--inside-probe", action="store_true")
    args = parser.parse_args()
    if args.inside_probe:
        raise SystemExit(inside_probe())
    need(args.lane and args.source and args.evidence, "RUN_ARGUMENTS")
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
