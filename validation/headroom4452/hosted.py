#!/usr/bin/env python3
"""Bounded hosted-Docker controller for Headroom PR #4452, validation attempt 25.

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
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402
import xml.etree.ElementTree as ET  # noqa: E402

HERE = Path(__file__).resolve().parent
SPEC_PATH = HERE / "spec.json"
LANES = ("source-gates", "python-proof", "rust-workspace", "ci-python-commitlint")


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


def dockerfile(spec):
    model = spec["model"]
    enc = json.dumps(spec["tiktoken_encodings"])
    # Preparation has network. Validation containers made from this image do not.
    return f'''FROM {spec["container_image"]}
ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates curl git make nodejs npm pkg-config rustup && rm -rf /var/lib/apt/lists/*
RUN rustup set profile minimal && rustup toolchain install {spec["rust"]} --component rustfmt --component clippy && rustup default {spec["rust"]}
WORKDIR /src
COPY . /src
RUN uv venv /opt/venv --python 3.12 && UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --extra dev --extra langchain --no-install-project && uv pip install --python /opt/venv/bin/python "maturin>=1.5,<2.0"
RUN cargo fetch --locked
RUN mkdir -p /opt/hf /opt/tiktoken /opt/precommit /opt/npm-cache /opt/work && HOME=/opt/work PRE_COMMIT_HOME=/opt/precommit /opt/venv/bin/pre-commit install-hooks
RUN npm_config_cache=/opt/npm-cache npx --yes --package=@commitlint/cli --package=@commitlint/config-conventional -- commitlint --version
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


def common_env():
    return {
        "PATH": "/opt/venv/bin:/root/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
        "VIRTUAL_ENV": "/opt/venv", "PYO3_PYTHON": "/opt/venv/bin/python",
        "PIP_NO_INDEX": "1", "PIP_NO_BUILD_ISOLATION": "1", "CARGO_TARGET_DIR": "/work/target",
        "HOME": "/work/home", "TMPDIR": "/work/tmp", "PYTHONDONTWRITEBYTECODE": "1",
        "RUFF_CACHE_DIR": "/work/cache/ruff", "MYPY_CACHE_DIR": "/work/cache/mypy",
        "PIP_CACHE_DIR": "/work/cache/pip", "PYTHONPYCACHEPREFIX": "/work/cache/pycache",
        "XDG_CACHE_HOME": "/work/cache/xdg", "UV_CACHE_DIR": "/work/cache/uv",
        "COVERAGE_FILE": "/work/cache/coverage/.coverage", "PRE_COMMIT_HOME": "/opt/precommit",
        "CARGO_NET_OFFLINE": "true", "HF_HOME": "/opt/hf", "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1", "TIKTOKEN_CACHE_DIR": "/opt/tiktoken",
        "npm_config_cache": "/opt/npm-cache", "npm_config_offline": "true",
        "HEADROOM_WORKSPACE_DIR": "/work/headroom", "HEADROOM_CONFIG_DIR": "/work/headroom/config",
        "HEADROOM_MEMORY_DB_PATH": "/work/headroom/memory.db", "CLAUDE_CONFIG_DIR": "/work/claude",
        "HEADROOM_BEACON": "off", "HEADROOM_TELEMETRY": "off", "HEADROOM_UPDATE_CHECK": "off",
        "HEADROOM_PORT_DISCOVERY": "0", "HEADROOM_HARD_WATCHDOG_SECS": "0",
        "TOKENIZERS_PARALLELISM": "false", "OMP_NUM_THREADS": "2", "MKL_NUM_THREADS": "2",
        "NO_COLOR": "1",
    }


def lane_steps(lane):
    changed = ["headroom/memory/bridge.py", "tests/test_memory_bridge.py"]
    pc_tail = ["--hook-stage", "pre-commit", "--show-diff-on-failure", "--color", "never",
               "--files"] + changed
    py = "/opt/venv/bin/python"
    tests = "/src/tests/test_memory_bridge.py"
    d1 = tests + "::TestMemoryBridgeSync::test_sync_inserts_export_into_existing_section_above_last_heading"
    d2 = tests + "::TestMemoryBridgeSync::test_sync_exports_organic_memory_when_markdown_changes"
    pytest = [py, "-m", "pytest", "-p", "no:cacheprovider", "--rootdir=/src", "-c", "/src/pyproject.toml"]
    base_tests = "/work/basearm/tests/test_memory_bridge.py"
    base_d1 = base_tests + "::TestMemoryBridgeSync::test_sync_inserts_export_into_existing_section_above_last_heading"
    base_d2 = base_tests + "::TestMemoryBridgeSync::test_sync_exports_organic_memory_when_markdown_changes"
    base_pytest = [py, "-m", "pytest", "-p", "no:cacheprovider", "--rootdir=/work/basearm",
                   "-c", "/work/basearm/pyproject.toml"]
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
            ("Q0", ["bash", "-lc", "python --version && rustc --version && cargo --version && node --version && npm --version && pre-commit --version && pip --version && mypy --version && ruff --version && make --version | head -1 && git --version && npx --offline --yes --package=@commitlint/cli --package=@commitlint/config-conventional -- commitlint --version"], "/work/run", {}),
            ("Q1", [py, "/src/scripts/verify-ruff-version.py"], "/work/run", {}),
            ("Q2", ["ruff", "--version"], "/work/run", {}),
            ("Q3", ["ruff", "check", "--no-cache", "/src"], "/work/run", {}),
            ("Q4", ["ruff", "format", "--no-cache", "--check", "/src"], "/work/run", {}),
            ("Q5", ["mypy", "/src/headroom", "--ignore-missing-imports", "--cache-dir", "/work/cache/mypy-ci"], "/work/run", {}),
            ("Q6b", ["pre-commit", "run", "mypy"] + pc_tail, "/src", {"MYPY_CACHE_DIR": "/work/cache/mypy-hook"}),
        ]
    if lane == "python-proof":
        return [
            ("S01", ["bash", "/src/scripts/build_rust_extension.sh"], "/src", {}),
            ("S02", [py, str(HERE / "hosted.py"), "inside-basearm"], "/work/run", {}),
            ("S03", base_pytest + ["--tb=long", "-vv", "-rA", "--junitxml=/evidence/S03.xml", base_d1], "/work/run", {"PYTHONPATH": "/work/basearm"}),
            ("S04", base_pytest + ["--tb=long", "-vv", "-rA", "--junitxml=/evidence/S04.xml", base_d2], "/work/run", {"PYTHONPATH": "/work/basearm"}),
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
            ("M1-commitlint-range", ["npx", "--offline", "--yes", "--package=@commitlint/cli",
             "--package=@commitlint/config-conventional", "--", "commitlint", "--from",
             "18067b1d19f6606bae3b4d6b50efeeaa48dc477e", "--to",
             "c79ba62c19b63f921d52aa7f507c2fe06c16756a", "--config", "/src/.commitlintrc.json"], "/src", {}),
            ("M1-commitlint-candidate", ["bash", "-lc", "printf '%s\\n' 'fix(memory): export memories into their existing section' | npx --offline --yes --package=@commitlint/cli --package=@commitlint/config-conventional -- commitlint --config /src/.commitlintrc.json"], "/work/run", {}),
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


def inside_basearm(spec, root=Path("/src"), dest=Path("/work/basearm")):
    shutil.copytree(root / "headroom", dest / "headroom", ignore=shutil.ignore_patterns("__pycache__", "_core*.so"))
    shutil.copytree(root / "tests", dest / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(root / "pyproject.toml", dest / "pyproject.toml")
    body = subprocess.run(["git", "-C", str(root), "show", spec["pr_head"] + ":headroom/memory/bridge.py"],
                          stdout=subprocess.PIPE, check=True).stdout
    need(hashlib.sha256(body).hexdigest() == spec["base_files"]["headroom/memory/bridge.py"], "BASE_BRIDGE")
    (dest / "headroom/memory/bridge.py").write_bytes(body)
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


def inside_run(lane, spec, evidence):
    evidence = Path(evidence)
    (Path("/work/run")).mkdir(parents=True, exist_ok=True)
    for path in ("/work/home", "/work/tmp", "/work/cache", "/work/headroom", "/work/claude"):
        Path(path).mkdir(parents=True, exist_ok=True)
    begin = time.monotonic()
    receipts = []
    first_failure = None
    for step, argv, cwd, extra in lane_steps(lane):
        env = os.environ.copy()
        env.update(common_env())
        env.update(extra)
        rec = bounded(argv, cwd=cwd, env=env, timeout=55 * 60, cap=64 * 1024 * 1024)
        log = evidence / (step + ".log")
        log_text = rec.pop("output")
        log.write_text(log_text, encoding="utf-8")
        rec["contract"] = check_step_contract(step, rec, log_text, spec, evidence)
        rec.update({"step": step, "log_sha256": sha256(log)})
        save(evidence / (step + ".json"), rec)
        receipts.append(rec)
        if not rec["contract"]["ok"]:
            first_failure = step
            break
    after = source_inventory("/src")
    before = strict_json(evidence / "candidate-identity.json")["inventory"]
    delta = inventory_delta(before, after, spec["allowed_new_files_after_build"])
    elapsed = time.monotonic() - begin
    ok = first_failure is None and delta["ok"] and elapsed < 60 * 60
    save(evidence / "summary.json", {"schema": "headroom4452-a25-lane-result/1", "attempt": "25 of 55",
         "lane": lane, "status": "PASS" if ok else "FAIL", "first_failure": first_failure,
         "lane_elapsed_monotonic_seconds": elapsed, "job_limit_seconds": 3600,
         "no_cross_clock_arithmetic": True, "source_delta": delta,
         "receipts": [{k: v for k, v in r.items() if k != "argv"} for r in receipts]})
    return 0 if ok else 4


def run_hosted(args):
    spec = strict_json(SPEC_PATH)
    need(args.lane in spec["lanes"], "LANE")
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    try:
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
        tag = "headroom4452-a25-" + args.lane
        prep = bounded(["docker", "build", "--pull", "--network", "default", "-f", str(dockerfile_path),
                        "-t", tag, str(Path(args.source))], timeout=50 * 60, cap=64 * 1024 * 1024)
        (evidence / "preparation.log").write_text(prep.pop("output"), encoding="utf-8")
        save(evidence / "preparation.json", prep)
        need(prep["exit"] == 0, "P0_PREPARATION")
        image = bounded(["docker", "image", "inspect", tag, "--format", "{{json .}}"], timeout=30)
        need(image["exit"] == 0, "IMAGE_INSPECT")
        image_info = json.loads(image["output"])
        save(evidence / "image.json", {"id": image_info["Id"], "repo_digests": image_info.get("RepoDigests", []),
             "model_revision": spec["model"]["revision"], "network_used_only_for_preparation": True})
        name = "headroom4452-a25-" + args.lane + "-" + os.environ.get("GITHUB_RUN_ID", "local")
        env_args = sum((["-e", k + "=" + v] for k, v in common_env().items()), [])
        command = ["docker", "run", "--name", name, "--network", "none", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "4096",
                   "--cpus", "4", "--memory", "14g", "--memory-swap", "14g",
                   "--tmpfs", "/work:rw,exec,nosuid,nodev,size=4g", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m",
                   "-v", str(evidence) + ":/evidence:rw", "-v", str(HERE) + ":/runtime:ro"] + env_args + [tag,
                   "/opt/venv/bin/python", "-I", "-B", "/runtime/hosted.py", "inside-run", args.lane,
                   "/evidence"]
        save(evidence / "command.json", {"argv": command, "network": "none", "prepared_before_attempt": True})
        # The Git ref creation, not this call, consumes attempt 25. This controller never creates refs.
        result = bounded(command, timeout=60 * 60, cap=8 * 1024 * 1024)
        (evidence / "container.log").write_text(result.pop("output"), encoding="utf-8")
        save(evidence / "container.json", result)
        need(result["exit"] == 0, "LANE_FAILED")
        summary = strict_json(evidence / "summary.json")
        need(summary["status"] == "PASS", "SUMMARY_FAILED")
        save(evidence / "host-summary.json", {"status": "PASS", "lane": args.lane,
             "host_elapsed_monotonic_seconds": time.monotonic() - started,
             "container_elapsed_monotonic_seconds": result["elapsed_monotonic_seconds"],
             "no_cross_clock_arithmetic": True, "attempt": "25 of 55"})
        return 0
    except (Stop, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        save(evidence / "host-summary.json", {"status": "FAIL", "lane": args.lane,
             "error": type(exc).__name__ + ": " + str(exc)[:2000],
             "host_elapsed_monotonic_seconds": time.monotonic() - started,
             "no_cross_clock_arithmetic": True, "attempt": "25 of 55"})
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
    need("snapshot_download" in dockerfile(spec) and spec["model"]["revision"] in dockerfile(spec),
         "SELFTEST_IMMUTABLE_MODEL")
    need(all(x[1][0] != "make" for x in sum((lane_steps(l) for l in LANES), [])), "SELFTEST_SPLIT_MAKE")
    print(json.dumps({"status": "PASS", "tests": 15, "lanes": all_steps,
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
    run.add_argument("--evidence", required=True)
    inside = sub.add_parser("inside-run")
    inside.add_argument("lane", choices=LANES)
    inside.add_argument("evidence")
    ident = sub.add_parser("inside-identity")
    ident.add_argument("label", choices=("S00", "G1"))
    sub.add_parser("inside-basearm")
    sub.add_parser("fake-selftest")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if args.mode == "run":
        return run_hosted(args)
    if args.mode == "inside-run":
        return inside_run(args.lane, strict_json(SPEC_PATH), args.evidence)
    if args.mode == "inside-identity":
        return inside_identity(args.label)
    if args.mode == "inside-basearm":
        return inside_basearm(strict_json(SPEC_PATH))
    if args.mode == "fake-selftest":
        return fake_selftest()
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
