#!/usr/bin/env python3
"""Single hardened Docker-run argv builder shared by counted and smoke payloads."""


def hardened_run_argv(*, name, image, evidence, runtime, environment, inner_argv):
    """Return the complete counted runtime contract in deterministic argv order."""
    env_args = []
    for key, value in environment.items():
        env_args.extend(("-e", key + "=" + value))
    return [
        "docker", "run", "--rm", "--name", name,
        "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "4096", "--cpus", "4",
        "--memory", "14g", "--memory-swap", "14g",
        "--tmpfs", "/work:rw,exec,nosuid,nodev,size=4g",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=128m",
        "--mount", "type=volume,dst=/src",
        "--mount", "type=volume,dst=/opt/venv",
        "--mount", "type=volume,dst=/cargo-target",
        "--tmpfs", "/opt/precommit:rw,exec,nosuid,nodev,size=2g",
        "--tmpfs", "/opt/npm-cache:rw,exec,nosuid,nodev,size=512m",
        "-v", str(evidence) + ":/evidence:rw",
        "-v", str(runtime) + ":/runtime:ro",
        *env_args, image, *inner_argv,
    ]
