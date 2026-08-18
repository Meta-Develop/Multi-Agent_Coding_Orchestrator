#!/usr/bin/env python3
"""Run a command inside a delegated systemd user manager, or fail closed."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


class DelegationError(RuntimeError):
    """The environment cannot provide a delegated systemd user manager."""


def delegated_user_manager_available(cgroups: str) -> bool:
    current = next(
        (line[3:] for line in cgroups.splitlines() if line.startswith("0::")),
        None,
    )
    if current is None:
        return False
    return any(
        component.startswith("user@") and component.endswith(".service")
        for component in current.split("/")
    )


def read_current_cgroup() -> str:
    return Path("/proc/self/cgroup").read_text(encoding="utf-8")


def current_cgroup_path(cgroups: str) -> str:
    return next(
        (line[3:] for line in cgroups.splitlines() if line.startswith("0::")),
        "<unified cgroup v2 entry absent>",
    )


def _sudo_prefix() -> list[str]:
    sudo = shutil.which("sudo")
    if sudo is None:
        return []
    probe = subprocess.run(
        [sudo, "-n", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return [sudo] if probe.returncode == 0 else []


def ensure_runtime_dir(runtime_dir: Path, uid: int) -> None:
    if runtime_dir.is_dir():
        return
    sudo = _sudo_prefix()
    if not sudo:
        raise DelegationError(
            f"delegated user manager requires owner-private {runtime_dir}"
        )
    subprocess.run([*sudo, "mkdir", "-p", str(runtime_dir)], check=True)
    subprocess.run(
        [*sudo, "chown", f"{uid}:{uid}", str(runtime_dir)],
        check=True,
    )
    subprocess.run([*sudo, "chmod", "700", str(runtime_dir)], check=True)


def start_user_manager(uid: int, user: str, runtime_dir: Path) -> None:
    sudo = _sudo_prefix()
    loginctl = shutil.which("loginctl")
    systemctl = shutil.which("systemctl")
    if sudo and loginctl:
        subprocess.run(
            [*sudo, loginctl, "enable-linger", user],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if sudo and systemctl:
        subprocess.run(
            [*sudo, systemctl, "start", f"user@{uid}.service"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    bus = runtime_dir / "bus"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if bus.is_socket():
            return
        time.sleep(0.2)
    if not bus.is_socket():
        raise DelegationError(
            f"user manager bus was not created at {bus}"
        )


def systemd_run_command(args: list[str], *, inherit_environment: bool) -> list[str]:
    systemd_run = shutil.which("systemd-run")
    if systemd_run is None:
        raise DelegationError("systemd-run is required for delegated containment")
    command = [
        systemd_run,
        "--user",
        "--wait",
        "--collect",
        "--pipe",
        "--same-dir",
        f"--working-directory={os.getcwd()}",
    ]
    if inherit_environment:
        command.extend(f"--setenv={name}" for name in os.environ)
    command.append("--")
    command.extend(args)
    return command


def probe_user_manager_cgroup() -> str:
    probe = systemd_run_command(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; print(Path('/proc/self/cgroup').read_text())",
        ],
        inherit_environment=False,
    )
    # The probe only needs the runtime bus, not the full CI environment.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "XDG_RUNTIME_DIR": os.environ["XDG_RUNTIME_DIR"],
    }
    if "DBUS_SESSION_BUS_ADDRESS" in os.environ:
        env["DBUS_SESSION_BUS_ADDRESS"] = os.environ["DBUS_SESSION_BUS_ADDRESS"]
    completed = subprocess.run(
        probe,
        check=False,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
        raise DelegationError(f"failed to start a systemd --user probe unit: {detail}")
    return completed.stdout


def prepare_environment() -> None:
    uid = os.getuid()
    runtime_dir = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{uid}"))
    os.environ["XDG_RUNTIME_DIR"] = str(runtime_dir)
    os.environ.setdefault(
        "DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime_dir / 'bus'}"
    )
    ensure_runtime_dir(runtime_dir, uid)
    if delegated_user_manager_available(read_current_cgroup()):
        return
    start_user_manager(uid, _current_user_name(), runtime_dir)


def _current_user_name() -> str:
    name = os.environ.get("USER") or os.environ.get("LOGNAME")
    if name:
        return name
    import pwd

    return pwd.getpwuid(os.getuid()).pw_name


def run_command(args: list[str]) -> int:
    prepare_environment()
    if delegated_user_manager_available(read_current_cgroup()):
        completed = subprocess.run(args, check=False)
        return completed.returncode

    probe = probe_user_manager_cgroup()
    if not delegated_user_manager_available(probe):
        raise DelegationError(
            "current cgroup "
            f"{current_cgroup_path(probe)} is not inside a delegated "
            "systemd user manager"
        )
    completed = subprocess.run(
        systemd_run_command(args, inherit_environment=True),
        check=False,
    )
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run a command inside a delegated systemd user manager. "
            "Fails closed when the manager is unavailable."
        )
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="command to execute after --",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    try:
        return run_command(command)
    except DelegationError as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
