#!/usr/bin/env python3
"""Build the GhostLock helper that Anchor packages as libanchor.so."""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path


def parse_local_properties(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().replace(r"\:", ":").replace(r"\\", "\\")
    return values


def find_ndk(project_dir: Path, explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    for variable in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        if value := os.environ.get(variable):
            candidates.append(Path(value))

    properties = parse_local_properties(project_dir / "local.properties")
    if value := properties.get("ndk.dir"):
        candidates.append(Path(value))
    if value := properties.get("sdk.dir"):
        ndk_root = Path(value) / "ndk"
        if ndk_root.is_dir():
            candidates.extend(sorted(ndk_root.iterdir(), reverse=True))

    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise RuntimeError(
        "Android NDK not found; set ANDROID_NDK_HOME or pass --ndk <path>."
    )


def host_tag() -> str:
    system = platform.system()
    if system == "Windows":
        return "windows-x86_64"
    if system == "Darwin":
        return "darwin-x86_64"
    if system == "Linux":
        return "linux-x86_64"
    raise RuntimeError(f"unsupported build host: {system}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-dir", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ndk")
    args = parser.parse_args()

    project_dir = args.project_dir.resolve()
    source_dir = args.source_dir.resolve()
    ndk = find_ndk(project_dir, args.ndk)
    compiler = (
        ndk
        / "toolchains"
        / "llvm"
        / "prebuilt"
        / host_tag()
        / "bin"
        / "aarch64-linux-android35-clang"
    )
    compiler_args: list[str] = []
    if os.name == "nt":
        # Avoid the .cmd target wrapper: cmd.exe would alter the quoted
        # TARGET_CONFIG_H macro argument. Invoke clang.exe with its target
        # explicitly instead.
        compiler = compiler.parent / "clang.exe"
        compiler_args.append("--target=aarch64-linux-android35")
    if not compiler.is_file():
        raise RuntimeError(f"NDK compiler not found: {compiler}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = args.output.with_suffix(args.output.suffix + ".tmp")
    sources = [
        "src/core/main.c",
        "src/core/util.c",
        "src/core/slide.c",
        "src/core/fops.c",
        "src/core/pipe_physrw.c",
        "src/core/root.c",
        "src/core/miniadb.c",
        "src/core/umh_root.c",
    ]
    command = [
        str(compiler),
        *compiler_args,
        "-O2",
        "-Wall",
        "-Wno-unused-parameter",
        "-Wno-sign-compare",
        "-Wno-unused-function",
        "-Isrc/core",
        "-Isrc/devices",
        '-DTARGET_CONFIG_H="target.h"',
        "-fPIE",
        "-pie",
        "-pthread",
        *sources,
        "-o",
        str(temporary_output),
    ]
    print("Building Anchor native helper with", compiler)
    subprocess.run(command, cwd=source_dir, check=True)
    os.replace(temporary_output, args.output)
    print("Wrote", args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"build_anchor_native: {error}", file=sys.stderr)
        raise SystemExit(1)
