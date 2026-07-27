#!/usr/bin/env python3
"""Generate one device offset-table entry from a kernel image.

The symbol table is intentionally an explicit input.  Android boot images do
not contain a universally parseable kallsyms dump, so silently using a
machine-specific file would produce unsafe offsets.

Example:
  python tools/all.py boot.img --kallsyms cph2655.kallsyms \
      --output src/devices/op13/offsets.generated.h \
      --kernel-phys-load 0xa8000000 --struct-layout 6.6 --pselect-shift -2
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parent
RELEASE_RE = re.compile(rb"Linux version ([^\x00\s]+)")
HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")

BTF_MAP = {
    "FAKE_TASK_PRIO_OFF": ".task_prio",
    "FAKE_TASK_NORMAL_PRIO_OFF": ".task_normal_prio",
    "FAKE_TASK_TASK_GROUP_OFF": ".task_sched_task_group",
    "FAKE_TASK_PI_LOCK_OFF": ".task_pi_lock",
    "FAKE_TASK_PI_WAITERS_OFF": ".task_pi_waiters",
    "FAKE_TASK_PI_TOP_TASK_OFF": ".task_pi_top_task",
    "FAKE_TASK_PI_BLOCKED_ON_OFF": ".task_pi_blocked_on",
    "TASK_PID_OFF": ".task_pid",
    "TASK_TGID_OFF": ".task_tgid",
    "TASK_REAL_PARENT_OFF": ".task_real_parent",
    "TASK_ATOMIC_FLAGS_OFF": ".task_atomic_flags",
    "TASK_REAL_CRED_OFF": ".task_real_cred",
    "TASK_CRED_OFF": ".task_cred",
    "TASK_COMM_OFF": ".task_comm",
    "TASK_TASKS_OFF": ".task_tasks",
    "TASK_SECCOMP_OFF": ".task_seccomp",
    "MM_OWNER_OFF": ".mm_owner",
}

TARGET_MAP = {
    "SLIDE_RANDOM_BOOT_ID_DATA_OFF": ".off_slide_boot_id",
    "SLIDE_SYSCTL_BOOTID_OFF": ".off_slide_boot_id",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("boot_img", type=Path)
    parser.add_argument("--kallsyms", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kernel", type=Path,
                        help="raw kernel; otherwise extract it from boot_img")
    parser.add_argument("--kernel-phys-load", type=lambda value: int(value, 0))
    parser.add_argument("--struct-layout", choices=("6.6", "6.12"))
    parser.add_argument("--pselect-shift", type=int)
    parser.add_argument("--device", default="generated")
    return parser.parse_args()


def extract_kernel(boot_img: Path) -> bytes:
    try:
        sys.path.insert(0, str(TOOLS_DIR))
        from check_feasibility import extract_kernel_from_bootimg
        data = extract_kernel_from_bootimg(str(boot_img))
    except Exception as exc:
        raise RuntimeError(f"cannot extract kernel from {boot_img}: {exc}") from exc
    if not data:
        raise RuntimeError("boot image did not yield a kernel payload")
    return data


def kernel_release(kernel: bytes) -> str:
    match = RELEASE_RE.search(kernel)
    if not match:
        raise RuntimeError("Linux version banner not found in kernel image")
    return match.group(1).decode("ascii", errors="strict")


def run_extract_target(kallsyms: Path) -> str:
    import subprocess

    command = [sys.executable, str(TOOLS_DIR / "extract_target.py"),
               "--kallsyms", str(kallsyms)]
    result = subprocess.run(command, check=False, capture_output=True,
                            text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "extract_target.py failed")
    return result.stdout


def parse_offset_output(text: str, btf: bool = False) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or not HEX_RE.fullmatch(parts[1]):
            continue
        name = parts[0]
        if btf:
            field = BTF_MAP.get(name)
        elif name.endswith("_OFF"):
            field = TARGET_MAP.get(name, ".off_" + name[:-4].lower())
        else:
            field = None
        if field:
            values[field] = parts[1]
    return values


def generate(args: argparse.Namespace) -> None:
    boot_img = args.boot_img.resolve()
    kallsyms = args.kallsyms.resolve()
    if not boot_img.is_file():
        raise RuntimeError(f"boot image not found: {boot_img}")
    if not kallsyms.is_file():
        raise RuntimeError(f"kallsyms file not found: {kallsyms}")

    kernel = args.kernel.resolve().read_bytes() if args.kernel else extract_kernel(boot_img)
    release = kernel_release(kernel)

    with tempfile.NamedTemporaryFile(prefix="ghostlock-kernel-", suffix=".raw",
                                     delete=False) as handle:
        handle.write(kernel)
        kernel_path = Path(handle.name)
    try:
        target_text = run_extract_target(kallsyms)
        import subprocess
        btf_cmd = [sys.executable, str(TOOLS_DIR / "extract_btf.py"), str(kernel_path)]
        btf_result = subprocess.run(btf_cmd, check=False, capture_output=True,
                                    text=True, encoding="utf-8", errors="replace")
        if btf_result.returncode:
            raise RuntimeError(btf_result.stderr.strip() or "extract_btf.py failed")
    finally:
        kernel_path.unlink(missing_ok=True)

    values = parse_offset_output(target_text)
    values.update(parse_offset_output(btf_result.stdout, btf=True))
    if not values:
        raise RuntimeError("no valid hexadecimal offsets were extracted")

    lines = [f'/* Generated for {args.device}; verify before deployment. */',
             f'OFFSETS_ENTRY("{release}",  /* generated */']
    if args.kernel_phys_load is not None:
        lines.append(f"  .kernel_phys_load=0x{args.kernel_phys_load:X},")
    if args.struct_layout:
        lines.append(f"  STRUCT_OFFSETS_{args.struct_layout.replace('.', '_')},")
    if args.pselect_shift is not None:
        lines.append(f"  .pselect_shift={args.pselect_shift},")
    for field in sorted(values):
        lines.append(f"  {field}={values[field]},")
    lines.extend(["),", ""])

    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n",
                                     dir=output.parent, delete=False) as handle:
        handle.write("\n".join(lines))
        temp_path = Path(handle.name)
    os.replace(temp_path, output)
    print(f"Generated {output} for {release} ({len(values)} offsets)")


if __name__ == "__main__":
    try:
        generate(parse_args())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
