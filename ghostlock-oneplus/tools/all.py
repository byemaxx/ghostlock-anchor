#!/usr/bin/env python3
"""Generate one device offset-table entry from a kernel image.

The symbol table is intentionally an explicit input.  Android boot images do
not contain a universally parseable kallsyms dump, so silently using a
machine-specific file would produce unsafe offsets.

Example:
  python tools/all.py boot.img \
      --output src/devices/op13/offsets.generated.h \
      --kernel-phys-load 0xa8000000 --struct-layout 6.6 --pselect-shift -2
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parent
RELEASE_RE = re.compile(rb"Linux version ([^\x00\s]+)")
HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
OP13_KERNEL_PHYS_LOAD = 0xA8000000

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

REQUIRED_TARGET_FIELDS = {
    ".off_init_task", ".off_init_cred", ".off_init_uts_ns",
    ".off_empty_zero_page", ".off_root_task_group",
    ".off_selinux_enforcing", ".off_kptr_restrict",
    ".off_selinux_blob_sizes", ".off_kmalloc_caches",
    ".off_anon_pipe_buf_ops", ".off_ashmem_fops",
    ".off_ashmem_ioctl", ".off_ashmem_compat_ioctl",
    ".off_ashmem_mmap", ".off_ashmem_open", ".off_ashmem_release",
    ".off_ashmem_show_fdinfo", ".off_configfs_read_iter",
    ".off_configfs_bin_write_iter", ".off_copy_splice_read",
    ".off_noop_llseek", ".off_slide_nfulnl_logger",
    ".off_slide_loggers_0_1", ".off_slide_boot_id",
    ".off_system_unbound_wq", ".off_call_usermodehelper_exec_work",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("boot_img", type=Path)
    parser.add_argument("--kallsyms", type=Path,
                        help="optional kallsyms/nm dump; auto-discovered beside boot.img")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kernel", type=Path,
                        help="raw kernel; otherwise extract it from boot_img")
    parser.add_argument("--kernel-phys-load", type=lambda value: int(value, 0))
    parser.add_argument("--struct-layout", choices=("6.6", "6.12"))
    parser.add_argument("--pselect-shift", type=int)
    parser.add_argument("--device", default="generated")
    return parser.parse_args()


def is_op13_output(args: argparse.Namespace) -> bool:
    device = args.device.lower().replace("-", "").replace("_", "")
    output = args.output.as_posix().lower()
    return device in {"op13", "oneplus13", "cph2655", "in2060"} or "/op13/" in output


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


def discover_kallsyms(boot_img: Path, kernel_arg: Path | None,
                      explicit: Path | None) -> Path | None:
    if explicit:
        candidate = explicit.resolve()
        if not candidate.is_file():
            raise RuntimeError(f"kallsyms file not found: {candidate}")
        return candidate
    candidates = [
        boot_img.with_name(boot_img.stem + ".kallsyms.txt"),
        boot_img.with_name("kallsyms.txt"),
    ]
    if kernel_arg:
        kernel = kernel_arg.resolve()
        candidates.extend([kernel.with_name(kernel.name + ".kallsyms.txt"),
                           kernel.with_name("kallsyms.txt")])
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def find_nm() -> str | None:
    for name in ("llvm-nm", "llvm-nm.exe", "nm", "nm.exe"):
        found = shutil.which(name)
        if found:
            return found
    ndk_root = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if ndk_root:
        candidates = Path(ndk_root).glob("toolchains/llvm/prebuilt/*/bin/llvm-nm.exe")
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
    sdk_ndk = Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "ndk"
    if sdk_ndk.is_dir():
        for candidate in sdk_ndk.glob("*/toolchains/llvm/prebuilt/*/bin/llvm-nm.exe"):
            if candidate.is_file():
                return str(candidate)
    return None


def find_decoder() -> str | None:
    candidates = [shutil.which("vmlinux-to-elf"), shutil.which("vmlinux_to_elf"),
                  str(Path(sys.executable).parent / "vmlinux-to-elf.exe"),
                  str(Path(sys.executable).parent / "vmlinux-to-elf"),
                  str(Path(sys.executable).parent / "Scripts" / "vmlinux-to-elf.exe"),
                  str(Path(sys.executable).parent / "Scripts" / "vmlinux-to-elf")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def decode_kallsyms(kernel_path: Path, work_dir: Path) -> Path:
    decoder = find_decoder()
    nm = find_nm()
    if not decoder:
        raise RuntimeError(
            "no kallsyms dump found and vmlinux-to-elf is unavailable; install "
            "it with `python -m pip install vmlinux-to-elf` or place "
            "<boot-stem>.kallsyms.txt beside boot.img")
    if not nm:
        raise RuntimeError("vmlinux-to-elf found, but llvm-nm/nm is unavailable")

    elf_path = work_dir / "kernel.vmlinux.elf"
    symbols_path = work_dir / "kernel.kallsyms.txt"
    result = subprocess.run([decoder, str(kernel_path), str(elf_path)],
                            check=False, capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"vmlinux-to-elf failed: {detail}")
    nm_result = subprocess.run([nm, "-n", str(elf_path)], check=False,
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
    if nm_result.returncode or not nm_result.stdout.strip():
        detail = nm_result.stderr.strip() or "no symbols returned"
        raise RuntimeError(f"nm failed: {detail}")
    symbols_path.write_text(nm_result.stdout, encoding="utf-8", newline="\n")
    return symbols_path


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
    if not boot_img.is_file():
        raise RuntimeError(f"boot image not found: {boot_img}")

    kernel = args.kernel.resolve().read_bytes() if args.kernel else extract_kernel(boot_img)
    release = kernel_release(kernel)

    kernel_phys_load = args.kernel_phys_load
    if is_op13_output(args):
        if kernel_phys_load is not None and kernel_phys_load != OP13_KERNEL_PHYS_LOAD:
            raise RuntimeError(
                "all OP13 entries must use kernel_phys_load=0xa8000000; "
                f"received 0x{kernel_phys_load:X}")
        kernel_phys_load = OP13_KERNEL_PHYS_LOAD

    with tempfile.TemporaryDirectory(prefix="ghostlock-offsets-") as temp_dir:
        temp_root = Path(temp_dir)
        kernel_path = temp_root / "kernel.raw"
        kernel_path.write_bytes(kernel)
        kallsyms = discover_kallsyms(boot_img, args.kernel, args.kallsyms)
        if not kallsyms:
            kallsyms = decode_kallsyms(kernel_path, temp_root)
        target_text = run_extract_target(kallsyms)
        btf_cmd = [sys.executable, str(TOOLS_DIR / "extract_btf.py"), str(kernel_path)]
        btf_result = subprocess.run(btf_cmd, check=False, capture_output=True,
                                    text=True, encoding="utf-8", errors="replace")
        if btf_result.returncode:
            raise RuntimeError(btf_result.stderr.strip() or "extract_btf.py failed")

    values = parse_offset_output(target_text)
    values.update(parse_offset_output(btf_result.stdout, btf=True))
    if not values:
        raise RuntimeError("no valid hexadecimal offsets were extracted")
    missing = sorted(REQUIRED_TARGET_FIELDS - values.keys())
    if missing:
        raise RuntimeError(
            "kallsyms extraction is incomplete; missing target offsets: "
            + ", ".join(missing))

    lines = [f'/* Generated for {args.device}; verify before deployment. */',
             f'OFFSETS_ENTRY("{release}",  /* generated */']
    if kernel_phys_load is not None:
        lines.append(f"  .kernel_phys_load=0x{kernel_phys_load:X},")
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
