"""使用最小触发配置构建 x86_64 内核镜像。

输入：run 目录中的 resolved.config 和 linux-<版本>/ 源码。
输出：bzImage、build.log、build.json；若 gating symbol 以模块形式编译，
还会构建并安装 modules/，避免漏洞代码只存在于未加载的模块中。
测试构建会禁用 QEMU/BIOS 不需要的 CONFIG_EFI_STUB，并通过临时 CC wrapper
把内核顶层 Makefile 的 -std=gnu89/gnu11 补回给自行重置 flags 的子目录，
并强制 -fno-PIE，避免新 GCC 的 C23/默认 PIE 破坏旧内核。构建产物统一放在
<run>/build/，内核 O= 目录为 <run>/build/kernel/。
"""

import json
import os
import re
import shutil
import subprocess
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ARCH = "x86_64"
BASE_CONFIG = "x86_64_defconfig"
RESOLVED_CONFIG = "resolved.config"
IMAGE = "bzImage"
BUILD_ROOT = "build"
KERNEL_DIRECTORY = "kernel"
BUILD_LOG = "build.log"
BUILD_REPORT = "build.json"
MODULES_DIRECTORY = "modules"
TEST_OVERLAY = ("CONFIG_EFI_STUB",)


@dataclass(frozen=True)
class BuildArtifacts:
    image: Path
    report: Path
    modules: Path | None


def _write_json(path: Path, data: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _log_tail(path: Path, lines: int = 30) -> str:
    with path.open(encoding="utf-8", errors="replace") as handle:
        return "".join(deque(handle, maxlen=lines)).strip()


def _disable_symbol(config: Path, symbol: str) -> None:
    disabled = f"# {symbol} is not set"
    lines = [
        line
        for line in config.read_text(encoding="utf-8").splitlines()
        if not line.startswith(f"{symbol}=") and line.strip() != disabled
    ]
    lines.append(disabled)
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _compiler_standard(source: Path) -> str:
    try:
        text = (source / "Makefile").read_text(encoding="utf-8")
    except OSError:
        return "-std=gnu89"
    match = re.search(r"-std=(gnu[0-9]+)", text)
    return f"-std={match.group(1)}" if match else "-std=gnu89"


def _compiler_wrapper(source: Path, build_directory: Path) -> tuple[Path, str]:
    standard = _compiler_standard(source)
    wrapper = (build_directory / "cc-wrapper.sh").resolve()
    wrapper.write_text(f'#!/bin/sh\nexec gcc {standard} -fno-PIE "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    return wrapper, standard


def _run_make(command: list[str], log, log_path: Path) -> None:
    log.write(f"$ {' '.join(command)}\n")
    log.flush()
    result = subprocess.run(
        command,
        stdout=log,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode:
        log.flush()
        raise ValueError(
            f"kernel build command failed ({' '.join(command)}):\n{_log_tail(log_path)}"
        )


def _read_gating(report_path: Path) -> dict:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    validation = report.get("validation")
    if not isinstance(validation, dict):
        return {}
    gating = validation.get("gating_results")
    return gating if isinstance(gating, dict) else {}


def build_kernel_image(run_directory: str | Path, version: str) -> BuildArtifacts:
    """从 resolved.config 构建 bzImage，返回镜像和报告路径。

    构建使用独立的 O=build 目录，不修改源码树。若 trigger-config.json 中
    任一 gating symbol 解析为 m，则同时构建并安装模块到 run/modules/。
    """
    run_directory = Path(run_directory).resolve()
    build_root = run_directory / BUILD_ROOT
    source = run_directory / f"linux-{version}"
    config = build_root / RESOLVED_CONFIG
    if not source.is_dir():
        raise FileNotFoundError(f"kernel source directory is missing: {source}")
    if not config.is_file():
        raise FileNotFoundError(f"resolved kernel config is missing: {config}")

    report_path = build_root / BUILD_REPORT
    image = build_root / IMAGE
    if report_path.is_file() and image.is_file():
        try:
            existing = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            existing = {}
        if existing.get("status") == "completed":
            recorded = existing.get("modules")
            modules = run_directory / recorded if isinstance(recorded, str) and recorded else None
            if modules is None or modules.is_dir():
                return BuildArtifacts(image, report_path, modules)

    build_root.mkdir(parents=True, exist_ok=True)
    kernel_directory = build_root / KERNEL_DIRECTORY
    modules_directory = build_root / MODULES_DIRECTORY
    log_path = build_root / BUILD_LOG
    kernel_directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(config, kernel_directory / ".config")
    for symbol in TEST_OVERLAY:
        _disable_symbol(kernel_directory / ".config", symbol)
    compiler_wrapper, compiler_standard = _compiler_wrapper(source, build_root)
    compiler = f"CC={compiler_wrapper}"

    cve_id = ""
    try:
        cve = json.loads((run_directory / "cve.json").read_text(encoding="utf-8"))
        cve_id = cve.get("cve_id") if isinstance(cve.get("cve_id"), str) else ""
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        pass

    gating = _read_gating(build_root / "trigger-config.json")
    build_modules = any(value == "m" for value in gating.values() if isinstance(value, str))
    jobs = os.cpu_count() or 1
    started = datetime.now().astimezone()
    report = {
        "schema_version": 1,
        "stage": "build_kernel",
        "cve_id": cve_id,
        "kernel_version": version,
        "arch": ARCH,
        "base_config": BASE_CONFIG,
        "config": f"{BUILD_ROOT}/{RESOLVED_CONFIG}",
        "overlay": [f"{symbol}=n" for symbol in TEST_OVERLAY],
        "compiler_standard": compiler_standard,
        "compiler_wrapper": f"{BUILD_ROOT}/cc-wrapper.sh",
        "source": source.name,
        "build_directory": f"{BUILD_ROOT}/{KERNEL_DIRECTORY}",
        "log": f"{BUILD_ROOT}/{BUILD_LOG}",
        "jobs": jobs,
        "started_at": started.isoformat(),
        "status": "running",
        "modules": f"{BUILD_ROOT}/{MODULES_DIRECTORY}" if build_modules else None,
    }
    _write_json(report_path, report)

    commands = [
        ["make", "-C", str(source), f"O={kernel_directory}", compiler, "olddefconfig"],
        ["make", "-C", str(source), f"O={kernel_directory}", compiler, f"-j{jobs}", "bzImage"],
    ]
    if build_modules:
        commands.extend([
            ["make", "-C", str(source), f"O={kernel_directory}", compiler, f"-j{jobs}", "modules"],
            [
                "make",
                "-C",
                str(source),
                f"O={kernel_directory}",
                compiler,
                f"INSTALL_MOD_PATH={modules_directory}",
                "modules_install",
            ],
        ])

    try:
        with log_path.open("w", encoding="utf-8") as log:
            for command in commands:
                _run_make(command, log, log_path)
        built_image = kernel_directory / "arch/x86/boot" / IMAGE
        if not built_image.is_file():
            raise ValueError(f"build completed without producing {built_image}")
        shutil.copyfile(built_image, image)
        if build_modules and not (modules_directory / "lib/modules").is_dir():
            raise ValueError(f"modules_install did not populate {modules_directory / 'lib/modules'}")
    except (OSError, ValueError) as error:
        report.update(
            status="failed",
            finished_at=datetime.now().astimezone().isoformat(),
            error=str(error),
        )
        _write_json(report_path, report)
        raise

    report.update(
        status="completed",
        finished_at=datetime.now().astimezone().isoformat(),
        image=f"{BUILD_ROOT}/{IMAGE}",
        image_bytes=image.stat().st_size,
        modules=f"{BUILD_ROOT}/{MODULES_DIRECTORY}" if build_modules else None,
    )
    _write_json(report_path, report)
    return BuildArtifacts(image, report_path, modules_directory if build_modules else None)
