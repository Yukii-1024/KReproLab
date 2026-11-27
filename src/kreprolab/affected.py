"""从 collect_cve 产出的 run 目录中筛选受影响的 Linux 内核版本号。

调用方传入 collect_cve() 返回的 run 目录（如 "runtime/20261127deepseek-flash-1"），
本模块读取该目录下的 cve.json。

筛选规则：upstream_kernel[].products[].versions[] 中 status == "affected" 的版本。
优先返回纯点分数字；否则把 "Linux Kernel 5.17 rc6" 这类公告字符串归一化为
"5.17-rc6"。stable 版本优先于 rc 版本。
"""

import json
import re
from pathlib import Path

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")
_ADVISORY_VERSION_RE = re.compile(
    r"(?<!\d)(\d+\.\d+(?:\.\d+)?)(?:\s*[- ]?rc\s*(\d+))?(?!\d)",
    re.IGNORECASE,
)


def _normalize_version(value: str) -> str | None:
    value = value.strip()
    if _VERSION_RE.fullmatch(value):
        return value
    match = _ADVISORY_VERSION_RE.search(value)
    if match is None:
        return None
    base = match.group(1)
    rc = match.group(2)
    return f"{base}-rc{rc}" if rc else base


def affected_linux_version(run_directory: str | Path) -> str:
    """返回指定 run 目录的 cve.json 中被标注为受影响的 Linux 内核版本号。

    Args:
        run_directory: collect_cve() 返回的 run 目录路径。

    Returns:
        版本号字符串，如 "6.8" 或 "5.17-rc6"。

    Raises:
        FileNotFoundError: cve.json 不存在。
        ValueError: JSON 不合法，或其中没有可归一化的受影响版本条目。
    """
    path = Path(run_directory) / "cve.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise FileNotFoundError(f"runtime 目录下不存在 cve.json: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"JSON 解析失败: {path}: {error}") from error

    stable_versions = []
    rc_versions = []
    for container in record.get("upstream_kernel") or []:
        for product in container.get("products") or []:
            for entry in product.get("versions") or []:
                if entry.get("status") != "affected":
                    continue
                version = _normalize_version(str(entry.get("version") or ""))
                if version is None:
                    continue
                if "-rc" in version:
                    rc_versions.append(version)
                else:
                    stable_versions.append(version)
    if stable_versions:
        return stable_versions[0]
    if rc_versions:
        return rc_versions[0]
    raise ValueError(f"未找到可归一化的 status=affected Linux 版本号: {path}")
