"""从 runtime/<run 目录>/cve.json 中筛选受影响的 Linux 内核版本号。

调用方只传 run 目录名（如 "20261127deepseek-flash-1"）；
cve.json 路径基于本模块位置解析：src/kreprolab -> 仓库根 -> runtime/<目录>/cve.json。

筛选规则：upstream_kernel[].products[].versions[] 中 status == "affected"
且 version 为纯点分数字（排除 git commit hash）的第一个条目。
"""

import json
import re
from pathlib import Path

_RUNTIME_ROOT = Path(__file__).resolve().parents[2] / "runtime"
_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")


def affected_linux_version(run_directory: str | Path) -> str:
    """返回指定 run 目录的 cve.json 中被标注为受影响的 Linux 内核版本号。

    Args:
        run_directory: runtime/ 下的目录名，如 "20261127deepseek-flash-1"。

    Returns:
        版本号字符串，如 "6.0"。

    Raises:
        FileNotFoundError: cve.json 不存在。
        ValueError: JSON 不合法，或其中没有受影响的版本号条目。
    """
    path = _RUNTIME_ROOT / run_directory / "cve.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise FileNotFoundError(f"runtime 目录下不存在 cve.json: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"JSON 解析失败: {path}: {error}") from error

    for container in record.get("upstream_kernel") or []:
        for product in container.get("products") or []:
            for entry in product.get("versions") or []:
                if entry.get("status") != "affected":
                    continue
                version = str(entry.get("version") or "")
                if _VERSION_RE.fullmatch(version):
                    return version
    raise ValueError(f"未找到 status=affected 的 Linux 版本号: {path}")
