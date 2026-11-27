"""下载并解压指定版本的 Linux 内核源码到 CVE 运行目录。

版本号来自 affected_linux_version()，如 "5.10.215"。优先从 kernel.org 下载，
不可用时回退到 GitHub 镜像；解压后位于 <run 目录>/linux-<版本号>/，与 cve.json
同目录，压缩包在解压后删除。
"""

import gzip
import lzma
import re
import tarfile
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import Request, urlopen

KERNEL_CDN = "https://cdn.kernel.org/pub/linux/kernel"
GITHUB_CDN = "https://codeload.github.com"
ARCHIVE_CHUNK_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 1024**3
_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)+")


def _source_candidates(version: str) -> Iterator[tuple[str, str]]:
    major = version.split(".", 1)[0]
    yield f"{KERNEL_CDN}/v{major}.x/linux-{version}.tar.xz", ".tar.xz"
    repo = "gregkh/linux" if version.count(".") >= 2 else "torvalds/linux"
    yield f"{GITHUB_CDN}/{repo}/tar.gz/refs/tags/v{version}", ".tar.gz"


def _download(url: str, destination: Path) -> None:
    request = Request(url, headers={"User-Agent": "KReproLab"})
    with urlopen(request, timeout=60) as response, destination.open("wb") as output:
        total = 0
        while chunk := response.read(ARCHIVE_CHUNK_BYTES):
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError(f"kernel source archive exceeded size limit: {url}")
            output.write(chunk)


def _download_archive(version: str, destination: Path) -> Path:
    failures: list[str] = []
    for url, suffix in _source_candidates(version):
        archive = destination / f"linux-{version}{suffix}"
        try:
            _download(url, archive)
        except HTTPError as error:
            error.close()
            archive.unlink(missing_ok=True)
            failures.append(f"{url} (HTTP {error.code})")
        except OSError as error:
            archive.unlink(missing_ok=True)
            failures.append(f"{url} ({error})")
        else:
            return archive
    raise ValueError("no kernel source archive available: " + "; ".join(failures))


def download_linux_source(version: str, run_directory: str | Path) -> Path:
    """下载并解压指定版本的内核源码，返回源码目录。

    Args:
        version: Linux 内核版本号，如 "5.10.215"。
        run_directory: collect_cve() 返回的 run 目录，即 cve.json 所在目录。

    Returns:
        解压后的源码目录，位于 run_directory 下；已存在时直接复用。

    Raises:
        ValueError: 版本号不合法，所有下载源都失败，或源码归档损坏。
        OSError: 文件操作失败。
    """
    if not _VERSION_RE.fullmatch(version):
        raise ValueError(f"invalid Linux kernel version: {version!r}")
    run_directory = Path(run_directory)
    source = run_directory / f"linux-{version}"
    if source.is_dir():
        return source

    run_directory.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".kernel-source-", dir=run_directory) as temporary:
        temporary_path = Path(temporary)
        archive = _download_archive(version, temporary_path)
        try:
            with tarfile.open(archive, mode="r:*") as tar:
                tar.extractall(temporary_path, filter="data")
        except (tarfile.TarError, EOFError, lzma.LZMAError, gzip.BadGzipFile) as error:
            raise ValueError(f"invalid kernel source archive for {version}: {error}") from error
        extracted = temporary_path / source.name
        if not extracted.is_dir():
            raise ValueError(f"kernel source archive did not contain {source.name}")
        extracted.replace(source)
    return source
