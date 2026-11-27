import hashlib
import json
import re
from datetime import datetime
from http.client import HTTPException
from itertools import count
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen


CVE_API = "https://cveawg.mitre.org/api/cve"
CVE_MIRROR = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
MAX_RECORD_BYTES = 4 * 1024 * 1024


def normalize_cve_id(value: str) -> str:
    cve_id = value.strip().upper()
    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cve_id):
        raise ValueError("expected a CVE ID such as CVE-2024-41000")
    return cve_id


def _reserve_directory(root: Path, model: str, started: datetime) -> Path:
    slug = quote(model, safe="")
    if len(slug) > 150:
        digest = hashlib.sha256(model.encode()).hexdigest()[:16]
        slug = f"{slug[:130]}-{digest}"
    root.mkdir(parents=True, exist_ok=True)
    prefix = f"{started:%Y%m%d}{slug}-"
    existing = (
        entry.name[len(prefix):]
        for entry in root.iterdir()
        if entry.name.startswith(prefix)
    )
    last_attempt = max((int(number) for number in existing if re.fullmatch(r"[0-9]+", number)), default=0)
    for attempt in count(last_attempt + 1):
        directory = root / f"{prefix}{attempt}"
        try:
            directory.mkdir()
        except FileExistsError:
            continue
        return directory


def _write_json(path: Path, data: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _fetch_record(cve_id: str, attempts: list[dict]) -> dict | None:
    _, year, number = cve_id.split("-")
    bucket = f"{number[:-3]}xxx"
    sources = (
        f"{CVE_API}/{cve_id}",
        f"{CVE_MIRROR}/{year}/{bucket}/{cve_id}.json",
    )
    for url in sources:
        attempt = {"url": url}
        attempts.append(attempt)
        try:
            request = Request(url, headers={"Accept": "application/json", "User-Agent": "KReproLab"})
            with urlopen(request, timeout=15) as response:
                body = response.read(MAX_RECORD_BYTES + 1)
            if len(body) > MAX_RECORD_BYTES:
                raise ValueError("CVE record exceeded size limit")
            record = json.loads(body)
            if (
                not isinstance(record, dict)
                or record.get("dataType") != "CVE_RECORD"
                or not isinstance(record.get("cveMetadata"), dict)
                or record["cveMetadata"].get("cveId") != cve_id
                or not isinstance(record.get("containers"), dict)
            ):
                raise ValueError("response does not contain the requested CVE Record")
            if record["cveMetadata"].get("state") == "PUBLISHED" and not isinstance(
                record["containers"].get("cna"), dict
            ):
                raise ValueError("published record is missing its CNA container")
        except HTTPError as error:
            attempt.update(status="http_error", http_status=error.code)
            error.close()
        except (OSError, HTTPException, ValueError) as error:
            attempt.update(status="error", error=str(error))
        else:
            attempt["status"] = "ok"
            return record
    return None


def _kernel_reference(reference: dict) -> bool:
    url = reference.get("url")
    if not isinstance(url, str):
        return False
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return parsed.netloc == "kernel.org" or parsed.netloc.endswith(".kernel.org")


def _container_corroboration(container: dict) -> str | None:
    descriptions = " ".join(
        item["value"]
        for item in container.get("descriptions", [])
        if isinstance(item, dict) and isinstance(item.get("value"), str)
    )
    if "linux kernel" in descriptions.casefold():
        return "description"
    if any(
        _kernel_reference(reference)
        for reference in container.get("references", [])
        if isinstance(reference, dict)
    ):
        return "reference"
    return None


def _kernel_scope(product: dict, corroboration: str | None) -> str | None:
    vendor = str(product.get("vendor", "")).strip().casefold()
    name = str(product.get("product", "")).casefold().replace("_", " ").replace("-", " ")
    if vendor in {"linux", "kernel.org"} and name in {"linux", "linux kernel", "kernel"}:
        return "vendor"
    if any(
        cpe.startswith("cpe:2.3:o:linux:linux_kernel:")
        for cpe in product.get("cpes", [])
        if isinstance(cpe, str)
    ):
        return "cpe"
    if corroboration and vendor in {"", "n/a", "na", "unknown"} and name in {"linux", "linux kernel", "kernel"}:
        return corroboration
    return None


def _kernel_fix_links(references: list[dict]) -> list[str]:
    links = []
    for reference in references:
        url = reference["url"]
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        if parsed.scheme == "https" and parsed.netloc == "git.kernel.org" and (
            re.fullmatch(r"/stable/c/[a-f0-9]{7,64}/?", parsed.path)
            or (
                re.fullmatch(r"/pub/scm/linux/kernel/git/[\w.-]+/[\w.-]+\.git/commit/?", parsed.path)
                and re.fullmatch(r"id=[a-f0-9]{7,64}", parsed.query)
            )
        ):
            links.append(url)
    return list(dict.fromkeys(links))


def _summarize(record: dict, source_url: str) -> tuple[dict, str]:
    metadata = record["cveMetadata"]
    cve_id = metadata["cveId"]
    state = metadata.get("state")
    report = {
        "schema_version": 1,
        "cve_id": cve_id,
        "record_state": state,
        "assigner": metadata.get("assignerShortName"),
        "published_at": metadata.get("datePublished"),
        "updated_at": metadata.get("dateUpdated"),
        "source": {"url": source_url, "record_url": f"https://www.cve.org/CVERecord?id={cve_id}"},
    }
    if state != "PUBLISHED":
        return report, "rejected" if state == "REJECTED" else "unpublished"

    containers = record["containers"]
    cna = containers["cna"]
    evidence = []
    sources = [("cna", cna)]
    sources.extend(("adp", adp) for adp in containers.get("adp", []))
    product_fields = ("vendor", "product", "packageName", "defaultStatus", "versions")
    for kind, container in sources:
        corroboration = _container_corroboration(container)
        kernel_products = []
        for product in container.get("affected", []):
            scope = _kernel_scope(product, corroboration)
            if scope:
                entry = {field: product[field] for field in product_fields if field in product}
                entry["scope"] = scope
                kernel_products.append(entry)
        if kernel_products:
            evidence.append({
                "container": kind,
                "provider": container.get("providerMetadata", {}).get("shortName"),
                "products": kernel_products,
                "fix_references": _kernel_fix_links(container.get("references", [])),
            })
    report.update(
        title=cna.get("title"),
        descriptions=[
            {"container": kind, "lang": item.get("lang"), "value": item["value"]}
            for kind, container in sources
            for item in container.get("descriptions", [])
            if isinstance(item, dict)
            and isinstance(item.get("value"), str)
            and item["value"].strip()
        ],
        cwe_ids=sorted({
            item["cweId"]
            for _, container in sources
            for problem in container.get("problemTypes", [])
            for item in problem.get("descriptions", [])
            if item.get("cweId")
        }),
        cvss=[
            {
                "container": kind,
                "provider": container.get("providerMetadata", {}).get("shortName"),
                "score": value,
            }
            for kind, container in sources
            for metric in container.get("metrics", [])
            for name, value in metric.items() if name.startswith("cvssV")
        ],
        upstream_kernel=evidence,
    )
    if not evidence:
        report["coverage"] = "kernel_scope_unverified"
    elif not any(
        version.get("status") == "affected"
        and any(
            version.get(key, "").strip().casefold() not in {"", "*", "n/a", "na", "unknown", "unspecified"}
            for key in ("version", "lessThan", "lessThanOrEqual")
        )
        for container in evidence
        for product in container["products"]
        for version in product.get("versions", [])
    ):
        report["coverage"] = "affected_versions_unavailable"
    else:
        report["coverage"] = "reported_upstream_versions"
        return report, "completed"
    report["reported_affected"] = [
        {
            "container": kind,
            "provider": container.get("providerMetadata", {}).get("shortName"),
            "products": products,
        }
        for kind, container in sources
        if (products := container.get("affected"))
    ]
    return report, "partial"


def collect_cve(cve_id: str, model: str, runtime_root: Path) -> tuple[Path, str]:
    started = datetime.now().astimezone()
    directory = _reserve_directory(runtime_root, model, started)
    manifest = {
        "schema_version": 1,
        "stage": "collect_cve",
        "cve_id": cve_id,
        "model": model,
        "attempt": int(directory.name.rsplit("-", 1)[1]),
        "started_at": started.isoformat(),
        "status": "running",
        "sources": [],
    }
    manifest_path = directory / "run.json"
    _write_json(manifest_path, manifest)
    attempts = manifest["sources"]
    status = "failed"
    try:
        record = _fetch_record(cve_id, attempts)
        if record is None:
            status = "not_found" if all(attempt.get("http_status") == 404 for attempt in attempts) else "failed"
        else:
            report, report_status = _summarize(record, attempts[-1]["url"])
            _write_json(directory / "cve.json", report)
            status = report_status
            if "coverage" in report:
                manifest["coverage"] = report["coverage"]
    except (AttributeError, KeyError, TypeError, ValueError):
        status = "failed"
        manifest["error"] = "CVE record contains unsupported or malformed fields"
    except KeyboardInterrupt:
        status = "cancelled"
    finally:
        manifest["status"] = status
        manifest["finished_at"] = datetime.now().astimezone().isoformat()
        _write_json(manifest_path, manifest)
    return directory, status
