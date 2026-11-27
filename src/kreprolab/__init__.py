from argparse import ArgumentParser
from pathlib import Path

from deepseek_harness.errors import HarnessError

from .affected import affected_linux_version
from .cve import collect_cve, normalize_cve_id
from .kernel_build import build_kernel_image
from .model import ModelConfig, open_harness
from .source import download_linux_source
from .trigger_config import prepare_trigger_config


def main() -> None:
    parser = ArgumentParser(description="Collect Linux kernel CVE metadata or check the model connection.")
    parser.add_argument("cve", nargs="?", help="CVE identifier to collect (omit to check the model connection)")
    parser.add_argument(
        "--config", type=Path, default=Path("model.json"), help="model JSON file (default: model.json)"
    )
    args = parser.parse_args()

    try:
        config = ModelConfig.load(args.config)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Model configuration error: {error}\n")

    if args.cve is not None:
        try:
            cve_id = normalize_cve_id(args.cve)
            directory, status = collect_cve(cve_id, config.model, Path("runtime"))
        except (OSError, ValueError) as error:
            parser.exit(1, f"CVE collection error: {error}\n")
        print(f"{directory} ({status})")
        if status == "partial":
            parser.exit(
                1,
                "CVE collection incomplete: insufficient upstream Linux scope or version evidence. "
                f"See {directory / 'cve.json'} (coverage, reported_affected).\n",
            )
        if status != "completed":
            parser.exit(1)
        try:
            version = affected_linux_version(directory)
        except (OSError, ValueError) as error:
            parser.exit(1, f"CVE version extraction error: {error}\n")
        print(version)
        try:
            source = download_linux_source(version, directory)
        except (OSError, ValueError) as error:
            parser.exit(1, f"Kernel source download error: {error}\n")
        print(source)
        try:
            artifacts = prepare_trigger_config(directory, version, config)
        except (HarnessError, OSError, TimeoutError, ValueError) as error:
            message = str(error).replace(config.api_key, "[redacted]")
            parser.exit(1, f"Trigger config inference error: {message}\n")
        print(artifacts.trigger_config)
        print(artifacts.resolved_config)
        print(artifacts.report)
        try:
            build = build_kernel_image(directory, version)
        except (OSError, ValueError) as error:
            parser.exit(1, f"Kernel build error: {error}\n")
        print(build.image)
        print(build.report)
        if build.modules is not None:
            print(build.modules)
        return

    try:
        with open_harness(config) as harness:
            result = harness.run("Reply with the single word OK.")
    except (HarnessError, OSError, TimeoutError) as error:
        message = str(error).replace(config.api_key, "[redacted]")
        parser.exit(1, f"Model request failed: {message}\n")

    if result.finish_reason != "completed" or not result.final_response.strip():
        reason = result.finish_reason or "no finish reason"
        parser.exit(1, f"Model did not return a complete text reply ({reason}).\n")
    print(result.final_response)
