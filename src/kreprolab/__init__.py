from argparse import ArgumentParser
from pathlib import Path

from deepseek_harness.errors import HarnessError

from .affected import affected_linux_version
from .cve import collect_cve, normalize_cve_id
from .model import ModelConfig, open_harness


def main() -> None:
    parser = ArgumentParser(description="Collect Linux kernel CVE metadata or check the model connection.")
    parser.add_argument("cve", nargs="?", help="CVE identifier to collect (omit to check the model connection)")
    parser.add_argument(
        "--config", type=Path, default=Path("model.json"), help="model JSON file (default: model.json)"
    )
    args = parser.parse_args()

    if args.cve is not None:
        try:
            cve_id = normalize_cve_id(args.cve)
            model = ModelConfig.load_name(args.config)
            directory, status = collect_cve(cve_id, model, Path("runtime"))
        except (OSError, ValueError) as error:
            parser.exit(1, f"CVE collection error: {error}\n")
        print(f"{directory} ({status})")
        if status != "completed":
            parser.exit(1)
        try:
            version = affected_linux_version(directory)
        except (OSError, ValueError) as error:
            parser.exit(1, f"CVE version extraction error: {error}\n")
        print(version)
        return

    try:
        config = ModelConfig.load(args.config)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Model configuration error: {error}\n")

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
