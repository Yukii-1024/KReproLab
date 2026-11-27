import json
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from deepseek_harness import DeepSeekHarness, DeepSeekHarnessConfig


@dataclass(frozen=True)
class ModelConfig:
    base_url: str
    api_key: str = field(repr=False)
    model: str

    @staticmethod
    def _read_fields(path: Path) -> dict:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ValueError(f"{path} is missing. Copy model.example.json and fill in the model settings.") from None
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError(f"{path} must contain valid UTF-8 JSON.") from None

        if not isinstance(data, dict) or data.keys() != {"base_url", "api_key", "model"}:
            raise ValueError(f"{path} must contain exactly base_url, api_key and model.")
        return data

    @staticmethod
    def _require_field(path: Path, data: dict, name: str) -> str:
        value = data[name]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{path}: {name} must be a non-empty string.")
        return value.strip()

    @classmethod
    def load(cls, path: Path) -> "ModelConfig":
        data = cls._read_fields(path)
        base_url, api_key, model = (
            cls._require_field(path, data, name) for name in ("base_url", "api_key", "model")
        )

        base_url = base_url.rstrip("/").removesuffix("/chat/completions").rstrip("/")
        try:
            url = urlsplit(base_url)
            valid_url = url.scheme in {"http", "https"} and bool(url.hostname) and not (
                url.username or url.password or url.query or url.fragment
            )
        except ValueError:
            valid_url = False
        if not valid_url:
            raise ValueError(f"{path}: base_url must be an HTTP or HTTPS API URL.")
        return cls(base_url=base_url, api_key=api_key, model=model)


def _harness_patch(config: ModelConfig, tools: bool) -> list[dict]:
    patch = [
        {"id": "session-log-deepseek", "disabled": True},
        {"id": "plugin-package-inventory-deepseek", "disabled": True},
    ]
    if not tools:
        patch.extend([
            {"id": "persistent-bash", "disabled": True},
            {"id": "persistent-pwsh", "disabled": True},
            {"id": "tool-fs", "disabled": True},
            {"id": "tool-working-directory", "disabled": True},
        ])
    patch.append({
        "insert": [
            {
                "id": "llm-pi-ai",
                "name": "@deepseek-ai/dsh-llm-pi-ai",
                "config": {
                    "providers": {
                        "kreprolab-openai": {
                            "api": "openai-completions",
                            "apiKeyEnv": "KREPROLAB_MODEL_API_KEY",
                            "baseURL": config.base_url,
                            "models": [{"id": config.model}],
                            "retryPolicy": {"mode": "normal", "maxRetries": 0},
                        },
                    },
                },
            },
        ],
    })
    return patch


@contextmanager
def open_harness(
    config: ModelConfig,
    *,
    dsh_home: Path | None = None,
    cwd: Path | None = None,
    tools: bool = False,
    system_prompt: str | None = None,
) -> Iterator[DeepSeekHarness]:
    env = {"KREPROLAB_MODEL_API_KEY": config.api_key}
    if system_prompt is not None:
        env["DSH_SYSTEM_PROMPT"] = system_prompt
    with ExitStack() as stack:
        if dsh_home is None:
            home = Path(stack.enter_context(TemporaryDirectory(prefix="kreprolab-")))
        else:
            home = Path(dsh_home).resolve()
            home.mkdir(parents=True, exist_ok=True)
        # JSON is valid YAML, including quoting for model IDs and API URLs.
        patch_path = home / "model.patch.yml"
        patch_path.write_text(json.dumps(_harness_patch(config, tools)), encoding="utf-8")
        workspace = str(Path(cwd).resolve()) if cwd is not None else None
        harness = DeepSeekHarness(DeepSeekHarnessConfig(
            provider="kreprolab-openai",
            model=config.model,
            profile="sdk-minimal",
            dsh_home=str(home),
            patches=(str(patch_path),),
            env=env,
            cwd=workspace,
            runtime_cwd=workspace,
        ))
        try:
            harness.start()
            yield harness
        finally:
            harness.close()
