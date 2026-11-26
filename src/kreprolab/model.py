import json
from collections.abc import Iterator
from contextlib import contextmanager
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

    @classmethod
    def load_name(cls, path: Path) -> str:
        return cls._require_field(path, cls._read_fields(path), "model")

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


@contextmanager
def open_harness(config: ModelConfig) -> Iterator[DeepSeekHarness]:
    provider = "kreprolab-openai"
    key_env = "KREPROLAB_MODEL_API_KEY"
    patch = [
        {"id": "session-log-deepseek", "disabled": True},
        {"id": "plugin-package-inventory-deepseek", "disabled": True},
        {"id": "persistent-bash", "disabled": True},
        {"id": "persistent-pwsh", "disabled": True},
        {"id": "tool-fs", "disabled": True},
        {"id": "tool-working-directory", "disabled": True},
        {
            "insert": [
                {
                    "id": "llm-pi-ai",
                    "name": "@deepseek-ai/dsh-llm-pi-ai",
                    "config": {
                        "providers": {
                            provider: {
                                "api": "openai-completions",
                                "apiKeyEnv": key_env,
                                "baseURL": config.base_url,
                                "models": [{"id": config.model}],
                                "retryPolicy": {"mode": "normal", "maxRetries": 0},
                            },
                        },
                    },
                },
            ],
        },
    ]
    with TemporaryDirectory(prefix="kreprolab-") as directory:
        # JSON is valid YAML, including quoting for model IDs and API URLs.
        patch_path = Path(directory) / "model.patch.yml"
        patch_path.write_text(json.dumps(patch), encoding="utf-8")
        harness = DeepSeekHarness(DeepSeekHarnessConfig(
            provider=provider,
            model=config.model,
            profile="sdk-minimal",
            dsh_home=directory,
            patches=(str(patch_path),),
            env={key_env: config.api_key},
        ))
        try:
            harness.start()
            yield harness
        finally:
            harness.close()
