# KReproLab

## 模型接入

在仓库根目录编辑 `model.json`。首次检出仓库时，从 `model.example.json` 复制一份，再填写这三个字段。

| 字段 | 填写内容 |
| --- | --- |
| `base_url` | OpenAI Chat Completions 兼容接口的基础地址，例如 `https://gateway.example/v1`。也可以填写完整的 `/chat/completions` 地址。 |
| `api_key` | 该服务的 API Key。 |
| `model` | 服务端接受的模型 ID。 |

`model.json` 已加入 Git 忽略规则。切换模型时修改这份文件即可。运行以下命令会通过 DeepSeek Harness 发送一条简短测试消息并打印模型回复。

```bash
uv run kreprolab
```

可用 `uv run kreprolab --config /path/to/model.json` 指定另一份配置。CVE 工作流也会使用这份配置启动 DSH Agent，因此 `model.json` 必须是完整可用的配置。

## 采集 CVE 并推断最小触发配置

在仓库根目录运行以下命令。此工作流读取 `model.json` 的完整配置：`model` 用于命名，`base_url` 和 `api_key` 用于最后的 DSH 步骤。它联网查询 CVE Program 的公开记录，API 不可用时尝试其官方镜像。

```bash
uv run kreprolab CVE-2024-41000
```

每次运行在当前目录的 `runtime/` 下建立一个子目录，按本地日期、模型名和当日同模型的运行序号命名，例如 `runtime/20261126glm5.2-1/`。序号从 `1` 开始，失败运行也占用序号，模型名中的 `/` 等特殊字符会编码。`runtime/` 已加入 Git 忽略规则。

- `run.json` 记录 CVE、模型、起止时间、运行状态和每个数据源的查询结果。
- `cve.json` 保存已读取的公告元数据，包括标题、描述、发布与更新时间、CWE、CVSS、上游内核适用版本和公告列出的 kernel.org 修复链接。版本规则保留公告中的上下界、比较类型、分支状态与默认状态，并记录提供方。版本上界按原规则解释，发行版的回移修复需要查阅发行版公告。

收集状态为 `completed` 时，命令继续执行：

1. 读取该次运行的 `cve.json`，输出首个受影响的 Linux 内核版本号。
2. 从 kernel.org 下载该版本源码（不可用时回退到 GitHub 镜像），解压到同一运行目录的 `linux-<版本号>/`，压缩包解压后删除。
3. 执行最小触发配置推断：
   - DSH `sdk-minimal` Agent 读取 `cve.json` 和源码，定位受影响代码的 gating symbol，给出候选配置和证据。
   - 确定性 Kconfig 层以 `x86_64_defconfig` 为基线合并候选片段，运行 `make olddefconfig`，校验 gating symbol 仍为 `y`/`m`，再贪心删除不影响 gating 的选项。
   - `trigger.candidate.config`：Agent 的原始候选片段。
   - `trigger.config`：Kconfig 级子集最小触发片段；不包含调试/启动选项。
   - `resolved.config`：合并基线并经 olddefconfig 解析后的完整配置，可直接作为后续构建输入。
   - `trigger-config.json`：证据、gating/candidate symbols、olddefconfig 校验和最小化记录。
   - `agent-run.json`：本轮 Agent 的结果、事件与通知。
   - `.dsh/`：该次运行的 DSH home 和 JSONL 会话记录。

Agent 在当前 run 目录内使用 shell 检查源码，允许 Kconfig-only 命令（defconfig、merge_config、olddefconfig），但不得构建完整内核、修改源码或下载其他内容。olddefconfig 校验需要内核 Kconfig 工具链（`make`、`gcc`、`flex`、`bison`、`bc`、`perl` 等）；缺少工具链时该步骤失败并保留 Agent 产物。依赖解释目前由 Agent 定向检查 Kconfig 完成，olddefconfig 作为硬校验；kconfig-mcp 尚未接入。未发现明确的上游受影响版本时标记为 `partial`，并保留能确认的信息。查无公开记录、撤回或查询失败时以对应状态写入 `run.json`。命令只在所有步骤成功时返回退出码 `0`。
