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

## 采集 CVE、推断触发配置并构建内核

在仓库根目录运行以下命令。此工作流读取 `model.json` 的完整配置：`model` 用于命名，`base_url` 和 `api_key` 用于最后的 DSH 步骤。它联网查询 CVE Program 的公开记录，API 不可用时尝试其官方镜像。

```bash
uv run kreprolab CVE-2024-41000
```

每次运行在当前目录的 `runtime/` 下建立一个子目录，按本地日期、模型名和当日同模型的运行序号命名，例如 `runtime/20261126glm5.2-1/`。序号从 `1` 开始，失败运行也占用序号，模型名中的 `/` 等特殊字符会编码。`runtime/` 已加入 Git 忽略规则。构建相关配置和产物统一放在运行目录的 `build/` 下：

```text
runtime/<run>/
├── run.json
├── cve.json
├── linux-<版本>/
├── .dsh/
└── build/
    ├── trigger.candidate.config
    ├── trigger.config
    ├── resolved.config
    ├── trigger-config.json
    ├── agent-run.json
    ├── cc-wrapper.sh
    ├── bzImage
    ├── build.log
    ├── build.json
    ├── kernel/          # 内核 O= 构建目录
    └── modules/         # gating symbol 为 m 时
```

- `run.json` 记录 CVE、模型、起止时间、运行状态和每个数据源的查询结果。
- `cve.json` 保存已读取的公告元数据，包括标题、描述、发布与更新时间、CWE、CVSS、上游内核适用版本和公告列出的 kernel.org 修复链接。版本规则保留公告中的上下界、比较类型、分支状态与默认状态，并记录提供方。版本上界按原规则解释，发行版的回移修复需要查阅发行版公告。

对于 `vendor: n/a`、`product: kernel` 这类非标准 CNA，若描述或引用能佐证 Linux 内核，会把该 product 以 `scope: description/reference` 记入 `upstream_kernel`。仍无法确认时标记为 `partial`：`run.json`/`cve.json` 的 `coverage` 区分 `kernel_scope_unverified` 与 `affected_versions_unavailable`，`cve.json` 的 `reported_affected` 保留原始产品条目及提供方，仅供审阅，不用于自动选择源码版本。CLI 在 stderr 提示查看报告，并以退出码 1 结束。

收集状态为 `completed` 时，命令继续执行：

1. 读取该次运行的 `cve.json`，输出首个受影响的稳定 Linux 内核版本；若公告只给出 rc，则输出归一化后的 rc 版本（如 `5.17-rc6`）。
2. 获取该版本的源码：stable 版本优先从 kernel.org 下载，不可用时回退 GitHub `gregkh/linux`；rc 版本从 GitHub `torvalds/linux` 对应 tag 下载。下载过程中在 stderr 显示进度条（仅 TTY；归档没有 `Content-Length` 时显示不确定进度），解压到同一运行目录的 `linux-<版本号>/`，压缩包解压后删除。
3. 执行最小触发配置推断：
   - DSH `sdk-minimal` Agent 读取 `cve.json` 和源码，定位受影响代码的 gating symbol，给出候选配置和证据。
   - 确定性 Kconfig 层以 `x86_64_defconfig` 为基线合并候选片段，运行 `make olddefconfig`，校验 gating symbol 仍为 `y`/`m`，再贪心删除不影响 gating 的选项。
   - 若受影响代码无条件编译（核心代码），使用 `gating_kind=unconditional` 且 `gating_symbols=[]`；`trigger.config` 可为空，`resolved.config` 为基线配置。
   - `build/trigger.candidate.config`：Agent 的原始候选片段。
   - `build/trigger.config`：Kconfig 级子集最小触发片段；不包含调试/启动选项。
   - `build/resolved.config`：合并基线并经 olddefconfig 解析后的完整配置，可直接作为后续构建输入。
   - `build/trigger-config.json`：证据、gating/candidate symbols、olddefconfig 校验和最小化记录。
   - `build/agent-run.json`：本轮 Agent 的结果、事件与通知。
   - `.dsh/`：该次运行的 DSH home 和 JSONL 会话记录。

4. 使用 `build/resolved.config` 构建 x86_64 内核镜像：
   - 在 `build/kernel/` 下执行 `make olddefconfig` 和 `make -j bzImage`，不修改源码树。
   - 镜像复制到 `build/bzImage`；构建日志写入 `build/build.log`；构建元数据写入 `build/build.json`。
   - 若 `build/trigger-config.json` 中任一 gating symbol 解析为 `m`，同时构建模块并安装到 `build/modules/`。
   - 测试镜像会禁用 QEMU/BIOS 启动不需要的 `CONFIG_EFI_STUB`；旧内核的 EFI stub 在 GCC C23 默认下会编译失败。该覆盖只作用于 `build/kernel/.config`，记录在 `build/build.json`，不修改 `build/resolved.config`。
   - 构建时生成临时 CC wrapper，把内核顶层 Makefile 的 `-std=gnu89`/`gnu11` 补回给自行重置 flags 的子目录（如 `arch/x86/realmode`、EFI stub），避免新 GCC 的 C23 默认标准破坏旧内核；wrapper 路径和标准写入 `build.json`。

完整内核构建由确定性的构建步骤在 Agent 结束后执行，不由 Agent 发起。Agent 在当前 run 目录内使用 shell 检查源码，允许 Kconfig-only 命令（defconfig、merge_config、olddefconfig），但不得构建完整内核、修改源码或下载其他内容。olddefconfig 校验需要内核 Kconfig 工具链（`make`、`gcc`、`flex`、`bison`、`bc`、`perl` 等）；缺少工具链时该步骤失败并保留 Agent 产物。`bzImage` 构建还需要 libssl、pahole（启用 BTF 时）、kmod（安装模块时）等常见依赖，具体以构建日志为准。依赖解释目前由 Agent 定向检查 Kconfig 完成，olddefconfig 作为硬校验；kconfig-mcp 尚未接入。当前产物是 `bzImage` 和按需模块，尚未生成 initramfs/rootfs 或执行 QEMU 启动。未发现明确的上游受影响版本时标记为 `partial`，并保留能确认的信息。查无公开记录、撤回或查询失败时以对应状态写入 `run.json`。命令只在所有步骤成功时返回退出码 `0`。
