当前项目名称为 KReproLab，是一个面向 Linux 内核缺陷复现任务的自动化 Agent 实验执行框架。

项目使用 Python 开发，使用 uv 管理项目环境及依赖，目前已完成项目初始化，并安装 `deepseek-harness-sdk`。

项目的基本设计原则：

- 使用 DeepSeek Harness（DSH）SDK 作为 Agent 运行时，直接复用其模型调用、Agent Loop、工具调用、Skill 和 Session 等能力。
- 使用 Python 编写确定性的工作流编排逻辑，负责实验任务管理、批量执行、环境隔离、资源控制及实验数据归档。
- 通过 Prompt 和 Skill 定制 Agent 的工作流程。
- 完整保留 Agent 的执行轨迹、工具调用记录、模型输出、运行日志及实验产物，为后续独立评分器提供数据。
- 评分器将作为独立项目开发，KReproLab 需要预留标准化的数据输出及外部接入接口。

KReproLab 的定位是实验基础设施，而非新的 Agent 框架。因此应尽可能复用 DSH SDK 的原生能力，避免重复实现已有功能，现阶段不考虑修改 DSH 核心源码。

开发过程中以简洁、模块化、可扩展为原则，避免过度设计。

DSH 官方资料：

- 源码：https://github.com/deepseek-ai/deepseek-harness
- Python SDK 文档：https://deepseek-harness.github.io/deepseek-harness/guide/python-sdk

涉及 SDK 的具体接口时，请优先查阅官方文档和实际源码，避免凭经验假设接口的存在及调用方式。