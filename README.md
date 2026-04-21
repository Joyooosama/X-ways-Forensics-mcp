# XWF-MCP

面向 **X-Ways Forensics 20.0** 的 MCP Server，用于把 X-Ways 的命令行能力、案件状态、日志、导出结果和离线分析流程统一暴露给支持 MCP 的客户端。

本文档只保留当前项目的可用能力、目录约定、配置方法和使用建议。

## 项目定位

XWF-MCP 主要解决三个问题：

- 把 X-Ways 的命令行操作封装成稳定的 MCP 工具，便于建案、加检材、跑 RVS、执行 `.whs` 脚本。
- 把案件日志、导出目录、关键词列表、桥接结果统一整理成可查询的资源面。
- 把长任务、离线导出、问答分析这几类高频流程做成可重复执行的标准工作流。

项目默认采用“控制面 + 结果面”的设计：

- 控制面：创建案件、挂载检材、运行 RVS、执行脚本、准备桥接目录。
- 结果面：读取消息日志、快照摘要、搜索命中、加密候选、离线 artifact、标准化导出。

## 当前能力概览

- `32` 个 MCP Tools
- `10` 个 MCP Resources
- `5` 个 MCP Prompts
- 支持异步 Job、日志轮询、案件级串行写入
- 支持离线导出桥接与问答规划
- 支持为聊天类客户端提供 `*_and_wait` 工具，减少长任务轮询噪声

## 运行要求

- Windows
- Python `>= 3.10`
- X-Ways Forensics 20.0
- Python 依赖：
  - `mcp >= 1.0.0`
  - `pydantic >= 2.0.0`

## 权限要求

只读能力通常不要求管理员权限，但以下这类修改型动作通常需要以管理员权限启动 MCP 客户端或 MCP 服务进程：

- `create_case`
- `add_image`
- `add_dir`
- `run_rvs`
- `run_whs_script`
- 对应的 `*_and_wait` 版本

如果出现 `WinError 740`，说明当前客户端进程没有以管理员权限启动，X-Ways 命令行子进程无法被正常拉起。

## 安装

在项目根目录执行：

```powershell
python -m pip install -e .
```

可执行入口有两种：

```powershell
python run_xwf_mcp.py
```

或者：

```powershell
python -m xwf_mcp.server
```

安装脚本入口后，也可以直接执行：

```powershell
xwf-mcp
```

## MCP 客户端配置

通用配置格式如下：

```json
{
  "mcpServers": {
    "xwf-mcp": {
      "command": "python",
      "args": ["run_xwf_mcp.py"],
      "cwd": "D:\\Programs\\XWF-mcp",
      "env": {
        "XWF_PROJECT_ROOT": "D:\\Programs\\XWF-mcp",
        "XWF_XWAYS_EXE": "D:\\Programs\\X-Ways Forensics 20.0 Portable\\X-Ways Forensics_20.0\\xwforensics64.exe",
        "XWF_CASES_ROOT": "D:\\Programs\\X-Ways Forensics 20.0 Portable\\X-Ways_Forensics_Case_Files\\Cases"
      }
    }
  }
}
```

如果不显式设置 `XWF_XWAYS_EXE` 和 `XWF_CASES_ROOT`，项目会尝试按以下相对关系自动发现：

- `..\X-Ways Forensics_20.0\xwforensics64.exe`
- `..\X-Ways_Forensics_Case_Files\Cases`

## 环境变量

| 变量名 | 默认值 | 说明 |
|------|------|------|
| `XWF_PROJECT_ROOT` | 当前项目根目录 | 项目根目录，影响相对路径解析 |
| `XWF_XWAYS_EXE` | 自动发现 | `xwforensics64.exe` 的绝对路径 |
| `XWF_CASES_ROOT` | 自动发现 | 案件根目录，通常指向 `Cases` |
| `XWF_RUNTIME_DIR` | `<project>/runtime` | 运行时目录 |
| `XWF_EXPORTS_DIR` | `<project>/exports` | 标准导出目录 |
| `XWF_LISTS_DIR` | `<project>/lists` | 搜索词列表目录 |
| `XWF_SCRIPTS_DIR` | `<project>/scripts` | `.whs` 脚本目录 |
| `XWF_GLOBAL_MSGLOG` | `<xways_dir>/msglog.txt` | 全局消息日志路径 |
| `XWF_DEFAULT_OVERRIDE` | `1` | 默认 `Override:` 参数 |
| `XWF_DEFAULT_TIMEOUT_SECONDS` | `3600` | 默认超时秒数 |
| `XWF_POLL_INTERVAL_SECONDS` | `2.0` | Job 进度轮询间隔 |

## 目录结构

```text
XWF-mcp/
├── xwf_mcp/
│   ├── server.py
│   ├── service.py
│   ├── addon_tools.py
│   ├── config.py
│   ├── models.py
│   ├── parsers.py
│   ├── offline_qa_plan.py
│   ├── offline_qa_answers.py
│   ├── legacy_qa_bank.py
│   └── __init__.py
├── templates/
├── exports/
├── lists/
├── runtime/
│   ├── jobs/
│   ├── plans/
│   ├── sessions/
│   └── audit.jsonl
├── scripts/
├── run_xwf_mcp.py
├── pyproject.toml
└── README.md
```

目录用途如下：

- `xwf_mcp/`：核心代码
- `templates/`：桥接模板和 schema
- `exports/`：标准导出目录
- `lists/`：关键词列表目录
- `scripts/`：自定义 `.whs` 脚本目录
- `runtime/jobs/`：异步 Job 状态文件、stdout、stderr
- `runtime/plans/`：检材计划
- `runtime/sessions/`：可视化分析会话状态
- `runtime/audit.jsonl`：审计日志

首次运行时，`runtime/`、`exports/`、`lists/`、`scripts/` 会自动创建。

## Tools

### 1. 案件与会话管理

| 工具 | 说明 |
|------|------|
| `list_cases` | 枚举案件目录、案件文件和服务当前路径配置 |
| `create_case` | 提交异步建案任务，自动避免重名 |
| `create_case_and_wait` | 建案并等待任务完成，适合聊天客户端直接调用 |
| `open_case` | 读取案件元数据、消息、快照、导出、离线 artifact 和搜索词 |
| `launch_xways_gui` | 可视化启动 X-Ways，可选直接打开某个案件 |
| `prepare_visual_analysis_session` | 根据自然语言请求推导案件名、定位检材、准备或复用分析会话 |

### 2. 检材与证据管理

| 工具 | 说明 |
|------|------|
| `stage_evidence_plan` | 记录一份“准备挂哪些检材”的计划，不修改案件 |
| `get_evidence_plan` | 读取案件对应的检材计划 |
| `get_case_evidence_sources` | 解析案件中已有的证据来源 |
| `add_image` | 向案件添加镜像文件 |
| `add_image_and_wait` | 添加镜像并等待完成 |
| `add_dir` | 向案件添加目录、文件或通配符路径 |
| `add_dir_and_wait` | 添加目录并等待完成 |

### 3. 搜索、快照与脚本执行

| 工具 | 说明 |
|------|------|
| `load_search_terms` | 生成或覆盖案件级 `.lst` 搜索词文件 |
| `run_rvs` | 提交 RVS 任务，支持 `new` 和 `all` 两种范围 |
| `run_rvs_and_wait` | 提交 RVS 并等待完成 |
| `ensure_snapshot` | 如果快照还没有准备好，则触发一次 RVS |
| `get_volume_snapshot_summary` | 汇总快照日志和已导出快照记录 |
| `get_string_search_matches` | 返回搜索词命中结果，优先使用导出文件，缺失时退回日志 |
| `find_encrypted_files` | 返回加密候选文件，优先使用导出结果，缺失时退回日志/名称扫描 |
| `run_whs_script` | 提交 `.whs` 脚本执行任务 |
| `run_whs_script_and_wait` | 执行 `.whs` 并等待完成 |

### 4. 异步任务与日志读取

| 工具 | 说明 |
|------|------|
| `get_job_status` | 读取异步 Job 当前状态 |
| `wait_for_job` | 在服务端等待 Job 进入终态，减少客户端高频轮询 |
| `read_case_messages` | 读取案件 `msglog.txt`，支持数量限制和关键字过滤 |
| `read_password_dictionary` | 读取案件 `Passwords.txt` |

### 5. 导出桥接与离线分析

| 工具 | 说明 |
|------|------|
| `prepare_case_bridge` | 为案件准备标准导出目录、桥接清单和 schema |
| `ingest_export_file` | 将外部导出文件规整到统一格式 |
| `get_offline_artifact_inventory` | 查看当前案件已准备的离线 artifact 类型 |
| `plan_offline_qa` | 根据问题规划需要哪些 artifact |
| `answer_offline_qa` | 基于离线 artifact 自动回答问题 |
| `answer_legacy_qa` | 为历史兼容场景保留的问答入口 |

## Resources

| 资源 URI | 说明 |
|------|------|
| `xways://cases` | 全部案件清单 |
| `xways://case/{case_name}/activity-log` | 案件活动日志原文 |
| `xways://case/{case_name}/messages` | 结构化消息列表 |
| `xways://case/{case_name}/exports` | 标准导出目录概览 |
| `xways://case/{case_name}/offline-artifacts` | 离线 artifact 清单 |
| `xways://case/{case_name}/evidence-plan` | 检材计划 |
| `xways://case/{case_name}/search-lists` | 搜索词列表清单 |
| `xways://case/{case_name}/passwords` | 密码词典 |
| `xways://case/{case_name}/snapshot-summary` | 最新快照摘要 |
| `xways://job/{job_id}` | 单个异步 Job 的持久化状态 |

## Prompts

| Prompt | 说明 |
|------|------|
| `new-case-from-image` | 从镜像建案、挂载、跑 RVS 的标准流程 |
| `triage-live-system` | 活体系统快速取证流程 |
| `keyword-search-workflow` | 搜索词加载、RVS、结果读取流程 |
| `evidence-selection-workflow` | 先在 GUI 中判断，再通过 MCP 记录检材计划 |
| `export-bridge-workflow` | 手工导出后接入桥接目录并规整结果 |

## 异步 Job 机制

修改型工具大多采用异步 Job 设计。调用后通常先返回：

- `job_id`
- `status`
- `action`
- `case_name`
- `command_line`

随后可以通过以下方式获取结果：

- `get_job_status(job_id)`
- `wait_for_job(job_id, timeout_seconds, poll_interval_seconds)`
- 直接改用 `*_and_wait` 系列工具

Job 的状态通常为：

- `queued`
- `running`
- `succeeded`
- `failed`
- `orphaned`

Job 文件保存在 `runtime/jobs/`，同名的 `.stdout.log` 和 `.stderr.log` 会保留原始子进程输出。

## 推荐调用方式

如果客户端会频繁重复调用 `get_job_status`，建议优先使用以下工具：

- `create_case_and_wait`
- `add_image_and_wait`
- `add_dir_and_wait`
- `run_rvs_and_wait`
- `run_whs_script_and_wait`
- `wait_for_job`

这样可以把“提交任务”和“等待完成”合并为一次工具调用，减少长任务时的前端反复刷新和轮询噪声。

## 案件安全策略

项目默认带有以下保护：

- 同一案件的修改型操作会按案件串行化，避免并发写入。
- 如果同一案件已经存在 `queued` 或 `running` 的写操作，新的修改型任务会被拒绝。
- 如果案件已经在可见的 X-Ways 进程中打开，修改型任务会被拒绝，避免窗口冲突或案件锁冲突。
- `create_case` 默认使用不冲突的案件名，不直接覆盖已有案件。
- 默认使用 `Override:1`，不使用仅高版本兼容的组合参数。

## 离线桥接工作流

当需要基于 X-Ways 导出结果做进一步结构化分析时，推荐使用以下流程：

1. `prepare_case_bridge(case_ref)`
2. 将 X-Ways 导出文件放入 `exports/<案件名>/inbox/`
3. `ingest_export_file(case_ref, kind, source_path)`
4. `get_offline_artifact_inventory(case_ref)`
5. `plan_offline_qa(case_ref, questions)`
6. `answer_offline_qa(case_ref, questions)`

支持接入的常见输入格式包括：

- `.json`
- `.jsonl`
- `.csv`
- `.tsv`
- `.html`
- `.txt`

## 标准导出类型

当前桥接层面向多种常见导出类型，适合把 X-Ways 手工导出的清单规整为统一结果。典型类别如下：

- 注册表类：系统配置、账户、设备相关导出
- 事件日志类：系统、安全、应用、终端服务、PnP、WLAN、Defender、打印日志
- 程序执行类：Prefetch、Amcache、Shimcache、SRUM、执行记录
- 浏览器与用户活动类：浏览历史、最近项目、快捷方式、Jump Lists、时间线、便签、文档
- 文件系统类：文件列表、哈希清单、回收站、MFT、USN
- 磁盘与存储类：分区、卷信息、证据源元数据
- 安全与脚本类：加密候选、计划任务、命令历史、PowerShell 历史
- 多媒体与数据库类：音频、转写、SQLite WAL
- 设备与远程连接类：SetupAPI、应用日志、远程控制相关日志

如果某些结构化导出尚未提供，服务会按工具类型尽量退回到以下来源：

- 案件 `msglog.txt`
- 全局 `msglog.txt`
- 目录/文件名候选扫描

## 离线问答能力

离线问答层目前覆盖 `68` 个知识域，适合围绕标准化导出结果做结构化提问。能力范围包括：

- 基础系统信息
- 程序执行与安装痕迹
- 用户行为与文档访问
- 登录、远程访问与网络连接
- 磁盘、分区、卷与文件系统
- USB 与外接存储历史
- 加密、恢复密钥与安全痕迹
- 系统事件、计划任务、日志与防护记录
- 数据库、WAL 与恢复场景
- 网络与无线连接
- 多媒体与移动端相关线索

`plan_offline_qa` 用于先做题目到 artifact 的映射，`answer_offline_qa` 用于基于当前已有数据直接作答。

## 常见使用场景

### 新建案件并挂载镜像

推荐顺序：

1. `create_case_and_wait`
2. `add_image_and_wait`
3. `run_rvs_and_wait`
4. `open_case`
5. `get_volume_snapshot_summary`

### 只想查看案件当前状态

推荐顺序：

1. `list_cases`
2. `open_case`
3. `read_case_messages`
4. `get_volume_snapshot_summary`

### 已经在 GUI 里操作，只想读取结果

推荐顺序：

1. `prepare_case_bridge`
2. 手工导出文件到 `exports/<案件名>/inbox/`
3. `ingest_export_file`
4. `get_offline_artifact_inventory`
5. `answer_offline_qa`

### 关键词搜索工作流

推荐顺序：

1. `load_search_terms`
2. `run_rvs_and_wait`
3. `get_string_search_matches`

## 故障排查

### 1. `WinError 740`

原因：

- 当前客户端或 MCP 服务没有管理员权限。

处理方式：

- 以管理员身份启动 MCP 客户端。
- 确认 `xwforensics64.exe` 所在路径可执行。

### 2. 长任务期间界面持续刷新

原因：

- 客户端不断调用 `get_job_status`。

处理方式：

- 优先改用 `*_and_wait` 工具。
- 或使用 `wait_for_job` 代替高频轮询。

### 3. 案件被占用或提示不能并发写入

原因：

- 同一案件已有修改型 Job 在运行。
- 同一案件已在可见 X-Ways 窗口中打开。

处理方式：

- 等当前 Job 结束。
- 或关闭正在占用该案件的 GUI 窗口。

### 4. 找不到案件或导出结果

优先检查：

- `XWF_CASES_ROOT`
- `XWF_EXPORTS_DIR`
- `XWF_XWAYS_EXE`
- 客户端 `cwd`

## 文档说明

本文档以当前代码行为为准，描述的是：

- 已注册的 MCP Tool
- 已注册的 MCP Resource
- 已注册的 MCP Prompt
- 当前目录约定与环境变量行为

如果你扩展了新的导出类型、桥接 parser、等待工具或工作流，建议同步更新本文件对应章节，避免“功能已上线但文档仍停留旧状态”。

## 欢迎交流与改进

如果你在实际使用里遇到不顺手的地方，或者希望补充新的导出类型、桥接解析器、问答能力、等待策略、错误提示和工作流封装，欢迎直接交流。
作者博客：https://www.cnblogs.com/Joyooo

项目会持续朝着“更稳定、更清晰、更适合实战落地”的方向改进~
