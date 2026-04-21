# XWF-MCP 首次联调清单

本清单用于验证 XWF-MCP 是否已正确连接到你的 X-Ways Forensics 20.0。

---

## 0. 前置确认

1. 确认 X-Ways Forensics 可以手工正常启动，无弹窗/许可证问题
2. 确认案件根目录存在（默认为 `X-Ways_Forensics_Case_Files\Cases`）
3. 关闭 X-Ways GUI
4. 安装依赖：`python -m pip install -e .`

---

## 1. 配置 MCP 客户端

在你的 MCP 客户端配置文件中添加：

```json
{
  "mcpServers": {
    "xwf-mcp": {
      "command": "python",
      "args": ["run_xwf_mcp.py"],
      "cwd": "<XWF-mcp 目录的绝对路径>",
      "env": {
        "XWF_XWAYS_EXE": "<X-Ways 安装目录>\\xwforensics64.exe",
        "XWF_CASES_ROOT": "<案件根目录>\\Cases"
      }
    }
  }
}
```

> **VS Code 用户**：配置写入 `%APPDATA%\Code\User\mcp.json`

---

## 2. 只读验证（推荐先做）

### Prompt 1 — 列出案件
```text
使用 xwf-mcp 列出当前所有 X-Ways 案件，告诉我案件名和路径。
```

### Prompt 2 — 打开案件
```text
使用 xwf-mcp 打开 <你的案件名> 案件，读取消息日志摘要。
```

### Prompt 3 — 快照摘要
```text
使用 xwf-mcp 读取 <案件名> 的磁盘快照摘要。
```

### Prompt 4 — 离线分析
```text
使用 xwf-mcp 为 <案件名> 案件查看已准备好的离线 artifact 清单。
```

---

## 3. 导出桥接层验证

```text
1. 使用 xwf-mcp 为 <案件名> 准备导出桥接目录
2. 将 X-Ways 导出文件放入 exports/<案件名>/inbox/
3. 使用 xwf-mcp 将 inbox 中的文件 ingest 成对应类型
4. 使用 xwf-mcp 回答关于 <案件名> 的取证问题
```

---

## 4. 离线 QA 示例问题

将 X-Ways 导出好数据后，可以直接提问：

- "该检材的操作系统版本是什么？"
- "系统最后一次开机时间是什么时候？"
- "列出所有曾连接的 USB 设备及其首次连接时间"
- "该系统是否有 BitLocker 加密？恢复密钥是什么？"
- "分区表类型是 MBR 还是 GPT？有几个分区？"
- "是否发现数据擦除工具的使用痕迹？"

---

## 5. 常见故障排查

| 现象 | 检查点 |
|------|-------|
| 客户端看不到 xwf-mcp | 重启 VS Code；检查 mcp.json 配置 |
| `list_cases` 报错 | 检查 `XWF_CASES_ROOT` 路径是否正确 |
| `open_case` 失败 | 确认案件名拼写；检查 .xfc 文件存在 |
| 写操作失败 | 检查 X-Ways 是否未占用案件；确认无弹窗 |
| 离线 QA 返回"未找到数据" | 执行 `prepare_case_bridge` 后重新导出并 `ingest` |

---

## 6. 最小通过标准

以下 3 项全部成功即说明已正常接通：

1. `list_cases` 返回案件列表
2. `open_case(<案件名>)` 返回元数据
3. `get_offline_artifact_inventory(<案件名>)` 成功（即使为空）


- `Codex` 客户端是否能看到 `xwf-mcp`
- `GitHub Copilot Chat` 是否能看到 `xwf-mcp`
- `xwf-mcp` 是否能正确访问本地 `X-Ways Forensics 20.0`
- 只读结果面是否可用
- 导出桥接层是否可用

建议先只做只读测试，确认稳定后再做会修改案件的操作。

## 0. 前置确认

先手工确认一次：

1. 能正常启动  
   `C:\Users\27516\Desktop\X-Ways Forensics 20.0 Portable\X-Ways Forensics_20.0\xwforensics64.exe`
2. 没有首次运行弹窗、许可证弹窗、语言选择弹窗卡住。
3. 现有案件目录存在：  
   `C:\Users\27516\Desktop\X-Ways Forensics 20.0 Portable\X-Ways_Forensics_Case_Files\Cases`
4. 其中至少有案件：
   - `测试`
   - `新案件`
5. 关闭 X-Ways。
6. 彻底重启 VS Code，或者执行一次 `Developer: Reload Window`。

## 1. 你现在的 MCP 配置位置

已经写好的配置在：

- Codex: [config.toml](</C:/Users/27516/.codex/config.toml>)
- VS Code MCP: [mcp.json](</C:/Users/27516/AppData/Roaming/Code/User/mcp.json>)
- Copilot MCP: [settings.json](</C:/Users/27516/AppData/Roaming/Code/User/settings.json>)

统一启动入口是：

- [run_xwf_mcp.py](</c:/Users/27516/Desktop/X-Ways Forensics 20.0 Portable/XWF-mcp/run_xwf_mcp.py>)

## 2. Codex 联调 Prompt

按顺序发，不要一上来就跑写操作。

### Prompt 1

```text
使用 xwf-mcp 列出当前所有 X-Ways 案件，并告诉我案件名、case 文件路径、case 目录路径。
```

期望结果：

- 能列出至少 `测试` 和 `新案件`
- 返回里能看到 `.xfc` 路径和 case 目录路径

如果失败：

- 大概率是 Codex 没加载到 `xwf-mcp`
- 先重开 VS Code，再开一个新对话

### Prompt 1.5

```text
使用 xwf-mcp 可视化打开 X-Ways，并直接打开 `测试` 案件。
```

期望结果：

- 会弹出可见的 `X-Ways Forensics` 窗口
- `测试` 案件应被直接打开

如果失败：

- 优先检查 X-Ways 是否能手工正常启动
- 再检查 `xwforensics64.exe` 路径是否仍然有效

### Prompt 1.55

```text
使用 xwf-mcp 根据这句话准备分析会话：`分析h盘的计算机检材3`。要求直接可视化打开 X-Ways，自动定位并加载对应检材，准备开始分析。
```

期望结果：
- 会自动把 `H:\检材3.E01` 识别为目标检材
- 如无现成案件，会创建类似 `H盘_计算机检材3` 的案件
- 会弹出可见的 `X-Ways Forensics` 窗口
- 返回里能看到 `case_file`、`evidence_path`、`pid`

如果失败：
- 先确认 `H:` 当前已挂载，且根目录还能看到 `检材3.E01`
- 再确认没有另一个 X-Ways 正在占用同名案件

### Prompt 1.6

```text
使用 xwf-mcp 为 `测试` 案件建立一份待挂载检材计划，先不要真正修改案件。计划里包含：
1. 一个 image: `D:\Evidence\disk1.E01`
2. 一个 dir: `D:\Evidence\LiveCollection`
并把这份计划命名为 `首轮候选检材`
```

期望结果：

- 会返回一份 evidence plan
- 每条记录会显示 `kind`、`path`、`include`
- 不会真的向案件写入检材

### Prompt 2

```text
使用 xwf-mcp 打开 `测试` 案件，只做只读检查，并总结这个案件是否有消息日志、密码词典、导出目录和搜索词目录。
```

期望结果：

- 能读到 `测试.xfc`
- 能看到 `!log/msglog.txt`
- 能看到 `Passwords.txt`
- `exports/测试` 和 `lists/测试` 即使为空也应该能解析

如果失败：

- 大概率是中文案件名没有被正确传递，或者工作区不是当前目录

### Prompt 3

```text
使用 xwf-mcp 读取 `测试` 案件的消息日志，并给我提取磁盘快照摘要。
```

期望结果：

- 能看到 `进行磁盘快照后共有 ... 个数据项`
- 能提取 `total_items`、`previous_items`、`delta_items`

如果失败：

- 大概率是日志路径不对，或客户端没有真正调用 tool

### Prompt 4

```text
使用 xwf-mcp 读取 `测试` 案件的密码词典，并告诉我一共有多少条。
```

期望结果：

- 能读到 `Passwords.txt`
- 应该能看到 `qwerty`、`password`、`密码` 这类词条

### Prompt 5

```text
使用 xwf-mcp 分析 `测试` 案件里的加密文件候选，只做只读分析，并明确区分哪些是启发式候选。
```

期望结果：

- 能返回 `names-heuristic`
- 会明确说这不是 X-Ways 官方结构化命中表

## 3. Copilot 联调 Prompt

Copilot 这边建议也按同样顺序测试，但 prompt 更短一点，避免它太爱自己总结而不调工具。

### Prompt 1

```text
调用 xwf-mcp，列出当前 X-Ways 案件。
```

### Prompt 2

```text
调用 xwf-mcp，打开 `测试` 案件并读取消息日志。
```

### Prompt 3

```text
调用 xwf-mcp，读取 `测试` 案件的磁盘快照摘要。
```

### Prompt 4

```text
调用 xwf-mcp，读取 `测试` 案件的密码词典。
```

### Prompt 5

```text
调用 xwf-mcp，只读分析 `测试` 案件中的加密文件候选。
```

## 4. 导出桥接层测试

当前第一版里，`字符串搜索命中` 和 `加密文件结构化结果` 最稳的读法是桥接导出。

### Prompt 1

```text
使用 xwf-mcp 为 `测试` 案件准备导出桥接目录。
```

期望结果：

- 会创建：
  - `XWF-mcp/exports/测试/README.md`
  - `XWF-mcp/exports/测试/bridge-manifest.json`
  - `XWF-mcp/exports/测试/schemas/...`

### Prompt 2

在 X-Ways 里把某个搜索结果或列表导出成：

- `csv`
- `html`
- `txt`
- `json`

放到：

- `XWF-mcp/exports/测试/inbox/`

### Prompt 3

```text
使用 xwf-mcp，把 `测试` 案件 inbox 里的那个导出文件 ingest 成 search_hits。
```

如果你想显式给路径，也可以这样说：

```text
使用 xwf-mcp，把 `C:\Users\27516\Desktop\X-Ways Forensics 20.0 Portable\XWF-mcp\exports\测试\inbox\你的文件.csv` ingest 成 `测试` 案件的 search_hits。
```

期望结果：

- 会生成 `search-hits-*.jsonl`
- 之后 `get_string_search_matches` 就会优先读它

### Prompt 4

```text
使用 xwf-mcp 读取 `测试` 案件的字符串搜索命中，并优先使用结构化导出结果。
```

## 5. 风险操作测试

前面都通过以后，再试会改案件的操作。

建议不要直接碰正式案件，先用一个新名字，例如：

- `MCP-试验-001`

### Prompt 1

```text
使用 xwf-mcp 新建一个案件 `MCP-试验-001`，要求安全模式，不覆盖已有案件。
```

期望结果：

- 会安全选择一个不冲突的新案件名，然后再创建
- 会返回 `job_id`

### Prompt 2

```text
使用 xwf-mcp 查询刚才那个 job 的状态。
```

### Prompt 3

```text
使用 xwf-mcp 给 `MCP-试验-001` 加载一个镜像文件，但先不要运行 RVS。
```

### Prompt 4

```text
使用 xwf-mcp 对 `MCP-试验-001` 运行新的数据项 RVS，并返回 job_id。
```

## 6. 常见故障对照

### 现象：客户端完全看不到 `xwf-mcp`

优先检查：

- VS Code 是否已经重启
- 当前对话是不是新开的
- [config.toml](</C:/Users/27516/.codex/config.toml>) 是否包含 `xwf-mcp`
- [mcp.json](</C:/Users/27516/AppData/Roaming/Code/User/mcp.json>) 是否包含 `xwf-mcp`

### 现象：能看到 `xwf-mcp`，但 `list_cases` 报错

优先检查：

- Python 路径是否存在：
  `D:\Programs\Python\Python310\python.exe`
- launcher 是否存在：
  [run_xwf_mcp.py](</c:/Users/27516/Desktop/X-Ways Forensics 20.0 Portable/XWF-mcp/run_xwf_mcp.py>)

### 现象：`list_cases` 可以，`open_case("测试")` 不行

优先检查：

- 中文案件名是否在客户端里被改写
- 工作区是否就是：
  `C:\Users\27516\Desktop\X-Ways Forensics 20.0 Portable`
- `测试.xfc` 和 `测试\!log\msglog.txt` 是否仍存在

### 现象：只读操作可以，写操作不行

优先检查：

- X-Ways 是否能手工正常启动
- 是否存在许可证/加密狗/首次弹窗
- 是否有另一个 X-Ways 进程占用案件
- 案件是否已有运行中的 job

### 现象：`get_string_search_matches` 没有命中

说明：

- 这不一定是坏了
- 可能只是还没有结构化导出

优先检查：

- 先执行 `prepare_case_bridge`
- 再把 X-Ways 导出结果放进 `exports/<案件名>/inbox/`
- 再执行 `ingest_export_file`

## 7. 最小通过标准

如果下面 4 件事都成功，就说明第一版已经接通了：

1. `list_cases` 能列出案件
2. `open_case("测试")` 能返回案件元数据
3. `get_volume_snapshot_summary("测试")` 能提取快照摘要
4. `read_password_dictionary("测试")` 能读到 `Passwords.txt`

做到这一步，就可以继续调写操作和导出桥接层了。
