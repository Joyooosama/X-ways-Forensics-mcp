# Export Bridge

这份模板说明 `XWF-mcp` 的结果桥接约定：

1. 在 X-Ways 中运行快照、搜索或加密文件识别。
2. 把导出文件放进某个案件的 `exports/<案件名>/inbox/`。
3. 调用 `ingest_export_file` 归一成 JSONL。
4. 再用 MCP 工具读取标准化结果。

建议优先保留原始导出文件，再生成标准化 JSONL，便于审计和回溯。

