from __future__ import annotations

import json
from urllib.parse import unquote

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts.base import AssistantMessage, UserMessage

from .config import XWaysConfig
from .service import XWaysService

config = XWaysConfig.from_env()
service = XWaysService(config)
mcp = FastMCP(
    name="xwf-mcp",
    instructions=(
        "X-Ways Forensics 20.0 automation server. "
        "Use it for safe case creation, evidence ingestion, RVS runs, "
        "message-log inspection, search-hit export reading, and encrypted-file triage.\n\n"
        "【AI 使用流程】\n"
        "1. 调用 answer_offline_qa(case_ref, questions) 直接回答取证问题\n"
        "2. 如果返回 status='needs_artifacts'，按 ai_next_step 提示调用 ensure_snapshot\n"
        "3. 如果返回 status='unmapped'，用 get_string_search_matches 搜索关键词\n"
        "4. 答案在返回值的 answers[].answer 字段，ai_hint 字段有直接答案提示\n"
    ),
)


def _json(data: object) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool(description="List discovered X-Ways cases and active server paths.")
def list_cases() -> dict:
    return service.list_cases()


@mcp.tool(
    description="Launch visible X-Ways GUI, optionally with one case file already opened.",
)
def launch_xways_gui(case_ref: str | None = None) -> dict:
    return service.launch_xways_gui(case_ref)


@mcp.tool(
    description=(
        "Prepare a visible X-Ways analysis session from a natural request such as "
        "'分析h盘的计算机检材3': resolve the evidence file, create/reuse a case, "
        "stage the evidence plan, and launch X-Ways GUI with the evidence ready."
    ),
)
def prepare_visual_analysis_session(
    request_text: str,
    force_reload_evidence: bool = False,
    override: int | None = None,
) -> dict:
    return service.prepare_visual_analysis_session(
        request_text,
        force_reload_evidence=force_reload_evidence,
        override=override,
    )


@mcp.tool(
    description="Create a new X-Ways case. Safe by default: avoids overwrite by selecting a unique case name unless overwrite_existing=true.",
)
def create_case(
    case_name: str,
    overwrite_existing: bool = False,
    override: int | None = None,
    auto: bool = True,
) -> dict:
    return service.create_case(
        case_name,
        overwrite_existing=overwrite_existing,
        override=override,
        auto=auto,
    )


@mcp.tool(
    description="Resolve and inspect an X-Ways case without forcing a GUI session.",
)
def open_case(case_ref: str) -> dict:
    return service.open_case(case_ref)


@mcp.tool(
    description="Extract evidence object paths referenced by one X-Ways case, primarily from UTF-16 strings embedded in the .xfc file.",
)
def get_case_evidence_sources(case_ref: str) -> dict:
    return service.get_case_evidence_sources(case_ref)


@mcp.tool(
    description="Legacy helper: answer forensics questions from a curated WP-backed question bank, with confidence and validation notes.",
)
def answer_legacy_qa(case_ref: str, questions: list[str]) -> dict:
    return service.answer_legacy_qa(case_ref, questions)


@mcp.tool(
    description=(
        "Plan how to solve forensics questions offline, mapping each question to artifact groups and extraction steps. "
        "(规划离线取证答题方案，返回每题所需的数据源和分析步骤)"
    ),
)
def plan_offline_qa(case_ref: str, questions: list[str]) -> dict:
    return service.plan_offline_qa(case_ref, questions)


@mcp.tool(
    description=(
        "Inspect which offline artifact export kinds are already prepared for one case. "
        "(查看案例已导出哪些数据类型，判断能回答哪些问题)"
    ),
)
def get_offline_artifact_inventory(case_ref: str) -> dict:
    return service.get_offline_artifact_inventory(case_ref)


@mcp.tool(
    description=(
        "Answer a batch of offline forensics questions using local case exports. "
        "(用本地导出数据直接回答取证问题，答案在 answers[].answer 字段)"
    ),
)
def answer_offline_qa(case_ref: str, questions: list[str]) -> dict:
    return service.answer_offline_qa(case_ref, questions)


@mcp.tool(
    description="Add one image or image glob to an existing case via AddImage.",
)
def add_image(
    case_ref: str,
    image_path: str,
    force_as: str | None = None,
    sector_size: int | None = None,
    override: int | None = None,
    auto: bool = True,
) -> dict:
    return service.add_image(
        case_ref,
        image_path,
        force_as=force_as,
        sector_size=sector_size,
        override=override,
        auto=auto,
    )


@mcp.tool(
    description="Add one directory, one file, or a root wildcard to an existing case via AddDir.",
)
def add_dir(
    case_ref: str,
    directory_path: str,
    override: int | None = None,
    auto: bool = True,
) -> dict:
    return service.add_dir(
        case_ref,
        directory_path,
        override=override,
        auto=auto,
    )


@mcp.tool(
    description="Write a case-scoped .lst search-term file for later use with LST: and RVS.",
)
def load_search_terms(
    case_ref: str,
    list_name: str,
    terms: list[str],
    overwrite_existing: bool = False,
) -> dict:
    return service.load_search_terms(
        case_ref,
        list_name,
        terms,
        overwrite_existing=overwrite_existing,
    )


@mcp.tool(
    description="Stage or update a reviewed evidence-mount plan without modifying the X-Ways case yet.",
)
def stage_evidence_plan(
    case_ref: str,
    entries: list[dict],
    replace: bool = False,
    title: str | None = None,
    note: str | None = None,
) -> dict:
    return service.stage_evidence_plan(
        case_ref,
        entries,
        replace=replace,
        title=title,
        note=note,
    )


@mcp.tool(
    description="Read the persisted evidence plan for one case.",
)
def get_evidence_plan(case_ref: str) -> dict:
    return service.get_evidence_plan(case_ref)


@mcp.tool(
    description="Prepare a per-case export bridge bundle with schemas, inbox/raw directories, and a guide.",
)
def prepare_case_bridge(
    case_ref: str,
    overwrite_existing: bool = False,
) -> dict:
    return service.prepare_case_bridge(case_ref, overwrite_existing=overwrite_existing)


@mcp.tool(
    description="Normalize one exported list/report file into canonical JSONL inside the case export directory.",
)
def ingest_export_file(
    case_ref: str,
    kind: str,
    source_path: str,
    copy_source: bool = True,
    title: str | None = None,
) -> dict:
    return service.ingest_export_file(
        case_ref,
        kind,
        source_path,
        copy_source=copy_source,
        title=title,
    )


@mcp.tool(
    description="Run RVS for a case. scope='new' maps to RVS:~+, scope='all' maps to RVS:~. Optionally prepends LST:.",
)
def run_rvs(
    case_ref: str,
    scope: str = "new",
    search_list_name: str | None = None,
    search_list_path: str | None = None,
    override: int | None = None,
    auto: bool = True,
) -> dict:
    return service.run_rvs(
        case_ref,
        scope=scope,
        search_list_name=search_list_name,
        search_list_path=search_list_path,
        override=override,
        auto=auto,
    )


@mcp.tool(
    description="Parse volume snapshot progress and summary from the case message log, plus any structured snapshot exports.",
)
def get_volume_snapshot_summary(case_ref: str) -> dict:
    return service.get_volume_snapshot_summary(case_ref)


@mcp.tool(
    description=(
        "On-demand disk snapshot utility — call this anytime when evidence data is needed, "
        "not limited to any specific workflow. "
        "Checks whether a snapshot already exists: if yes and force=false, returns existing status instantly (zero cost). "
        "If no snapshot exists or force=true, executes RVS. "
        "scope='new' (default) → RVS:~+ incremental scan, fast and economic. "
        "scope='all' → RVS:~ full re-scan for thorough analysis. "
        "Recommended as first step when starting any analysis, "
        "or whenever answer_offline_qa / get_offline_artifact_inventory reports missing artifacts."
    ),
)
def ensure_snapshot(
    case_ref: str,
    scope: str = "new",
    force: bool = False,
    override: int | None = None,
    auto: bool = True,
) -> dict:
    return service.ensure_snapshot(
        case_ref,
        scope=scope,
        force=force,
        override=override,
        auto=auto,
    )


@mcp.tool(
    description="Return keyword search matches from structured exports if available, otherwise fall back to message-log summaries.",
)
def get_string_search_matches(
    case_ref: str,
    search_term: str | None = None,
    limit: int = 100,
) -> dict:
    return service.get_string_search_matches(
        case_ref,
        search_term=search_term,
        limit=limit,
    )


@mcp.tool(
    description="Find encrypted files from structured exports, message-log hints, or a conservative Names-file heuristic scan.",
)
def find_encrypted_files(
    case_ref: str,
    limit: int = 100,
    mode: str = "auto",
) -> dict:
    return service.find_encrypted_files(case_ref, limit=limit, mode=mode)


@mcp.tool(
    description="Read and filter parsed case messages from !log/msglog.txt.",
)
def read_case_messages(
    case_ref: str,
    limit: int = 100,
    contains: str | None = None,
) -> dict:
    return service.read_case_messages(case_ref, limit=limit, contains=contains)


@mcp.tool(
    description="Read the case Passwords.txt dictionary, useful for encrypted-file and container triage.",
)
def read_password_dictionary(
    case_ref: str,
    limit: int = 500,
) -> dict:
    return service.read_password_dictionary(case_ref, limit=limit)


@mcp.tool(
    description="Run a .whs script. If case_ref is supplied, the case is opened first and the script runs in that context.",
)
def run_whs_script(
    script_path: str,
    case_ref: str | None = None,
    override: int | None = None,
    auto: bool = True,
) -> dict:
    return service.run_whs_script(
        script_path,
        case_ref=case_ref,
        override=override,
        auto=auto,
    )


@mcp.tool(description="Return persisted status for an async X-Ways job.")
def get_job_status(job_id: str) -> dict:
    return service.get_job_status(job_id)


@mcp.resource(
    "xways://cases",
    name="xways-cases",
    description="Structured view of discovered X-Ways cases.",
    mime_type="application/json",
)
def resource_cases() -> str:
    return _json(service.list_cases())


@mcp.resource(
    "xways://case/{case_name}/activity-log",
    name="xways-case-activity-log",
    description="Raw !log/msglog.txt text for a case.",
    mime_type="text/plain",
)
def resource_case_activity_log(case_name: str) -> str:
    return service.read_case_activity_log(unquote(case_name))


@mcp.resource(
    "xways://case/{case_name}/messages",
    name="xways-case-messages",
    description="Parsed case message log entries.",
    mime_type="application/json",
)
def resource_case_messages(case_name: str) -> str:
    return _json(service.read_case_messages(unquote(case_name), limit=250))


@mcp.resource(
    "xways://case/{case_name}/exports",
    name="xways-case-exports",
    description="Inventory of bridge exports for a case.",
    mime_type="application/json",
)
def resource_case_exports(case_name: str) -> str:
    return _json(service.get_case_exports(unquote(case_name)))


@mcp.resource(
    "xways://case/{case_name}/offline-artifacts",
    name="xways-case-offline-artifacts",
    description="Readiness view for offline artifact exports used by the answer workflow.",
    mime_type="application/json",
)
def resource_case_offline_artifacts(case_name: str) -> str:
    return _json(service.get_offline_artifact_inventory(unquote(case_name)))


@mcp.resource(
    "xways://case/{case_name}/evidence-plan",
    name="xways-case-evidence-plan",
    description="Persisted reviewed evidence-mount plan for a case.",
    mime_type="application/json",
)
def resource_case_evidence_plan(case_name: str) -> str:
    return _json(service.get_evidence_plan(unquote(case_name)))


@mcp.resource(
    "xways://case/{case_name}/search-lists",
    name="xways-case-search-lists",
    description="Inventory of case-scoped .lst files used by LST:.",
    mime_type="application/json",
)
def resource_case_search_lists(case_name: str) -> str:
    return _json(service.list_search_terms(unquote(case_name)))


@mcp.resource(
    "xways://case/{case_name}/passwords",
    name="xways-case-passwords",
    description="Passwords.txt content for a case.",
    mime_type="application/json",
)
def resource_case_passwords(case_name: str) -> str:
    return _json(service.read_password_dictionary(unquote(case_name)))


@mcp.resource(
    "xways://case/{case_name}/snapshot-summary",
    name="xways-case-snapshot-summary",
    description="Latest volume snapshot summary from message log and export files.",
    mime_type="application/json",
)
def resource_case_snapshot_summary(case_name: str) -> str:
    return _json(service.get_volume_snapshot_summary(unquote(case_name)))


@mcp.resource(
    "xways://job/{job_id}",
    name="xways-job",
    description="Persisted status for one async X-Ways job.",
    mime_type="application/json",
)
def resource_job(job_id: str) -> str:
    return _json(service.get_job_status(job_id))


@mcp.prompt(
    name="new-case-from-image",
    description="Guide an analyst through creating a new case from one or more images.",
)
def prompt_new_case_from_image(case_name: str, image_path: str) -> list:
    return [
        UserMessage(
            f"Create a new X-Ways case named '{case_name}', ingest image '{image_path}', "
            "run a new-items RVS pass, and then summarize what logs and exports should be checked next."
        ),
        AssistantMessage(
            "Prefer safe defaults, avoid overwrite, and call out any missing export bridges for structured hit retrieval."
        ),
    ]


@mcp.prompt(
    name="triage-live-system",
    description="Guide a live-system triage flow that prioritizes safe collection and auditability.",
)
def prompt_triage_live_system(case_name: str) -> list:
    return [
        UserMessage(
            f"Triage a live system into X-Ways case '{case_name}' using AddDir or AddDrive semantics, "
            "then explain how to monitor progress and review the resulting activity log."
        ),
        AssistantMessage(
            "Prefer read-focused actions, mention path/lock risk, and keep the workflow reproducible."
        ),
    ]


@mcp.prompt(
    name="keyword-search-workflow",
    description="Guide a keyword-search workflow that loads terms, runs simultaneous search, and reads back results.",
)
def prompt_keyword_search_workflow(case_name: str, list_name: str) -> list:
    return [
        UserMessage(
            f"For case '{case_name}', create or reuse keyword list '{list_name}', run RVS with LST, "
            "and explain how to retrieve structured search hits if exports are configured."
        ),
        AssistantMessage(
            "If structured exports do not exist, say so clearly and fall back to message-log summaries."
        ),
    ]


@mcp.prompt(
    name="evidence-selection-workflow",
    description="Guide a mixed GUI+MCP evidence-selection workflow before any ingest happens.",
)
def prompt_evidence_selection_workflow(case_name: str) -> list:
    return [
        UserMessage(
            f"For case '{case_name}', open X-Ways visibly, review what evidence should be mounted, "
            "and then stage a proposed evidence plan without executing it yet."
        ),
        AssistantMessage(
            "Separate human judgment from deterministic execution: GUI for choosing, MCP for recording the reviewed plan."
        ),
    ]


@mcp.prompt(
    name="export-bridge-workflow",
    description="Guide how to take an X-Ways exported list and ingest it into the MCP bridge.",
)
def prompt_export_bridge_workflow(case_name: str, source_path: str, kind: str) -> list:
    return [
        UserMessage(
            f"For case '{case_name}', prepare the export bridge, ingest exported file '{source_path}' "
            f"as '{kind}', and explain how to read the normalized results afterward."
        ),
        AssistantMessage(
            "If the source format is lossy or ambiguous, say what fields could not be preserved and why."
        ),
    ]


from .addon_tools import register_addon_tools

register_addon_tools(mcp, service)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
