from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .offline_qa_plan import build_offline_question_plan, normalize_offline_question_text
from .parsers import (
    list_export_files, load_export_records,
    auto_decode_timestamp, analyze_file_timestamps,
    convert_timezone, CST, UTC,
)


# ---------------------------------------------------------------------------
# Topic handler 注册表 — 新增题型只需实现 handler 并注册到此表
# handler 签名: (question, export_dir, cache) -> dict[str, Any]
# ---------------------------------------------------------------------------
_TopicHandler = Callable[[str, Path, dict[str, tuple[list[dict[str, Any]], list[str]]]], dict[str, Any]]
_TOPIC_HANDLERS: dict[str, _TopicHandler] = {}


def register_topic_handler(topic: str, handler: _TopicHandler) -> None:
    """注册一个 topic handler，用于离线答题分发。"""
    _TOPIC_HANDLERS[topic] = handler


KNOWN_OFFLINE_EXPORT_KINDS: tuple[str, ...] = (
    "registry_system",
    "event_logs_system",
    "event_logs_security",
    "event_logs_application",
    "installed_software",
    "registry_devices",
    "registry_sam",
    "registry_ntuser",
    "sunlogin_logs",
    "application_logs",
    "recent_items",
    "browser_history",
    "powershell_history",
    "cmd_history",
    "bash_history",
    "prefetch",
    "amcache",
    "shimcache",
    "srum",
    "process_execution",
    "file_listing",
    "windows_timeline",
    "event_logs_terminal_services",
    "event_logs_pnp",
    "event_logs_wlan",
    "setupapi_logs",
    "recycle_bin",
    "lnk_files",
    "jump_lists",
    "sticky_notes",
    "user_docs",
    "hash_inventory",
    "audio_files",
    "audio_transcript",
    "target_file_export",
    "encrypted_files",
    "scheduled_tasks",
    "event_logs_defender",
    "event_logs_printservice",
    "usn_journal",
    "mft_export",
    "sqlite_wal",
    "etw_traces",
    "disk_partition_info",
    "volume_info",
    "evidence_metadata",
)

EXPORT_KIND_LABELS: dict[str, str] = {
    "registry_system": "Registry System",
    "event_logs_system": "System Event Logs",
    "event_logs_security": "Security Event Logs",
    "event_logs_application": "Application Event Logs",
    "installed_software": "Installed Software",
    "registry_devices": "Registry Devices",
    "registry_sam": "Registry SAM (User Accounts)",
    "registry_ntuser": "Registry NTUSER (User Profile)",
    "sunlogin_logs": "Sunlogin Logs",
    "application_logs": "Application Logs (Generic)",
    "recent_items": "Recent Items / RecentDocs",
    "browser_history": "Browser History",
    "powershell_history": "PowerShell Command History",
    "cmd_history": "CMD Command History",
    "bash_history": "Bash/WSL Command History",
    "prefetch": "Prefetch (Program Execution)",
    "amcache": "Amcache (Application Inventory)",
    "shimcache": "ShimCache / AppCompatCache",
    "srum": "SRUM (System Resource Usage)",
    "process_execution": "Process Execution History",
    "file_listing": "File Listing (Timestamps)",
    "windows_timeline": "Windows Timeline (ActivitiesCache.db)",
    "event_logs_terminal_services": "Terminal Services / RDP Event Logs",
    "event_logs_pnp": "Plug and Play (PnP) Event Logs",
    "event_logs_wlan": "WLAN / WiFi Event Logs",
    "setupapi_logs": "SetupAPI Device Logs",
    "recycle_bin": "Recycle Bin ($Recycle.Bin) Analysis",
    "lnk_files": "LNK Shortcut Files (.lnk)",
    "jump_lists": "Jump Lists (AutomaticDestinations / CustomDestinations)",
    "sticky_notes": "Sticky Notes (便签)",
    "user_docs": "User Documents (桌面/文档文件)",
    "hash_inventory": "File Hash Inventory (MD5/SHA)",
    "audio_files": "Audio Files (音频文件)",
    "audio_transcript": "Audio Transcripts (音频转写文本)",
    "target_file_export": "Target File Export (指定文件导出)",
    "encrypted_files": "Encrypted Files (加密候选文件)",
    "scheduled_tasks": "Scheduled Tasks (计划任务)",
    "event_logs_defender": "Windows Defender Event Logs",
    "event_logs_printservice": "PrintService Event Logs (打印记录)",
    "usn_journal": "USN Journal ($UsnJrnl:$J 变更日志)",
    "mft_export": "MFT Export ($MFT 导出)",
    "sqlite_wal": "SQLite WAL Files (Write-Ahead Log)",
    "etw_traces": "ETW Trace Files (.etl)",
    "disk_partition_info": "Disk Partition Info (分区表/磁盘结构)",
    "volume_info": "Volume/Filesystem Info (卷/文件系统信息)",
    "evidence_metadata": "Evidence Source Metadata (证据源/镜像元数据)",
}

ARTIFACT_GROUP_TO_EXPORT_KINDS: dict[str, list[str]] = {
    "registry_system": ["registry_system"],
    "event_logs_system": ["event_logs_system"],
    "event_logs_security": ["event_logs_security"],
    "event_logs_application": ["event_logs_application"],
    "installed_software": ["installed_software"],
    "registry_software": ["installed_software"],
    "program_files_scan": ["installed_software"],
    "shortcuts": ["installed_software"],
    "registry_devices": ["registry_devices"],
    "usbstor": ["registry_devices"],
    "mounted_devices": ["registry_devices"],
    "registry_sam": ["registry_sam"],
    "registry_ntuser": ["registry_ntuser"],
    "sunlogin_logs": ["sunlogin_logs"],
    "application_logs": ["application_logs", "sunlogin_logs"],
    "recent_items": ["recent_items", "registry_ntuser"],
    "jump_lists": ["jump_lists", "recent_items"],
    "shellbags": ["registry_ntuser"],
    "browser_history": ["browser_history"],
    "browser_login_data": ["browser_history"],
    "browser_local_state": ["browser_history"],
    "security_audit": ["event_logs_security"],
    "user_logon_history": ["event_logs_security", "registry_sam"],
    "powershell_history": ["powershell_history"],
    "cmd_history": ["cmd_history"],
    "bash_history": ["bash_history"],
    "command_history": ["powershell_history", "cmd_history", "bash_history"],
    "prefetch": ["prefetch"],
    "amcache": ["amcache"],
    "shimcache": ["shimcache"],
    "srum": ["srum"],
    "process_execution": ["process_execution", "prefetch", "amcache", "shimcache"],
    "file_listing": ["file_listing", "recent_items"],
    "windows_timeline": ["windows_timeline"],
    "event_logs_terminal_services": ["event_logs_terminal_services"],
    "event_logs_pnp": ["event_logs_pnp"],
    "event_logs_wlan": ["event_logs_wlan"],
    "setupapi_logs": ["setupapi_logs"],
    "rdp_history": ["event_logs_terminal_services", "event_logs_security"],
    "pnp_device_history": ["event_logs_pnp", "event_logs_system", "setupapi_logs", "registry_devices"],
    "wifi_history": ["event_logs_wlan"],
    "user_profile_service": ["event_logs_system", "event_logs_application"],
    "system_time_change": ["event_logs_system", "event_logs_security"],
    "recycle_bin_analysis": ["recycle_bin", "file_listing"],
    "os_basic_info": ["registry_system", "installed_software"],
    "user_account_list": ["registry_sam", "event_logs_security"],
    "network_config": ["registry_system"],
    "lnk_shortcut_analysis": ["lnk_files", "recent_items"],
    "jump_list_analysis": ["jump_lists", "lnk_files", "recent_items"],
    "recent_docs_analysis": ["recent_items", "registry_ntuser"],
    "user_assist_analysis": ["registry_ntuser"],
    "sticky_notes": ["sticky_notes", "user_docs"],
    "user_docs": ["user_docs", "file_listing"],
    "images_or_embedded_objects": ["file_listing"],
    "hash_inventory": ["hash_inventory", "file_listing"],
    "audio_export": ["audio_files"],
    "audio_transcript": ["audio_transcript"],
    "target_file_export": ["target_file_export"],
    "docx_or_zip_unpack": ["target_file_export"],
    "srum_analysis": ["srum"],
    "prefetch_deep_analysis": ["prefetch"],
    "shellbags_analysis": ["registry_ntuser"],
    "file_signature_analysis": ["file_listing"],
    "pcap_file_locator": ["file_listing"],
    "bitlocker_veracrypt_detection": ["encrypted_files", "file_listing", "registry_system"],
    "scheduled_task_analysis": ["scheduled_tasks", "event_logs_security"],
    "autostart_service_analysis": ["registry_system", "registry_ntuser", "installed_software"],
    "defender_antivirus_log": ["event_logs_defender", "event_logs_application"],
    "clipboard_history_analysis": ["windows_timeline"],
    "print_history": ["event_logs_printservice", "event_logs_system"],
    "usn_journal_analysis": ["usn_journal", "file_listing"],
    "mft_entry_analysis": ["mft_export", "file_listing"],
    "sqlite_wal_recovery": ["sqlite_wal", "windows_timeline", "browser_history"],
    "browser_download_cookie": ["browser_history"],
    "etw_trace_analysis": ["etw_traces", "file_listing"],
    "partition_table_analysis": ["disk_partition_info", "file_listing"],
    "volume_filesystem_info": ["volume_info", "disk_partition_info", "registry_system"],
    "usb_device_forensic_timeline": ["registry_devices", "setupapi_logs", "event_logs_pnp"],
    "deleted_partition_detection": ["disk_partition_info", "file_listing"],
    "evidence_source_metadata": ["evidence_metadata", "disk_partition_info"],
    "storage_media_overview": ["evidence_metadata", "disk_partition_info", "volume_info", "registry_devices"],
    "boot_sector_analysis": ["disk_partition_info", "volume_info"],
    "file_carving_analysis": ["file_listing"],
    "disk_activity_timeline": ["usn_journal", "mft_export", "file_listing"],
    "encryption_key_recovery": ["registry_system", "encrypted_files", "file_listing"],
    "external_device_full_history": ["registry_devices", "setupapi_logs", "event_logs_pnp", "event_logs_system", "registry_system"],
    "anti_forensics_detection": ["prefetch", "amcache", "usn_journal", "file_listing", "event_logs_system", "event_logs_security"],
}

WECHAT_ALIASES = ("wechat", "\u5fae\u4fe1")
REMOTE_CONTROL_OPTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("todesk", ("todesk",)),
    ("\u5411\u65e5\u8475", ("sunlogin", "\u5411\u65e5\u8475", "\u5411\u65e5\u8475\u5ba2\u6237\u7aef")),
    ("raylink", ("raylink",)),
    ("\u7231\u601d\u8fdc", ("\u7231\u601d\u8fdc", "aisiyuan", "isiyuan")),
)
USB_OPTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ThinkPLus", ("thinkplus",)),
    ("Toshiba", ("toshiba",)),
    ("Samsumg", ("samsung", "samsumg")),
    ("Database", ("database",)),
)

KEY_NORMALIZE_RE = re.compile(r"[^0-9a-z\u4e00-\u9fff]+", re.IGNORECASE)
VERSION_RE = re.compile(r"\b\d+(?:\.\d+){1,5}\b")
IP_PORT_RE = re.compile(r"(?<!\d)((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)")
IP_RE = re.compile(r"(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d)")
PORT_RE = re.compile(r"(?:port|\u7aef\u53e3)\s*[:=]?\s*(\d{1,5})", re.IGNORECASE)
DATETIME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?P<year>20\d{2})[-/](?P<month>\d{1,2})[-/](?P<day>\d{1,2})"
        r"(?:[ T]+)(?P<hour>\d{1,2}):(?P<minute>\d{1,2})(?::(?P<second>\d{1,2}))?"
    ),
    re.compile(
        r"(?P<year>20\d{2})\s*\u5e74\s*(?P<month>\d{1,2})\s*\u6708\s*(?P<day>\d{1,2})\s*\u65e5"
        r"\s*(?P<hour>\d{1,2})\s*(?:\u65f6|\u70b9)\s*(?P<minute>\d{1,2})\s*\u5206?"
        r"(?:\s*(?P<second>\d{1,2})\s*\u79d2)?"
    ),
)
PARTIAL_DATETIME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?P<month>\d{1,2})[-/](?P<day>\d{1,2})[ T]+(?P<hour>\d{1,2}):(?P<minute>\d{1,2})(?::(?P<second>\d{1,2}))?"
    ),
    re.compile(
        r"(?P<month>\d{1,2})\s*\u6708\s*(?P<day>\d{1,2})\s*\u65e5"
        r"\s*(?P<hour>\d{1,2})\s*(?:\u65f6|\u70b9)\s*(?P<minute>\d{1,2})\s*\u5206?"
        r"(?:\s*(?P<second>\d{1,2})\s*\u79d2)?"
    ),
)
BOOT_KEYWORDS: tuple[tuple[str, int], ...] = (
    ("eventlog service was started", 120),
    ("6005", 100),
    ("boot", 90),
    ("startup", 90),
    ("\u5f00\u673a", 90),
    ("system started", 80),
    ("lastshutdowntime", 45),
    ("shutdown", 25),
    ("\u5173\u673a", 25),
)
SUNLOGIN_ACTIVITY_TERMS = (
    "remote",
    "login",
    "control",
    "client",
    "\u8fdc\u7a0b",
    "\u63a7\u5236",
    "\u767b\u5f55",
)


def get_offline_artifact_inventory(export_dir: Path) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    ready_kinds: list[str] = []
    for kind in KNOWN_OFFLINE_EXPORT_KINDS:
        files = list_export_files(export_dir, kind)
        if files:
            ready_kinds.append(kind)
        items.append(
            {
                "kind": kind,
                "label": EXPORT_KIND_LABELS[kind],
                "ready": bool(files),
                "file_count": len(files),
                "files": files,
            }
        )
    return {
        "known_kinds": list(KNOWN_OFFLINE_EXPORT_KINDS),
        "ready_kinds": ready_kinds,
        "items": items,
    }


def answer_offline_qa(
    export_dir: Path,
    questions: list[str],
) -> dict[str, Any]:
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]] = {}
    answers = [
        _build_offline_answer(export_dir, question, cache=cache) for question in questions
    ]
    answered = sum(1 for item in answers if item["status"] == "answered")
    needs = sum(1 for item in answers if item["status"] == "needs_artifacts")
    result: dict[str, Any] = {
        "summary": {
            "question_count": len(questions),
            "answered_count": answered,
            "needs_artifacts_count": needs,
            "planned_not_implemented_count": sum(
                1 for item in answers if item["status"] == "planned_not_implemented"
            ),
            "unmapped_count": sum(1 for item in answers if item["status"] == "unmapped"),
        },
        "answers": answers,
    }
    # 仅在有缺失数据时才附带 inventory (节省性能)
    if needs > 0:
        result["artifact_inventory"] = get_offline_artifact_inventory(export_dir)
    return result


def _build_offline_answer(
    export_dir: Path,
    question: str,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    plan = build_offline_question_plan(question)
    if not plan.get("matched"):
        return plan

    required_kinds = _required_export_kinds(plan)
    available_kinds = [kind for kind in required_kinds if _has_kind(export_dir, kind, cache=cache)]
    missing_kinds = [kind for kind in required_kinds if kind not in available_kinds]
    topic = str(plan["topic"])

    base = {
        "question": question,
        "matched": True,
        "status": "planned_not_implemented",
        "domain_id": plan["domain_id"],
        "topic": topic,
        "description": plan.get("description", ""),
        "artifact_groups": plan["artifact_groups"],
        "required_export_kinds": required_kinds,
        "available_export_kinds": available_kinds,
        "missing_export_kinds": missing_kinds,
        "answer_format": plan["answer_format"],
        "answer": None,
        "confidence": "low",
        "evidence": [],
        "notes": list(plan.get("extraction_notes", [])),
    }

    # 通过注册表分发 topic handler
    handler = _TOPIC_HANDLERS.get(topic)
    if handler is not None:
        return _merge_answer(base, handler(question, export_dir, cache))
    return base


def _merge_answer(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    merged.update(extra)
    if extra.get("notes"):
        merged["notes"] = list(dict.fromkeys([*base.get("notes", []), *extra["notes"]]))
    if extra.get("evidence"):
        merged["evidence"] = extra["evidence"]
    # 限制 detail_items 数量，避免低智商 AI 被淹没
    if "detail_items" in merged and len(merged["detail_items"]) > 15:
        merged["detail_items"] = merged["detail_items"][:15]
        merged.setdefault("notes", []).append(
            f"(已截断，仅展示前 15 条记录，完整数据共 {len(extra.get('detail_items', []))} 条)"
        )
    # 为低智商 AI 添加直接答案提示
    if merged.get("answer") and merged.get("status") == "answered":
        merged["ai_hint"] = f"直接答案: {merged['answer']}"
    elif merged.get("status") == "needs_artifacts":
        merged.setdefault("ai_next_step", (
            f"需要先导出数据。调用 ensure_snapshot(case_ref, scope='new') 后重试。"
        ))
    return merged


def _answer_last_boot_time(
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    candidates: list[tuple[int, datetime, str, dict[str, Any]]] = []
    for kind in ("event_logs_system", "registry_system"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            score = sum(weight for term, weight in BOOT_KEYWORDS if term in lower or term in text)
            if score <= 0:
                continue
            datetimes = _extract_datetimes_from_record(record)
            if not datetimes:
                continue
            dt = max(datetimes)
            candidates.append((score, dt, files[0] if files else kind, record))
    if not candidates:
        return _missing_answer(
            "No boot-time candidate was extracted from registry-system or event-logs-system exports.",
            required_kinds=["registry_system", "event_logs_system"],
        )
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    score, dt, source_file, record = candidates[0]
    notes = []
    if score < 80:
        notes.append(
            "Boot-time signal is weak, so this answer should be cross-checked with an additional System log export."
        )
    return {
        "status": "answered",
        "answer": dt.strftime("%Y-%m-%d %H:%M:%S"),
        "confidence": "high" if score >= 100 else "medium",
        "evidence": [_record_preview(record, source_file=source_file)],
        "notes": notes,
    }


def _answer_wechat_version(
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    candidates: list[tuple[int, str, str, dict[str, Any]]] = []
    for kind in ("installed_software",):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            if not any(alias in lower or alias in text for alias in WECHAT_ALIASES):
                continue
            version = _extract_version_from_record(record)
            if not version:
                continue
            score = 100
            if "displayversion" in _normalized_record_keys(record):
                score += 20
            candidates.append((score, version, files[0] if files else kind, record))
    if not candidates:
        return _missing_answer(
            "No WeChat version was found in installed-software exports.",
            required_kinds=["installed_software"],
        )
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    _, version, source_file, record = candidates[0]
    return {
        "status": "answered",
        "answer": version,
        "confidence": "high",
        "evidence": [_record_preview(record, source_file=source_file)],
        "notes": [],
    }


def _answer_remote_control_software(
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    matches: dict[str, dict[str, Any]] = {}
    records, files = _load_kind(export_dir, "installed_software", cache=cache)
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        for label, aliases in REMOTE_CONTROL_OPTIONS:
            if any(alias in lower or alias in text for alias in aliases):
                matches.setdefault(
                    label,
                    _record_preview(record, source_file=files[0] if files else "installed_software"),
                )
    if not matches:
        return _missing_answer(
            "No supported remote-control software names were found in installed-software exports.",
            required_kinds=["installed_software"],
        )
    ordered = [label for label, _ in REMOTE_CONTROL_OPTIONS if label in matches]
    return {
        "status": "answered",
        "answer": ordered,
        "confidence": "medium" if len(ordered) == 1 else "high",
        "evidence": [matches[label] for label in ordered[:3]],
        "notes": [],
    }


def _answer_sunlogin_log_filename(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    candidate = _find_best_sunlogin_candidate(question, export_dir, cache=cache)
    if candidate is None:
        return _missing_answer(
            "No Sunlogin log record close to the requested timestamp was found.",
            required_kinds=["sunlogin_logs"],
        )
    source_name = Path(candidate["source_file"]).name
    return {
        "status": "answered",
        "answer": source_name,
        "confidence": candidate["confidence"],
        "evidence": [candidate["preview"]],
        "notes": [],
    }


def _answer_sunlogin_remote_ip_port(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    candidate = _find_best_sunlogin_candidate(question, export_dir, cache=cache)
    if candidate is None:
        return _missing_answer(
            "No Sunlogin log record close to the requested timestamp was found.",
            required_kinds=["sunlogin_logs"],
        )

    records, _ = _load_kind(export_dir, "sunlogin_logs", cache=cache)
    source_file = candidate["source_file"]
    target_dt = _extract_question_datetime(question)
    best_ip_port: tuple[int, str, dict[str, Any]] | None = None
    for record in records:
        if _source_file(record) != source_file:
            continue
        text = _record_text(record)
        ip_port = _extract_ip_port(text)
        if not ip_port:
            continue
        score = 0
        if target_dt is not None:
            record_dts = _extract_datetimes_from_record(record, default_year=target_dt.year)
            if record_dts:
                distance = min(abs((dt - target_dt).total_seconds()) for dt in record_dts)
                score += max(0, 200 - int(distance))
        if any(term in text.lower() or term in text for term in SUNLOGIN_ACTIVITY_TERMS):
            score += 25
        if best_ip_port is None or score > best_ip_port[0]:
            best_ip_port = (
                score,
                ip_port,
                _record_preview(record, source_file=source_file),
            )
    if best_ip_port is None:
        return _missing_answer(
            "A matching Sunlogin log file was found, but no public IP:port pair was extracted from it.",
            required_kinds=["sunlogin_logs"],
        )
    return {
        "status": "answered",
        "answer": best_ip_port[1],
        "confidence": "high" if best_ip_port[0] >= 100 else "medium",
        "evidence": [best_ip_port[2]],
        "notes": [],
    }


def _answer_recent_usb_device(
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    best: tuple[datetime, str, dict[str, Any]] | None = None
    records, files = _load_kind(export_dir, "registry_devices", cache=cache)
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        matched_label = None
        for label, aliases in USB_OPTIONS:
            if any(alias in lower or alias in text for alias in aliases):
                matched_label = label
                break
        if matched_label is None:
            continue
        datetimes = _extract_datetimes_from_record(record)
        latest = max(datetimes) if datetimes else datetime.min
        preview = _record_preview(record, source_file=files[0] if files else "registry_devices")
        if best is None or latest > best[0]:
            best = (latest, matched_label, preview)
    if best is None:
        return _missing_answer(
            "No supported USB device candidate was found in registry-devices exports.",
            required_kinds=["registry_devices"],
        )
    confidence = "high" if best[0] != datetime.min else "medium"
    notes = [] if best[0] != datetime.min else [
        "No connection timestamp was extracted, so the selected device is based on name matching only."
    ]
    return {
        "status": "answered",
        "answer": best[1],
        "confidence": confidence,
        "evidence": [best[2]],
        "notes": notes,
    }


def _find_best_sunlogin_candidate(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any] | None:
    target_dt = _extract_question_datetime(question)
    records, _ = _load_kind(export_dir, "sunlogin_logs", cache=cache)
    best: tuple[int, str, dict[str, Any]] | None = None
    for record in records:
        source_file = _source_file(record)
        if not source_file:
            continue
        text = _record_text(record)
        score = 0
        if any(term in text.lower() or term in text for term in SUNLOGIN_ACTIVITY_TERMS):
            score += 25
        record_dts = _extract_datetimes_from_record(
            record,
            default_year=target_dt.year if target_dt else None,
        )
        if target_dt is not None and record_dts:
            distance = min(abs((dt - target_dt).total_seconds()) for dt in record_dts)
            score += max(0, 240 - int(distance))
        elif target_dt is not None and _question_time_hint(question) in text:
            score += 120
        if best is None or score > best[0]:
            best = (
                score,
                source_file,
                _record_preview(record, source_file=source_file),
            )
    if best is None or best[0] <= 0:
        return None
    return {
        "score": best[0],
        "source_file": best[1],
        "preview": best[2],
        "confidence": "high" if best[0] >= 120 else "medium",
    }


def _missing_answer(message: str, *, required_kinds: list[str]) -> dict[str, Any]:
    return {
        "status": "needs_artifacts",
        "answer": None,
        "confidence": "low",
        "evidence": [],
        "notes": [message],
        "missing_export_kinds": required_kinds,
        "ai_next_step": (
            f"数据不足，请先调用 ensure_snapshot 导出以下数据: {', '.join(required_kinds)}，"
            "然后重新调用 answer_offline_qa。"
        ),
    }


def _required_export_kinds(plan: dict[str, Any]) -> list[str]:
    kinds: list[str] = []
    for group in plan.get("artifact_groups", []):
        for kind in ARTIFACT_GROUP_TO_EXPORT_KINDS.get(group, []):
            if kind not in kinds:
                kinds.append(kind)
    return kinds


def _load_kind(
    export_dir: Path,
    kind: str,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> tuple[list[dict[str, Any]], list[str]]:
    if kind not in cache:
        cache[kind] = load_export_records(export_dir, kind, limit=5000)
    return cache[kind]


def _get_records(
    export_dir: Path,
    kind: str,
    *,
    cache: dict,
) -> list[dict[str, Any]]:
    """返回指定 export kind 的记录列表 (不含 files)。供新 handler 使用。"""
    records, _ = _load_kind(export_dir, kind, cache=cache)
    return records


def _has_kind(
    export_dir: Path,
    kind: str,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> bool:
    records, files = _load_kind(export_dir, kind, cache=cache)
    return bool(files or records)


def _normalized_record_keys(record: dict[str, Any]) -> set[str]:
    return {_normalize_key(key) for key in record}


def _extract_version_from_record(record: dict[str, Any]) -> str | None:
    version_keys = (
        "version",
        "displayversion",
        "productversion",
        "fileversion",
        "\u7248\u672c",
    )
    for key, value in record.items():
        normalized = _normalize_key(key)
        if any(candidate in normalized for candidate in version_keys):
            match = VERSION_RE.search(str(value))
            if match:
                return match.group(0)
    match = VERSION_RE.search(_record_text(record))
    return match.group(0) if match else None


def _extract_question_datetime(question: str) -> datetime | None:
    values = _extract_datetimes(question)
    return values[0] if values else None


def _extract_datetimes_from_record(
    record: dict[str, Any],
    default_year: int | None = None,
) -> list[datetime]:
    values: list[datetime] = []
    for value in record.values():
        values.extend(_extract_datetimes(str(value), default_year=default_year))
    seen: set[str] = set()
    unique: list[datetime] = []
    for value in values:
        token = value.isoformat()
        if token in seen:
            continue
        seen.add(token)
        unique.append(value)
    return unique


def _extract_datetimes(text: str, default_year: int | None = None) -> list[datetime]:
    values: list[datetime] = []
    for pattern in DATETIME_PATTERNS:
        for match in pattern.finditer(text):
            second = int(match.group("second") or "0")
            try:
                values.append(
                    datetime(
                        int(match.group("year")),
                        int(match.group("month")),
                        int(match.group("day")),
                        int(match.group("hour")),
                        int(match.group("minute")),
                        second,
                    )
                )
            except ValueError:
                continue
    if default_year is not None:
        for pattern in PARTIAL_DATETIME_PATTERNS:
            for match in pattern.finditer(text):
                second = int(match.group("second") or "0")
                try:
                    values.append(
                        datetime(
                            default_year,
                            int(match.group("month")),
                            int(match.group("day")),
                            int(match.group("hour")),
                            int(match.group("minute")),
                            second,
                        )
                    )
                except ValueError:
                    continue
    values.sort()
    return values


def _extract_ip_port(text: str) -> str | None:
    direct = IP_PORT_RE.search(text)
    if direct:
        return f"{direct.group(1)}:{direct.group(2)}"
    ip_match = IP_RE.search(text)
    port_match = PORT_RE.search(text)
    if ip_match and port_match:
        return f"{ip_match.group(1)}:{port_match.group(1)}"
    return None


def _record_text(record: dict[str, Any]) -> str:
    parts = []
    for key, value in record.items():
        if key == "_source_file" or value in (None, ""):
            continue
        parts.append(f"{key}={value}")
    return " | ".join(parts)


def _record_preview(record: dict[str, Any], *, source_file: str) -> dict[str, Any]:
    payload = dict(record)
    preview_text = _record_text(payload)
    if len(preview_text) > 320:
        preview_text = preview_text[:317] + "..."
    return {
        "source_file": source_file,
        "preview": preview_text,
    }


def _question_time_hint(question: str) -> str:
    numbers = re.findall(r"\d+", question)
    if len(numbers) >= 6:
        return f"{int(numbers[3]):02d}:{int(numbers[4]):02d}:{int(numbers[5]):02d}"
    return ""


def _source_file(record: dict[str, Any]) -> str | None:
    value = record.get("_source_file")
    return str(value) if value else None


def _normalize_key(value: Any) -> str:
    return KEY_NORMALIZE_RE.sub("", str(value).lower())


# ---------------------------------------------------------------------------
# 新增日志分析类 handler
# ---------------------------------------------------------------------------

SHUTDOWN_KEYWORDS: tuple[tuple[str, int], ...] = (
    ("shutdowntime", 120),
    ("shutdown", 80),
    ("关机", 80),
    ("6006", 100),
    ("1074", 90),
    ("6008", 85),
    ("restart", 60),
    ("重启", 60),
)


def _answer_last_shutdown_time(
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从注册表和系统事件日志中提取最后一次关机时间。"""
    candidates: list[tuple[int, datetime, str, dict[str, Any]]] = []
    for kind in ("registry_system", "event_logs_system"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            score = sum(weight for term, weight in SHUTDOWN_KEYWORDS if term in lower or term in text)
            if score <= 0:
                continue
            datetimes = _extract_datetimes_from_record(record)
            if not datetimes:
                continue
            dt = max(datetimes)
            candidates.append((score, dt, files[0] if files else kind, record))
    if not candidates:
        return _missing_answer(
            "No shutdown-time candidate was extracted from registry-system or event-logs-system exports.",
            required_kinds=["registry_system", "event_logs_system"],
        )
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    score, dt, source_file, record = candidates[0]
    return {
        "status": "answered",
        "answer": dt.strftime("%Y-%m-%d %H:%M:%S"),
        "confidence": "high" if score >= 100 else "medium",
        "evidence": [_record_preview(record, source_file=source_file)],
        "notes": [],
    }


LOGON_EVENT_IDS = {"4624", "4625", "4634", "4647", "4648"}
LOGON_KEYWORDS: tuple[str, ...] = (
    "logon", "登录", "login", "4624", "4625",
    "logoff", "注销", "4634", "4647",
)
LOGON_TYPE_LABELS: dict[str, str] = {
    "2": "Interactive (Local)",
    "3": "Network",
    "7": "Unlock",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def _answer_user_logon_activity(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从安全事件日志中提取用户登录/注销活动。"""
    events: list[dict[str, Any]] = []
    for kind in ("event_logs_security", "event_logs_system"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            if not any(kw in lower or kw in text for kw in LOGON_KEYWORDS):
                continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes) if datetimes else None
            # 尝试提取事件 ID
            event_id = None
            for key, value in record.items():
                nk = _normalize_key(key)
                if nk in ("eventid", "id", "事件id"):
                    event_id = str(value).strip()
                    break
            # 尝试提取 LogonType
            logon_type = None
            for key, value in record.items():
                nk = _normalize_key(key)
                if "logontype" in nk or "登录类型" in nk:
                    logon_type = str(value).strip()
                    break
            events.append({
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
                "event_id": event_id,
                "logon_type": logon_type,
                "logon_type_label": LOGON_TYPE_LABELS.get(logon_type or "", logon_type),
                "preview": _record_text(record)[:200],
                "source_file": files[0] if files else kind,
            })
    if not events:
        return _missing_answer(
            "No logon/logoff events were found in security event log exports.",
            required_kinds=["event_logs_security"],
        )
    # 按时间排序，最近的在前
    events.sort(key=lambda e: e.get("time") or "", reverse=True)
    # 检查问题中是否有特定关注（如"RDP"、"远程"、"失败"）
    q_lower = question.lower()
    if any(kw in q_lower for kw in ("rdp", "远程登录", "远程桌面", "remoteinteractive")):
        events = [e for e in events if e.get("logon_type") == "10" or "rdp" in (e.get("preview") or "").lower()]
    elif any(kw in q_lower for kw in ("失败", "fail", "4625")):
        events = [e for e in events if e.get("event_id") == "4625"]
    summary = f"Found {len(events)} logon-related events."
    top_events = events[:10]
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(events) >= 3 else "medium",
        "evidence": [{"event": e} for e in top_events],
        "notes": [f"Total events: {len(events)}. Showing top {len(top_events)}."],
    }


SERVICE_INSTALL_KEYWORDS: tuple[tuple[str, int], ...] = (
    ("7045", 120),
    ("new service", 100),
    ("服务安装", 100),
    ("service installed", 100),
    ("4697", 90),
    ("7034", 60),
    ("service control manager", 50),
)


def _answer_service_installation(
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从事件日志中提取服务安装/创建记录。"""
    candidates: list[dict[str, Any]] = []
    for kind in ("event_logs_system", "event_logs_security"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            score = sum(w for term, w in SERVICE_INSTALL_KEYWORDS if term in lower or term in text)
            if score <= 0:
                continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None
            candidates.append({
                "time": event_time,
                "score": score,
                "preview": text[:250],
                "source_file": files[0] if files else kind,
            })
    if not candidates:
        return _missing_answer(
            "No service installation events were found in event log exports.",
            required_kinds=["event_logs_system"],
        )
    candidates.sort(key=lambda c: (c["score"], c.get("time") or ""), reverse=True)
    top = candidates[:10]
    return {
        "status": "answered",
        "answer": f"Found {len(candidates)} service install/change events.",
        "confidence": "high" if len(candidates) >= 2 else "medium",
        "evidence": top,
        "notes": [f"Total events: {len(candidates)}. Showing top {len(top)}."],
    }


ACCOUNT_KEYWORDS: tuple[tuple[str, int], ...] = (
    ("4720", 120),  # 账户创建
    ("4722", 80),   # 账户启用
    ("4723", 80),   # 密码修改(用户自己)
    ("4724", 80),   # 密码重置(管理员)
    ("4725", 80),   # 账户禁用
    ("4726", 100),  # 账户删除
    ("4738", 60),   # 属性变更
    ("4732", 70),   # 添加到组
    ("4733", 70),   # 从组移除
    ("user account", 50),
    ("账户", 40),
    ("用户管理", 50),
)


def _answer_account_management(
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从安全事件日志中提取用户账户管理操作。"""
    candidates: list[dict[str, Any]] = []
    for kind in ("event_logs_security", "registry_sam"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            score = sum(w for term, w in ACCOUNT_KEYWORDS if term in lower or term in text)
            if score <= 0:
                continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None
            candidates.append({
                "time": event_time,
                "score": score,
                "preview": text[:250],
                "source_file": files[0] if files else kind,
            })
    if not candidates:
        return _missing_answer(
            "No account management events were found in security event log or SAM exports.",
            required_kinds=["event_logs_security", "registry_sam"],
        )
    candidates.sort(key=lambda c: (c["score"], c.get("time") or ""), reverse=True)
    top = candidates[:10]
    return {
        "status": "answered",
        "answer": f"Found {len(candidates)} account management events.",
        "confidence": "high" if len(candidates) >= 2 else "medium",
        "evidence": top,
        "notes": [f"Total events: {len(candidates)}. Showing top {len(top)}."],
    }


APP_ERROR_KEYWORDS: tuple[tuple[str, int], ...] = (
    ("1000", 100),   # Application Error
    ("1001", 80),    # WER / BugCheck
    ("1002", 70),    # Application Hang
    ("application error", 100),
    ("应用程序错误", 100),
    ("应用崩溃", 90),
    ("faulting", 80),
    ("bugcheck", 90),
    ("蓝屏", 90),
    ("blue screen", 80),
    ("crash", 60),
    ("exception", 40),
)


def _answer_application_error(
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从事件日志中提取应用程序错误/崩溃记录。"""
    candidates: list[dict[str, Any]] = []
    for kind in ("event_logs_application", "event_logs_system"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            score = sum(w for term, w in APP_ERROR_KEYWORDS if term in lower or term in text)
            if score <= 0:
                continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None
            candidates.append({
                "time": event_time,
                "score": score,
                "preview": text[:250],
                "source_file": files[0] if files else kind,
            })
    if not candidates:
        return _missing_answer(
            "No application error/crash events were found in event log exports.",
            required_kinds=["event_logs_application", "event_logs_system"],
        )
    candidates.sort(key=lambda c: (c["score"], c.get("time") or ""), reverse=True)
    top = candidates[:10]
    return {
        "status": "answered",
        "answer": f"Found {len(candidates)} application error/crash events.",
        "confidence": "high" if len(candidates) >= 2 else "medium",
        "evidence": top,
        "notes": [f"Total events: {len(candidates)}. Showing top {len(top)}."],
    }


def _answer_generic_log_timeline(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """通用日志时间线分析 — 从问题中提取关键词，在所有日志中搜索并按时间排序。"""
    # 从问题中提取搜索关键词（排除常见停用词）
    stop_words = {"请", "分析", "日志", "记录", "是什么", "有哪些", "什么时候", "的", "了", "在", "和", "与"}
    q_normalized = normalize_offline_question_text(question)
    tokens = [t for t in re.split(r'[\s,，;；、]+', q_normalized) if t and t not in stop_words and len(t) >= 2]

    all_log_kinds = ("event_logs_system", "event_logs_security", "event_logs_application", "application_logs")
    events: list[dict[str, Any]] = []
    for kind in all_log_kinds:
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            # 如果有搜索词，只保留匹配记录；如果没有搜索词，保留所有
            if tokens:
                score = sum(1 for t in tokens if t in lower or t in text)
                if score <= 0:
                    continue
            else:
                score = 1
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes) if datetimes else None
            events.append({
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
                "score": score,
                "kind": kind,
                "preview": text[:200],
                "source_file": files[0] if files else kind,
            })
    if not events:
        return _missing_answer(
            "No matching log events found across all available log exports.",
            required_kinds=list(all_log_kinds),
        )
    events.sort(key=lambda e: (e.get("time") or "", e["score"]), reverse=True)
    top = events[:20]
    search_info = f"Search tokens: {tokens}" if tokens else "No specific search terms — showing all events."
    return {
        "status": "answered",
        "answer": f"Found {len(events)} matching log events. {search_info}",
        "confidence": "medium",
        "evidence": top,
        "notes": [f"Total events: {len(events)}. Showing top {len(top)}."],
    }




# ---------------------------------------------------------------------------
# 终端命令解析类 handler
# ---------------------------------------------------------------------------

SUSPICIOUS_COMMAND_PATTERNS: tuple[tuple[str, int, str], ...] = (
    # (pattern, severity, description)
    ("invoke-expression", 80, "PowerShell dynamic eval"),
    ("iex(", 80, "PowerShell IEX shorthand"),
    ("-encodedcommand", 90, "Base64-encoded PowerShell"),
    ("-enc ", 85, "Encoded command shorthand"),
    ("downloadstring", 80, "Remote script download"),
    ("downloadfile", 70, "Remote file download"),
    ("certutil", 60, "LOLBin: certutil"),
    ("bitsadmin", 60, "LOLBin: bitsadmin"),
    ("mshta", 70, "LOLBin: mshta"),
    ("regsvr32", 50, "LOLBin: regsvr32"),
    ("rundll32", 40, "LOLBin: rundll32"),
    ("net user", 60, "User management"),
    ("net localgroup", 60, "Local group management"),
    ("whoami", 30, "User enumeration"),
    ("systeminfo", 30, "System enumeration"),
    ("mimikatz", 95, "Credential dumping tool"),
    ("procdump", 70, "Process memory dump"),
    ("sekurlsa", 95, "Credential extraction"),
    ("reg save", 60, "Registry hive export"),
    ("shadow", 50, "Shadow copy/password file"),
    ("bypass", 60, "Execution policy bypass"),
    ("-noprofile", 40, "No-profile PowerShell"),
    ("hidden", 40, "Hidden window execution"),
    ("new-object net.webclient", 75, "WebClient download"),
    ("start-bitstransfer", 60, "BITS file transfer"),
    ("add-mppreference", 70, "Defender exclusion"),
    ("set-mppreference", 70, "Defender configuration"),
    ("disable-", 50, "Disabling security feature"),
)


def _answer_command_history(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从 PowerShell/CMD/Bash 历史中提取命令记录。"""
    all_commands: list[dict[str, Any]] = []
    q_lower = question.lower()
    q_normalized = normalize_offline_question_text(question)

    # 确定搜索范围
    search_kinds: list[str] = []
    if any(kw in q_lower for kw in ("powershell", "ps1", "ps ")):
        search_kinds = ["powershell_history"]
    elif any(kw in q_lower for kw in ("cmd", "command prompt", "命令提示符")):
        search_kinds = ["cmd_history"]
    elif any(kw in q_lower for kw in ("bash", "wsl", "linux", "shell")):
        search_kinds = ["bash_history"]
    else:
        search_kinds = ["powershell_history", "cmd_history", "bash_history"]

    # 从问题中提取搜索关键词
    stop_words = {"命令", "历史", "执行", "记录", "终端", "command", "history", "shell", "哪些", "什么"}
    tokens = [t for t in re.split(r'[\s,，;；、]+', q_normalized) if t and t not in stop_words and len(t) >= 2]

    for kind in search_kinds:
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            cmd_line = record.get("line", record.get("command", text))
            if isinstance(cmd_line, str):
                cmd_line = cmd_line.strip()
            else:
                cmd_line = str(cmd_line).strip()

            if not cmd_line:
                continue

            # 关键词过滤
            lower = cmd_line.lower()
            if tokens:
                if not any(t in lower for t in tokens):
                    continue

            datetimes = _extract_datetimes_from_record(record)
            exec_time = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None

            all_commands.append({
                "time": exec_time,
                "command": cmd_line[:300],
                "kind": kind,
                "source_file": files[0] if files else kind,
            })

    if not all_commands:
        return _missing_answer(
            "No command history records found. Ensure exports are available.",
            required_kinds=search_kinds,
        )
    # 按时间排序（有时间的在前）
    all_commands.sort(key=lambda c: c.get("time") or "", reverse=True)
    top = all_commands[:30]
    return {
        "status": "answered",
        "answer": f"Found {len(all_commands)} command history entries across {', '.join(search_kinds)}.",
        "confidence": "high" if len(all_commands) >= 5 else "medium",
        "evidence": top,
        "notes": [f"Total commands: {len(all_commands)}. Showing top {len(top)}."],
    }


def _answer_program_execution_history(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从 Prefetch/Amcache/ShimCache 中提取程序执行痕迹。"""
    executions: list[dict[str, Any]] = []
    q_normalized = normalize_offline_question_text(question)

    # 从问题中提取搜索关键词（如特定程序名）
    stop_words = {"程序", "执行", "运行", "记录", "痕迹", "哪些", "什么", "过"}
    tokens = [t for t in re.split(r'[\s,，;；、]+', q_normalized) if t and t not in stop_words and len(t) >= 2]

    for kind in ("prefetch", "amcache", "shimcache", "process_execution"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()

            if tokens and not any(t in lower for t in tokens):
                continue

            # 尝试提取程序名
            program_name = None
            for key, value in record.items():
                nk = _normalize_key(key)
                if any(pk in nk for pk in ("executablename", "filename", "name", "path", "程序名", "应用")):
                    program_name = str(value).strip()
                    break
            if not program_name:
                # 从 Prefetch 文件名格式提取: PROGRAMNAME-HASH.pf
                for key, value in record.items():
                    sv = str(value)
                    if ".pf" in sv.lower():
                        parts = sv.rsplit("-", 1)
                        if parts:
                            program_name = parts[0].strip()
                            break
            if not program_name:
                program_name = text[:100]

            # 提取执行次数（Prefetch 特有）
            run_count = None
            for key, value in record.items():
                nk = _normalize_key(key)
                if "runcount" in nk or "执行次数" in nk or "count" in nk:
                    try:
                        run_count = int(value)
                    except (ValueError, TypeError):
                        pass
                    break

            datetimes = _extract_datetimes_from_record(record)
            last_exec = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None

            executions.append({
                "program": program_name,
                "last_execution": last_exec,
                "run_count": run_count,
                "source_kind": kind,
                "source_file": files[0] if files else kind,
                "preview": text[:200],
            })

    if not executions:
        return _missing_answer(
            "No program execution records found. Ensure Prefetch/Amcache/ShimCache exports are available.",
            required_kinds=["prefetch", "amcache", "shimcache"],
        )
    # 按最后执行时间排序
    executions.sort(key=lambda e: e.get("last_execution") or "", reverse=True)
    top = executions[:25]
    return {
        "status": "answered",
        "answer": f"Found {len(executions)} program execution records.",
        "confidence": "high" if len(executions) >= 3 else "medium",
        "evidence": top,
        "notes": [f"Total records: {len(executions)}. Showing top {len(top)}."],
    }


def _answer_suspicious_command_detection(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从命令历史和日志中检测可疑/恶意命令。"""
    findings: list[dict[str, Any]] = []

    # 在命令历史中搜索
    for kind in ("powershell_history", "cmd_history", "bash_history"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            cmd_line = record.get("line", record.get("command", text))
            if isinstance(cmd_line, str):
                cmd_line = cmd_line.strip()
            else:
                cmd_line = str(cmd_line).strip()
            if not cmd_line:
                continue

            lower = cmd_line.lower()
            matched_patterns = []
            total_severity = 0
            for pattern, severity, desc in SUSPICIOUS_COMMAND_PATTERNS:
                if pattern in lower:
                    matched_patterns.append({"pattern": pattern, "severity": severity, "description": desc})
                    total_severity += severity

            if total_severity > 0:
                datetimes = _extract_datetimes_from_record(record)
                exec_time = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None
                findings.append({
                    "command": cmd_line[:300],
                    "time": exec_time,
                    "severity_score": total_severity,
                    "matched_indicators": matched_patterns,
                    "source_kind": kind,
                    "source_file": files[0] if files else kind,
                })

    # 在安全事件日志中搜索 (4688 新进程 / 4104 PowerShell ScriptBlock)
    for kind in ("event_logs_security", "event_logs_application"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            # 只看可能包含命令行的记录
            if "4688" not in text and "4104" not in text and "commandline" not in lower and "scriptblock" not in lower:
                continue
            matched_patterns = []
            total_severity = 0
            for pattern, severity, desc in SUSPICIOUS_COMMAND_PATTERNS:
                if pattern in lower:
                    matched_patterns.append({"pattern": pattern, "severity": severity, "description": desc})
                    total_severity += severity
            if total_severity > 0:
                datetimes = _extract_datetimes_from_record(record)
                exec_time = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None
                findings.append({
                    "command": text[:300],
                    "time": exec_time,
                    "severity_score": total_severity,
                    "matched_indicators": matched_patterns,
                    "source_kind": kind,
                    "source_file": files[0] if files else kind,
                })

    if not findings:
        return _missing_answer(
            "No suspicious commands detected in available command history and event log exports.",
            required_kinds=["powershell_history", "cmd_history", "event_logs_security"],
        )
    # 按危险程度排序
    findings.sort(key=lambda f: f["severity_score"], reverse=True)
    top = findings[:15]
    risk_level = "high" if any(f["severity_score"] >= 80 for f in findings) else "medium"
    return {
        "status": "answered",
        "answer": f"Detected {len(findings)} suspicious commands/events. Highest severity: {findings[0]['severity_score']}.",
        "confidence": "high",
        "evidence": top,
        "notes": [
            f"Risk level: {risk_level}. Total findings: {len(findings)}.",
            "Review evidence details for IOC extraction and incident timeline.",
        ],
    }


def _answer_powershell_script_analysis(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从 PowerShell 历史和事件日志中分析脚本执行记录。"""
    scripts: list[dict[str, Any]] = []
    q_normalized = normalize_offline_question_text(question)
    tokens = [t for t in re.split(r'[\s,，;；、]+', q_normalized)
              if t and len(t) >= 2 and t not in {"powershell", "脚本", "script", "分析", "日志"}]

    # PowerShell 命令历史
    records, files = _load_kind(export_dir, "powershell_history", cache=cache)
    for record in records:
        cmd_line = record.get("line", record.get("command", _record_text(record)))
        if isinstance(cmd_line, str):
            cmd_line = cmd_line.strip()
        else:
            cmd_line = str(cmd_line).strip()
        if not cmd_line:
            continue
        lower = cmd_line.lower()
        if tokens and not any(t in lower for t in tokens):
            continue
        datetimes = _extract_datetimes_from_record(record)
        exec_time = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None
        scripts.append({
            "type": "history",
            "command": cmd_line[:500],
            "time": exec_time,
            "source_file": files[0] if files else "powershell_history",
        })

    # Event ID 4104 (Script Block) / 4103 (Module) 从安全和应用日志
    ps_event_ids = {"4104", "4103"}
    for kind in ("event_logs_security", "event_logs_application"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            # 检查是否是 PowerShell 相关事件
            event_id = None
            for key, value in record.items():
                nk = _normalize_key(key)
                if nk in ("eventid", "id", "事件id"):
                    event_id = str(value).strip()
                    break
            is_ps_event = event_id in ps_event_ids or "scriptblock" in text.lower() or "powershell" in text.lower()
            if not is_ps_event:
                continue
            lower = text.lower()
            if tokens and not any(t in lower for t in tokens):
                continue
            datetimes = _extract_datetimes_from_record(record)
            exec_time = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None
            scripts.append({
                "type": f"event_{event_id or 'unknown'}",
                "command": text[:500],
                "time": exec_time,
                "source_kind": kind,
                "source_file": files[0] if files else kind,
            })

    if not scripts:
        return _missing_answer(
            "No PowerShell script records found in history or event logs.",
            required_kinds=["powershell_history", "event_logs_security"],
        )
    scripts.sort(key=lambda s: s.get("time") or "", reverse=True)
    top = scripts[:20]
    return {
        "status": "answered",
        "answer": f"Found {len(scripts)} PowerShell script/command records.",
        "confidence": "high" if len(scripts) >= 3 else "medium",
        "evidence": top,
        "notes": [f"Total records: {len(scripts)}. Showing top {len(top)}."],
    }


# ---------------------------------------------------------------------------
# Windows 时间信息取证 handler
# ---------------------------------------------------------------------------


# 用于在记录文本中探测可能的原始时间戳数值
_RAW_TIMESTAMP_RE = re.compile(
    r"(?:0x[0-9a-fA-F]{8,16}|\b1[3-9]\d{8,9}\b|\b1[3-9]\d{11,12}\b|\b\d{17,18}\b)"
)

TIMEZONE_KEYWORDS: tuple[tuple[str, int], ...] = (
    ("timezoneinformation", 120),
    ("timezonekey", 100),
    ("timezone", 80),
    ("时区", 80),
    ("bias", 60),
    ("activetimebias", 100),
    ("standardname", 50),
    ("daylightname", 50),
    ("utc", 30),
)


def _answer_timestamp_decode(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """DCode 风格：从问题或导出数据中提取原始时间戳数值并解码为多种格式。"""
    results: list[dict[str, Any]] = []

    # 1. 先从问题文本中提取时间戳数值
    raw_values = _RAW_TIMESTAMP_RE.findall(question)
    for raw in raw_values:
        decoded = auto_decode_timestamp(raw)
        if decoded:
            results.append({
                "source": "question",
                "raw_value": raw,
                "decoded": decoded,
            })

    # 2. 从注册表导出中搜索包含时间戳的记录
    for kind in ("registry_system", "registry_ntuser"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            # 在记录内容中查找可能的原始时间戳
            found_values = _RAW_TIMESTAMP_RE.findall(text)
            for raw in found_values:
                decoded = auto_decode_timestamp(raw)
                if decoded:
                    results.append({
                        "source": files[0] if files else kind,
                        "raw_value": raw,
                        "record_preview": text[:150],
                        "decoded": decoded,
                    })
            if len(results) >= 50:
                break
        if len(results) >= 50:
            break

    if not results:
        # 如果没有找到可解码的时间戳，但问题中有数值，尝试宽松匹配
        numbers = re.findall(r'\d{8,}', question)
        for num in numbers:
            decoded = auto_decode_timestamp(num)
            if decoded:
                results.append({"source": "question", "raw_value": num, "decoded": decoded})
        if not results:
            return _missing_answer(
                "No decodable timestamps found in question or registry exports.",
                required_kinds=["registry_system", "registry_ntuser"],
            )

    return {
        "status": "answered",
        "answer": f"Decoded {len(results)} timestamp(s) across {len({r.get('source', '') for r in results})} source(s).",
        "confidence": "high" if len(results) >= 1 else "medium",
        "evidence": results[:15],
        "notes": [
            "每个时间戳尝试了 FILETIME/Unix/FAT32/WebKit 多种格式。",
            "注意 FAT32 时间戳通常为本地时间而非 UTC。",
        ],
    }


def _answer_timezone_analysis(
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从注册表中提取系统时区设置。"""
    candidates: list[dict[str, Any]] = []
    records, files = _load_kind(export_dir, "registry_system", cache=cache)
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        score = sum(w for term, w in TIMEZONE_KEYWORDS if term in lower or term in text)
        if score <= 0:
            continue

        # 尝试提取 Bias 值
        bias_value = None
        for key, value in record.items():
            nk = _normalize_key(key)
            if "bias" in nk:
                try:
                    bias_value = int(str(value).strip())
                except (ValueError, TypeError):
                    pass
                if bias_value is not None:
                    break

        # 提取时区名称
        tz_name = None
        for key, value in record.items():
            nk = _normalize_key(key)
            if "standardname" in nk or "timezonekeyname" in nk:
                tz_name = str(value).strip()
                break

        utc_offset = None
        if bias_value is not None:
            utc_offset_minutes = -bias_value  # Bias = UTC - Local, so UTC offset = -Bias
            utc_offset_hours = utc_offset_minutes / 60
            utc_offset = f"UTC{'+' if utc_offset_hours >= 0 else ''}{utc_offset_hours:g}"

        candidates.append({
            "score": score,
            "timezone_name": tz_name,
            "bias_minutes": bias_value,
            "utc_offset": utc_offset,
            "preview": text[:200],
            "source_file": files[0] if files else "registry_system",
        })

    if not candidates:
        return _missing_answer(
            "No timezone information found in registry-system exports.",
            required_kinds=["registry_system"],
        )

    candidates.sort(key=lambda c: c["score"], reverse=True)
    best = candidates[0]
    answer_parts = []
    if best.get("timezone_name"):
        answer_parts.append(f"Timezone: {best['timezone_name']}")
    if best.get("utc_offset"):
        answer_parts.append(f"Offset: {best['utc_offset']}")
    if best.get("bias_minutes") is not None:
        answer_parts.append(f"Bias: {best['bias_minutes']} minutes")

    return {
        "status": "answered",
        "answer": " | ".join(answer_parts) if answer_parts else "Timezone info found (see evidence).",
        "confidence": "high" if best["score"] >= 100 else "medium",
        "evidence": candidates[:5],
        "notes": [
            "Bias = UTC - 本地时间（分钟）。CST(中国标准时间): Bias = -480 即 UTC+8。",
            "注意区分 StandardBias 和 DaylightBias（夏令时相关）。",
        ],
    }


def _answer_file_timestamp_analysis(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析文件的 CMA 时间戳，检测时间异常（timestomping 等）。"""
    q_lower = question.lower()
    q_normalized = normalize_offline_question_text(question)

    # 从问题中提取文件名关键词
    file_keywords = [t for t in re.split(r'[\s,，;；、]+', q_normalized)
                     if t and len(t) >= 2 and t not in {"文件", "时间", "创建", "修改", "访问", "分析"}]

    analyzed_files: list[dict[str, Any]] = []

    # 搜索文件列表导出
    for kind in ("recent_items", "registry_ntuser"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()

            # 文件名过滤
            if file_keywords and not any(kw in lower for kw in file_keywords):
                continue

            # 提取 CMA 时间
            created = modified = accessed = None
            for key, value in record.items():
                nk = _normalize_key(key)
                sv = str(value).strip()
                if any(ck in nk for ck in ("created", "creationtime", "创建时间")):
                    created = sv
                elif any(mk in nk for mk in ("modified", "lastwrite", "modifiedtime", "修改时间")):
                    modified = sv
                elif any(ak in nk for ak in ("accessed", "lastaccesstime", "访问时间")):
                    accessed = sv

            if created or modified or accessed:
                analysis = analyze_file_timestamps(created, modified, accessed)
                analysis["record_preview"] = text[:200]
                analysis["source_file"] = files[0] if files else kind
                analyzed_files.append(analysis)

            if len(analyzed_files) >= 30:
                break
        if len(analyzed_files) >= 30:
            break

    if not analyzed_files:
        return _missing_answer(
            "No file timestamp records found for CMA analysis.",
            required_kinds=["recent_items", "registry_ntuser"],
        )

    # 统计异常
    total_anomalies = sum(f.get("anomaly_count", 0) for f in analyzed_files)
    anomalous_files = [f for f in analyzed_files if f.get("anomaly_count", 0) > 0]

    return {
        "status": "answered",
        "answer": f"Analyzed {len(analyzed_files)} file(s). {len(anomalous_files)} with anomalies ({total_anomalies} total).",
        "confidence": "high" if analyzed_files else "medium",
        "evidence": analyzed_files[:15],
        "notes": [
            "CMA = Created/Modified/Accessed。",
            "Modified < Created 通常表示文件被复制（Created 反映复制时间）。",
            "NTFS: 对比 $STANDARD_INFORMATION 和 $FILE_NAME 可检测 timestomping。",
        ],
    }


# ---------------------------------------------------------------------------
# Windows 时间线 (ActivitiesCache.db) handler
# ---------------------------------------------------------------------------

# ActivityType 关键词映射，用于从问题中推断用户关注的活动类型
_TIMELINE_TYPE_KEYWORDS: dict[str, list[int]] = {
    "clipboard": [16],
    "剪贴板": [16],
    "copy": [16],
    "paste": [16],
    "复制": [16],
    "粘贴": [16],
    "open": [5],
    "打开": [5],
    "启动": [5],
    "use": [6],
    "使用": [6],
    "运行": [5, 6],
    "notification": [10],
    "通知": [10],
}


def _answer_windows_timeline(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析 Windows Timeline (ActivitiesCache.db) 用户活动记录。"""
    q_lower = question.lower()
    q_normalized = normalize_offline_question_text(question)

    records, files = _load_kind(export_dir, "windows_timeline", cache=cache)
    if not records:
        return _missing_answer(
            "No Windows Timeline (ActivitiesCache.db) data found.",
            required_kinds=["windows_timeline"],
        )

    # 检查是否有解析错误
    errors = [r for r in records if "_error" in r]
    if errors and len(errors) == len(records):
        return {
            "status": "needs_artifacts",
            "answer": None,
            "confidence": "low",
            "evidence": errors[:3],
            "notes": ["ActivitiesCache.db 解析失败，请检查文件完整性。"],
        }

    valid_records = [r for r in records if "_error" not in r]

    # 从问题中推断活动类型过滤
    target_types: set[int] = set()
    for kw, types in _TIMELINE_TYPE_KEYWORDS.items():
        if kw in q_lower:
            target_types.update(types)

    # 过滤
    filtered = valid_records
    if target_types:
        filtered = [r for r in valid_records if r.get("activity_type") in target_types]

    # 从问题中提取应用名关键词过滤
    app_keywords = [t for t in re.split(r'[\s,，;；、]+', q_normalized)
                    if t and len(t) >= 2 and t not in {
                        "时间线", "活动", "记录", "分析", "用户", "应用", "使用",
                        "timeline", "activity", "windows",
                    }]
    if app_keywords:
        app_filtered = []
        for r in filtered:
            text = (
                str(r.get("app_name", "")) + " " +
                str(r.get("app_id", "")) + " " +
                str(r.get("payload_displayText", "")) + " " +
                str(r.get("payload_description", ""))
            ).lower()
            if any(kw in text for kw in app_keywords):
                app_filtered.append(r)
        if app_filtered:
            filtered = app_filtered

    if not filtered:
        filtered = valid_records[:50]

    # 统计
    type_counts: dict[str, int] = {}
    app_counts: dict[str, int] = {}
    for r in filtered:
        tl = r.get("activity_type_label", "Unknown")
        type_counts[tl] = type_counts.get(tl, 0) + 1
        app = r.get("app_name") or r.get("app_id", "Unknown")
        if isinstance(app, str) and len(app) > 60:
            app = app[:57] + "..."
        app_counts[app] = app_counts.get(app, 0) + 1

    # 构建简洁输出
    top_apps = sorted(app_counts.items(), key=lambda x: -x[1])[:10]
    summary_parts = [f"Total activities: {len(filtered)} (from {len(valid_records)} total)"]
    if type_counts:
        summary_parts.append("Types: " + ", ".join(f"{k}: {v}" for k, v in sorted(type_counts.items(), key=lambda x: -x[1])))
    if top_apps:
        summary_parts.append("Top apps: " + ", ".join(f"{a}({c})" for a, c in top_apps[:5]))

    # 选择证据（最多15条，按时间倒序）
    evidence = []
    for r in filtered[:15]:
        entry: dict[str, Any] = {}
        for key in ("app_name", "activity_type_label", "start_time_utc", "start_time_cst",
                     "end_time_utc", "end_time_cst", "payload_displayText",
                     "payload_description", "payload_appDisplayName"):
            if key in r and r[key] is not None:
                entry[key] = r[key]
        if entry:
            evidence.append(entry)

    return {
        "status": "answered",
        "answer": " | ".join(summary_parts),
        "confidence": "high" if len(filtered) >= 3 else "medium",
        "evidence": evidence,
        "notes": [
            f"ActivitiesCache.db source: {files[0] if files else 'N/A'}",
            "ActivityType: 5=Open, 6=InUse, 10=Notification, 16=Clipboard。",
            "时间戳已同时展示 UTC 和 CST(UTC+8)。",
        ],
    }


# ---------------------------------------------------------------------------
# Windows 事件日志取证类 handler
# ---------------------------------------------------------------------------

# --- User Profile Service 事件常量 ---
USER_PROFILE_EVENT_IDS: set[str] = {"1", "2", "3", "4", "5", "67"}
USER_PROFILE_KEYWORDS: tuple[str, ...] = (
    "user profile service", "profsvc", "profile", "配置文件", "登录通知",
    "注销通知", "ntuser.dat", "usrclass.dat",
)
USER_PROFILE_EVENT_LABELS: dict[str, str] = {
    "1": "收到用户登录通知",
    "2": "完成登录通知处理",
    "3": "收到用户注销通知",
    "4": "完成注销通知处理",
    "5": "加载/卸载注册表文件",
    "67": "用户登录类型 (Regular/Temporary)",
}

# --- RDP/TerminalServices 事件常量 ---
RDP_EVENT_IDS: set[str] = {"21", "22", "23", "24", "25", "1149", "4624", "4625"}
RDP_KEYWORDS: tuple[str, ...] = (
    "rdp", "远程桌面", "远程登录", "remote desktop", "terminal services",
    "localsessionmanager", "remoteconnectionmanager", "mstsc", "3389",
    "远程连接", "远程会话", "logontype", "logon type",
)
RDP_EVENT_LABELS: dict[str, str] = {
    "21": "RDP 登录成功 (LocalSessionManager)",
    "22": "RDP Shell 启动 (LocalSessionManager)",
    "23": "RDP 注销 (LocalSessionManager)",
    "24": "RDP 断开连接 (LocalSessionManager)",
    "25": "RDP 重新连接 (LocalSessionManager)",
    "1149": "RDP 用户认证成功 (RemoteConnectionManager)",
}

# --- PnP 设备事件常量 ---
PNP_EVENT_IDS: set[str] = {"20001", "20003", "400", "410", "430", "8001", "8002"}
PNP_KEYWORDS: tuple[str, ...] = (
    "pnp", "plug and play", "即插即用", "设备安装", "device install",
    "kernel-pnp", "userpnp", "setupapi", "驱动安装", "driver install",
    "usb", "设备接入", "外接设备",
)
PNP_EVENT_LABELS: dict[str, str] = {
    "20001": "驱动安装成功 (System)",
    "20003": "驱动加载 (System)",
    "400": "设备配置开始 (Kernel-PnP)",
    "410": "设备配置完成 (Kernel-PnP)",
    "430": "设备配置受限 (Kernel-PnP)",
    "8001": "请求安装设备 (UserPnp)",
    "8002": "设备安装结束 (UserPnp)",
}

# --- 系统时间修改事件常量 ---
TIME_CHANGE_EVENT_IDS: set[str] = {"1", "4616", "35", "37"}
TIME_CHANGE_KEYWORDS: tuple[str, ...] = (
    "时间修改", "时间变更", "time change", "时间篡改", "系统时钟",
    "4616", "kernel-general", "w32time", "时间同步", "ntp",
)
AUTO_SYNC_ACCOUNTS: set[str] = {
    "local service", "network service", "nt authority\\local service",
    "nt authority\\network service", "system", "nt authority\\system",
}

# --- WLAN/WiFi 事件常量 ---
WLAN_EVENT_IDS: set[str] = {"8001", "8002", "8003", "10000", "10001", "11000", "11001"}
WLAN_KEYWORDS: tuple[str, ...] = (
    "wifi", "wlan", "无线网络", "wireless", "ssid", "wlan-autoconfig",
    "networkprofile", "wifi连接", "wifi历史", "无线连接",
)
WLAN_EVENT_LABELS: dict[str, str] = {
    "8001": "WLAN 连接尝试 (WLAN-AutoConfig)",
    "8002": "WLAN 连接成功 (WLAN-AutoConfig)",
    "8003": "WLAN 断开连接 (WLAN-AutoConfig)",
    "10000": "网络已连接 (NetworkProfile)",
    "10001": "网络已断开 (NetworkProfile)",
    "11000": "无线网络关联开始",
    "11001": "无线网络关联成功",
}


def _extract_event_id(record: dict[str, Any]) -> str | None:
    """从记录中提取 EventID。"""
    for key, value in record.items():
        nk = _normalize_key(key)
        if nk in ("eventid", "id", "事件id", "event_id"):
            return str(value).strip()
    return None


def _extract_field(record: dict[str, Any], *field_names: str) -> str | None:
    """从记录中按候选字段名提取值。"""
    for key, value in record.items():
        nk = _normalize_key(key)
        if nk in field_names:
            return str(value).strip()
    return None


def _answer_user_profile_service(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析 User Profile Service 事件 (EventID 1-5, 67) — 用户登录/注销全过程追踪。"""
    events: list[dict[str, Any]] = []
    for kind in ("event_logs_system", "event_logs_application"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            # 匹配 User Profile Service 关键词或特定 EventID
            eid = _extract_event_id(record)
            is_profile_event = (eid in USER_PROFILE_EVENT_IDS and
                                any(kw in lower for kw in USER_PROFILE_KEYWORDS))
            if not is_profile_event:
                # 宽松匹配: 仅靠关键词
                if not any(kw in lower for kw in ("user profile", "profsvc", "配置文件服务")):
                    continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes) if datetimes else None
            events.append({
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
                "event_id": eid,
                "label": USER_PROFILE_EVENT_LABELS.get(eid or "", eid),
                "preview": text[:200],
                "source_file": files[0] if files else kind,
            })
    if not events:
        return _missing_answer(
            "未在系统/应用日志中找到 User Profile Service 相关事件。",
            required_kinds=["event_logs_system", "event_logs_application"],
        )
    events.sort(key=lambda e: e.get("time") or "", reverse=True)
    # 分组统计
    id_counts: dict[str, int] = {}
    for e in events:
        eid = e.get("event_id") or "unknown"
        id_counts[eid] = id_counts.get(eid, 0) + 1
    summary_parts = [f"EventID {eid}({USER_PROFILE_EVENT_LABELS.get(eid, '?')}): {cnt}条" for eid, cnt in sorted(id_counts.items())]
    return {
        "status": "answered",
        "answer": f"共找到 {len(events)} 条 User Profile Service 事件。" + " | ".join(summary_parts),
        "confidence": "high" if len(events) >= 3 else "medium",
        "evidence": [{"event": e} for e in events[:15]],
        "notes": [
            "登录完整流程: EventID 1→5→67→5→2",
            "注销完整流程: EventID 3→4",
            f"Total: {len(events)} events.",
        ],
    }


def _answer_rdp_remote_access(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析远程桌面 (RDP/Terminal Services) 连接事件。"""
    events: list[dict[str, Any]] = []
    for kind in ("event_logs_terminal_services", "event_logs_security"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            eid = _extract_event_id(record)
            # Terminal Services 特有事件
            is_rdp = eid in RDP_EVENT_IDS
            # 在 Security 日志中仅关注 LogonType=10 (RDP)
            if kind == "event_logs_security" and eid == "4624":
                logon_type = _extract_field(record, "logontype", "logon_type", "登录类型")
                if logon_type != "10":
                    continue
                is_rdp = True
            if not is_rdp and not any(kw in lower for kw in RDP_KEYWORDS):
                continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes) if datetimes else None
            # 提取源 IP
            source_ip = _extract_field(record, "ipaddress", "ip_address", "源ip",
                                        "sourceaddress", "source_address", "客户端ip", "clientip")
            # 提取用户名
            username = _extract_field(record, "username", "user_name", "用户名",
                                       "accountname", "account_name", "帐户名")
            events.append({
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
                "event_id": eid,
                "label": RDP_EVENT_LABELS.get(eid or "", eid),
                "source_ip": source_ip,
                "username": username,
                "preview": text[:200],
                "source_file": files[0] if files else kind,
            })
    if not events:
        return _missing_answer(
            "未找到 RDP/Terminal Services 远程桌面相关事件。",
            required_kinds=["event_logs_terminal_services", "event_logs_security"],
        )
    events.sort(key=lambda e: e.get("time") or "", reverse=True)
    # 提取唯一 IP
    unique_ips = {e["source_ip"] for e in events if e.get("source_ip")}
    unique_users = {e["username"] for e in events if e.get("username")}
    summary = f"共找到 {len(events)} 条 RDP 远程桌面事件。"
    if unique_ips:
        summary += f" 源IP: {', '.join(sorted(unique_ips))}。"
    if unique_users:
        summary += f" 用户: {', '.join(sorted(unique_users))}。"
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(events) >= 3 else "medium",
        "evidence": [{"event": e} for e in events[:15]],
        "notes": [
            "LocalSessionManager: 21=登录, 22=Shell, 23=注销, 24=断开, 25=重连",
            "RemoteConnectionManager: 1149=用户认证成功(含源IP)",
            "Security 4624 LogonType=10 = RDP 登录",
        ],
    }


def _answer_pnp_device_events(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析即插即用 (PnP) 设备事件 — USB/外接设备接入记录。"""
    events: list[dict[str, Any]] = []
    # 事件日志源
    for kind in ("event_logs_pnp", "event_logs_system"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            eid = _extract_event_id(record)
            is_pnp = eid in PNP_EVENT_IDS
            if not is_pnp and not any(kw in lower for kw in PNP_KEYWORDS):
                continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes) if datetimes else None
            device_id = _extract_field(record, "deviceid", "device_id", "设备id",
                                        "deviceinstanceid", "device_instance_id", "硬件id")
            device_desc = _extract_field(record, "devicedescription", "device_description",
                                          "设备描述", "driverdescription", "driver_description")
            events.append({
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
                "event_id": eid,
                "label": PNP_EVENT_LABELS.get(eid or "", eid),
                "device_id": device_id,
                "device_description": device_desc,
                "preview": text[:200],
                "source_file": files[0] if files else kind,
            })
    # SetupAPI 日志源
    setupapi_records, setupapi_files = _load_kind(export_dir, "setupapi_logs", cache=cache)
    for record in setupapi_records:
        text = _record_text(record)
        lower = text.lower()
        if not any(kw in lower for kw in ("install", "安装", "device", "设备", "usb", "pnp")):
            continue
        datetimes = _extract_datetimes_from_record(record)
        event_time = max(datetimes) if datetimes else None
        events.append({
            "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
            "event_id": None,
            "label": "SetupAPI 日志条目",
            "device_id": None,
            "device_description": None,
            "preview": text[:200],
            "source_file": setupapi_files[0] if setupapi_files else "setupapi_logs",
        })
    if not events:
        return _missing_answer(
            "未找到 PnP 即插即用设备相关事件。",
            required_kinds=["event_logs_pnp", "event_logs_system", "setupapi_logs"],
        )
    events.sort(key=lambda e: e.get("time") or "", reverse=True)
    # 提取唯一设备
    unique_devices = {e["device_id"] for e in events if e.get("device_id")}
    summary = f"共找到 {len(events)} 条 PnP 设备事件。"
    if unique_devices:
        summary += f" 涉及 {len(unique_devices)} 个不同设备。"
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(events) >= 3 else "medium",
        "evidence": [{"event": e} for e in events[:15]],
        "notes": [
            "System: 20001=驱动安装, 20003=驱动加载",
            "Kernel-PnP: 400=配置开始, 410=完成, 430=受限",
            "UserPnp: 8001=请求安装, 8002=安装结束",
            "SetupAPI 日志: Win7+: windows\\INF\\Setupapi.dev.log, WinXP: windows\\Setupapi.log",
        ],
    }


def _answer_system_time_change(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析系统时间修改事件 — 区分自动同步和人为修改。"""
    events: list[dict[str, Any]] = []
    for kind in ("event_logs_system", "event_logs_security"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            eid = _extract_event_id(record)
            # EventID=1 (Kernel-General 系统时间报告) 或 EventID=4616 (安全日志时间更改)
            is_time_event = eid in TIME_CHANGE_EVENT_IDS
            if not is_time_event and not any(kw in lower for kw in TIME_CHANGE_KEYWORDS):
                continue
            # 对 System EventID=1 做额外检查：需包含时间相关上下文
            if kind == "event_logs_system" and eid == "1":
                if not any(kw in lower for kw in ("kernel-general", "time", "时间", "clock")):
                    continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes) if datetimes else None
            # 提取帐户名 — 区分自动同步 vs 手动修改
            account = _extract_field(record, "accountname", "account_name", "帐户名",
                                      "username", "user_name", "用户名", "subjectusername")
            is_auto_sync = False
            if account:
                if account.lower().strip() in AUTO_SYNC_ACCOUNTS:
                    is_auto_sync = True
            # 提取时间变化详情
            old_time = _extract_field(record, "previoustime", "previous_time", "旧时间",
                                       "oldtime", "old_time")
            new_time = _extract_field(record, "newtime", "new_time", "新时间")
            events.append({
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
                "event_id": eid,
                "account": account,
                "change_type": "自动同步 (NTP/W32Time)" if is_auto_sync else "手动修改 (用户操作)",
                "old_time": old_time,
                "new_time": new_time,
                "preview": text[:200],
                "source_file": files[0] if files else kind,
            })
    if not events:
        return _missing_answer(
            "未找到系统时间修改相关事件。",
            required_kinds=["event_logs_system", "event_logs_security"],
        )
    events.sort(key=lambda e: e.get("time") or "", reverse=True)
    # 分类统计
    auto_count = sum(1 for e in events if "自动" in e.get("change_type", ""))
    manual_count = len(events) - auto_count
    summary = f"共找到 {len(events)} 条时间修改事件。自动同步: {auto_count}条, 手动修改: {manual_count}条。"
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(events) >= 2 else "medium",
        "evidence": [{"event": e} for e in events[:15]],
        "notes": [
            "System EventID=1: Kernel-General 系统时间报告",
            "Security EventID=4616: 系统时间已更改",
            "区分方法: LOCAL SERVICE/NETWORK SERVICE/SYSTEM = 自动同步, 用户帐户 = 手动修改",
            "W32Time EventID=35/37: 时间同步状态",
        ],
    }


def _answer_wlan_network_events(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析无线网络 (WLAN/WiFi) 连接事件。"""
    events: list[dict[str, Any]] = []
    for kind in ("event_logs_wlan",):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            eid = _extract_event_id(record)
            is_wlan = eid in WLAN_EVENT_IDS
            if not is_wlan and not any(kw in lower for kw in WLAN_KEYWORDS):
                continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes) if datetimes else None
            # 提取 SSID
            ssid = _extract_field(record, "ssid", "profilename", "profile_name",
                                   "networkname", "network_name", "网络名称")
            # 提取 BSSID
            bssid = _extract_field(record, "bssid", "macaddress", "mac_address")
            events.append({
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
                "event_id": eid,
                "label": WLAN_EVENT_LABELS.get(eid or "", eid),
                "ssid": ssid,
                "bssid": bssid,
                "preview": text[:200],
                "source_file": files[0] if files else kind,
            })
    if not events:
        return _missing_answer(
            "未找到 WLAN/WiFi 无线网络相关事件。",
            required_kinds=["event_logs_wlan"],
        )
    events.sort(key=lambda e: e.get("time") or "", reverse=True)
    # 提取唯一 SSID
    unique_ssids = {e["ssid"] for e in events if e.get("ssid")}
    summary = f"共找到 {len(events)} 条 WiFi/WLAN 事件。"
    if unique_ssids:
        summary += f" 涉及 SSID: {', '.join(sorted(unique_ssids))}。"
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(events) >= 3 else "medium",
        "evidence": [{"event": e} for e in events[:15]],
        "notes": [
            "WLAN-AutoConfig: 8001=连接尝试, 8002=连接成功, 8003=断开",
            "NetworkProfile: 10000=网络连接, 10001=网络断开",
            "工具推荐: WiFiHistoryView (NirSoft) 可辅助分析。",
            "日志路径: \\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx",
        ],
    }


def _answer_event_log_filter(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """通用事件日志过滤器 — 按 EventID/来源/时间范围/关键词灵活过滤。"""
    # 从问题中提取 EventID 过滤条件
    eid_pattern = re.compile(r'(?:eventid|事件id|id)\s*[=:：]\s*(\d+)', re.IGNORECASE)
    target_eids = set(eid_pattern.findall(question))
    # 也匹配纯数字 (4-5位, 常见 EventID)
    standalone_eid = re.compile(r'\b(\d{4,5})\b')
    for m in standalone_eid.findall(question):
        if m not in target_eids:
            target_eids.add(m)

    # 从问题中提取时间范围
    date_pattern = re.compile(r'(\d{4}[-/]\d{1,2}[-/]\d{1,2})')
    date_matches = date_pattern.findall(question)
    start_date = date_matches[0] if len(date_matches) >= 1 else None
    end_date = date_matches[1] if len(date_matches) >= 2 else None

    # 提取关键词 (去除常用停顿词)
    stop_words = {"请", "分析", "过滤", "筛选", "查找", "搜索", "事件", "日志",
                  "记录", "是什么", "有哪些", "的", "了", "在", "和", "与", "eventid"}
    q_norm = question.lower()
    tokens = [t for t in re.split(r'[\s,，;；、=:：]+', q_norm)
              if t and t not in stop_words and len(t) >= 2 and not t.isdigit()]

    # 搜索所有可用事件日志
    all_kinds = ("event_logs_system", "event_logs_security", "event_logs_application",
                 "event_logs_terminal_services", "event_logs_pnp", "event_logs_wlan")
    events: list[dict[str, Any]] = []
    for kind in all_kinds:
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            eid = _extract_event_id(record)
            # EventID 过滤
            if target_eids and eid not in target_eids:
                continue
            text = _record_text(record)
            lower = text.lower()
            # 关键词过滤 (如果有)
            if tokens and not target_eids:
                if not any(t in lower for t in tokens):
                    continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes) if datetimes else None
            # 时间范围过滤
            if event_time and start_date:
                try:
                    sd = datetime.strptime(start_date.replace("/", "-"), "%Y-%m-%d")
                    if event_time < sd:
                        continue
                except ValueError:
                    pass
            if event_time and end_date:
                try:
                    ed = datetime.strptime(end_date.replace("/", "-"), "%Y-%m-%d")
                    if event_time > ed.replace(hour=23, minute=59, second=59):
                        continue
                except ValueError:
                    pass
            events.append({
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
                "event_id": eid,
                "kind": kind,
                "preview": text[:200],
                "source_file": files[0] if files else kind,
            })
    if not events:
        filter_desc = []
        if target_eids:
            filter_desc.append(f"EventID={','.join(sorted(target_eids))}")
        if tokens:
            filter_desc.append(f"关键词={','.join(tokens)}")
        if start_date:
            filter_desc.append(f"起始={start_date}")
        return _missing_answer(
            f"未找到匹配事件。过滤条件: {'; '.join(filter_desc) if filter_desc else '无'}",
            required_kinds=list(all_kinds),
        )
    events.sort(key=lambda e: e.get("time") or "", reverse=True)
    top = events[:20]
    filter_info_parts = []
    if target_eids:
        filter_info_parts.append(f"EventID: {','.join(sorted(target_eids))}")
    if tokens:
        filter_info_parts.append(f"关键词: {','.join(tokens)}")
    if start_date:
        filter_info_parts.append(f"时间: {start_date}~{end_date or '至今'}")
    filter_info = " | ".join(filter_info_parts) if filter_info_parts else "无特定过滤条件"
    return {
        "status": "answered",
        "answer": f"共找到 {len(events)} 条匹配事件。过滤条件: {filter_info}",
        "confidence": "high" if len(events) >= 3 else "medium",
        "evidence": top,
        "notes": [
            f"Total: {len(events)} events, showing top {len(top)}.",
            f"搜索范围: {', '.join(all_kinds)}",
            "事件文件路径 (Vista+): \\Windows\\System32\\winevt\\Logs\\",
        ],
    }


# ---------------------------------------------------------------------------
# 操作系统基本信息 handler
# ---------------------------------------------------------------------------

# --- OS 信息关键词 ---
OS_INFO_KEYWORDS: tuple[tuple[str, str], ...] = (
    # (normalized_key_fragment, field_label)
    ("productname", "os_name"),
    ("currentbuildnumber", "build_number"),
    ("currentbuild", "build_number"),
    ("registeredowner", "registered_owner"),
    ("registeredorganization", "registered_organization"),
    ("productid", "product_id"),
    ("installdate", "install_date"),
    ("installeddate", "install_date"),
    ("installtime", "install_date"),
    ("editionid", "edition"),
    ("releaseid", "release_id"),
    ("displayversion", "display_version"),
    ("ubr", "ubr"),
    ("csdversion", "service_pack"),
)

COMPUTER_NAME_KEYWORDS: tuple[str, ...] = (
    "computername", "computer_name", "hostname", "计算机名",
)

PRODUCT_KEY_KEYWORDS: tuple[str, ...] = (
    "productkey", "product_key", "产品密钥", "cdkey", "digitalproductid",
)


def _answer_os_basic_info(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """提取操作系统基本信息: 计算机名、OS版本、安装时间、注册用户名、产品密钥。"""
    os_info: dict[str, str | None] = {
        "computer_name": None,
        "os_name": None,
        "build_number": None,
        "display_version": None,
        "edition": None,
        "registered_owner": None,
        "product_id": None,
        "install_date": None,
        "service_pack": None,
        "product_key": None,
    }
    source_files: list[str] = []

    for kind in ("registry_system", "installed_software"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        if files:
            source_files.extend(files)
        for record in records:
            # 遍历每个 key-value 对
            for key, value in record.items():
                if key.startswith("_"):
                    continue
                nk = _normalize_key(key)
                val_str = str(value).strip() if value is not None else ""
                if not val_str:
                    continue

                # 计算机名
                if any(cn_kw in nk for cn_kw in COMPUTER_NAME_KEYWORDS):
                    if not os_info["computer_name"]:
                        os_info["computer_name"] = val_str

                # 产品密钥
                if any(pk_kw in nk for pk_kw in PRODUCT_KEY_KEYWORDS):
                    if not os_info["product_key"]:
                        os_info["product_key"] = val_str

                # 其他 OS 信息字段
                for kw_fragment, field_label in OS_INFO_KEYWORDS:
                    if kw_fragment in nk:
                        if not os_info.get(field_label):
                            os_info[field_label] = val_str
                        break

            # 也通过全文本搜索提取
            text = _record_text(record)
            lower = text.lower()

            # 从文本中提取计算机名 (常见格式: "ComputerName = XXX" 或 "计算机名: XXX")
            if not os_info["computer_name"]:
                for pat in (r'computer\s*name\s*[=:：]\s*(\S+)', r'计算机名\s*[=:：]\s*(\S+)',
                            r'hostname\s*[=:：]\s*(\S+)'):
                    m = re.search(pat, text, re.IGNORECASE)
                    if m:
                        os_info["computer_name"] = m.group(1)
                        break

            # 从文本中提取安装时间 (InstallDate 可能是 Unix 时间戳)
            if not os_info["install_date"]:
                m = re.search(r'install\s*(?:date|time)\s*[=:：]\s*(\d{8,10})', text, re.IGNORECASE)
                if m:
                    ts = int(m.group(1))
                    if ts > 1_000_000_000 and ts < 2_000_000_000:
                        from .parsers import decode_unix_timestamp, CST as _CST
                        dt = decode_unix_timestamp(ts)
                        if dt:
                            os_info["install_date"] = dt.astimezone(_CST).strftime("%Y-%m-%d %H:%M:%S")

    # 处理 install_date 若还是纯数字
    if os_info.get("install_date") and os_info["install_date"].isdigit():
        ts = int(os_info["install_date"])
        if ts > 1_000_000_000 and ts < 2_000_000_000:
            from .parsers import decode_unix_timestamp, CST as _CST
            dt = decode_unix_timestamp(ts)
            if dt:
                os_info["install_date"] = dt.astimezone(_CST).strftime("%Y-%m-%d %H:%M:%S")

    # 判断是否有有效信息
    filled = {k: v for k, v in os_info.items() if v}
    if not filled:
        return _missing_answer(
            "未能从注册表导出中提取到操作系统基本信息。请确认已导出 registry_system 数据。",
            required_kinds=["registry_system", "installed_software"],
        )

    # 根据问题内容聚焦回答
    q_lower = question.lower()
    answer_parts: list[str] = []

    if any(kw in q_lower for kw in ("计算机名", "computer name", "hostname", "主机名")):
        answer_parts.append(f"计算机名: {os_info.get('computer_name') or '未提取到'}")
    elif any(kw in q_lower for kw in ("版本", "version", "系统版本", "os版本", "windows")):
        ver_parts = []
        if os_info.get("os_name"):
            ver_parts.append(os_info["os_name"])
        if os_info.get("display_version"):
            ver_parts.append(f"版本 {os_info['display_version']}")
        if os_info.get("build_number"):
            ver_parts.append(f"Build {os_info['build_number']}")
        if os_info.get("edition"):
            ver_parts.append(os_info["edition"])
        answer_parts.append(" ".join(ver_parts) if ver_parts else "未提取到版本信息")
    elif any(kw in q_lower for kw in ("安装时间", "install date", "安装日期")):
        answer_parts.append(f"安装时间: {os_info.get('install_date') or '未提取到'}")
    elif any(kw in q_lower for kw in ("注册用户", "owner", "注册人")):
        answer_parts.append(f"注册用户: {os_info.get('registered_owner') or '未提取到'}")
    elif any(kw in q_lower for kw in ("产品密钥", "product key", "cdkey", "序列号")):
        answer_parts.append(f"产品密钥: {os_info.get('product_key') or '未提取到'}")
    elif any(kw in q_lower for kw in ("产品id", "product id")):
        answer_parts.append(f"产品ID: {os_info.get('product_id') or '未提取到'}")
    else:
        # 返回所有信息
        label_map = {
            "computer_name": "计算机名",
            "os_name": "操作系统",
            "build_number": "Build号",
            "display_version": "版本号",
            "edition": "版本",
            "registered_owner": "注册用户",
            "product_id": "产品ID",
            "install_date": "安装时间",
            "service_pack": "Service Pack",
            "product_key": "产品密钥",
        }
        for field, label in label_map.items():
            if os_info.get(field):
                answer_parts.append(f"{label}: {os_info[field]}")

    return {
        "status": "answered",
        "answer": " | ".join(answer_parts),
        "confidence": "high" if len(filled) >= 3 else "medium",
        "evidence": [{"os_info": filled}],
        "notes": [
            f"提取到 {len(filled)} 个字段。",
            "注册表路径: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "计算机名: HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName",
        ],
    }


# --- 用户账户常量 ---
WELL_KNOWN_RIDS: dict[str, str] = {
    "500": "Administrator",
    "501": "Guest",
    "502": "krbtgt",
    "503": "DefaultAccount",
    "504": "WDAGUtilityAccount",
}

USER_ACCOUNT_KEYWORDS: tuple[str, ...] = (
    "user", "用户", "account", "账户", "帐户", "username", "用户名",
    "sid", "rid", "administrator", "guest",
)


def _answer_user_account_list(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """提取系统用户账户列表 — 用户名、SID、创建时间、最后登录、账户类型。"""
    users: list[dict[str, Any]] = []

    # 方式 1: 从 SAM 注册表导出
    sam_records, sam_files = _load_kind(export_dir, "registry_sam", cache=cache)
    for record in sam_records:
        text = _record_text(record)
        lower = text.lower()
        if not any(kw in lower for kw in USER_ACCOUNT_KEYWORDS):
            continue
        # 提取用户名
        username = _extract_field(record, "username", "user_name", "用户名",
                                   "name", "accountname", "account_name", "帐户名")
        if not username:
            # 从文本中尝试提取
            m = re.search(r'(?:user|用户|account|帐户)\s*(?:name|名)?\s*[=:：]\s*(\S+)', text, re.IGNORECASE)
            if m:
                username = m.group(1)
        if not username:
            continue

        sid = _extract_field(record, "sid", "security_identifier", "安全标识符")
        rid = _extract_field(record, "rid", "relative_id")
        # 从SID末尾提取RID
        if sid and not rid:
            parts = sid.split("-")
            if len(parts) >= 4:
                rid = parts[-1]

        last_login = _extract_field(record, "lastlogin", "last_login", "最后登录",
                                     "lastlogon", "last_logon")
        created = _extract_field(record, "created", "creation_time", "创建时间",
                                  "accountcreated", "account_created")
        account_type = _extract_field(record, "accounttype", "account_type", "账户类型",
                                       "type", "useraccountcontrol")
        # 判断是否为管理员
        is_admin = False
        if rid and rid == "500":
            is_admin = True
        if any(kw in lower for kw in ("admin", "管理员")):
            is_admin = True

        users.append({
            "username": username,
            "sid": sid,
            "rid": rid,
            "well_known": WELL_KNOWN_RIDS.get(rid or "", None),
            "is_admin": is_admin,
            "last_login": last_login,
            "created": created,
            "account_type": account_type,
            "preview": text[:200],
            "source": "registry_sam",
        })

    # 方式 2: 从安全日志中补充 (EventID=4720 账户创建)
    sec_records, sec_files = _load_kind(export_dir, "event_logs_security", cache=cache)
    seen_users = {u["username"].lower() for u in users if u.get("username")}
    for record in sec_records:
        eid = _extract_event_id(record)
        if eid != "4720":
            continue
        text = _record_text(record)
        username = _extract_field(record, "targetusername", "target_username",
                                   "目标帐户名", "newaccountname", "new_account_name")
        if not username or username.lower() in seen_users:
            continue
        datetimes = _extract_datetimes_from_record(record)
        created_time = max(datetimes).strftime("%Y-%m-%d %H:%M:%S") if datetimes else None
        sid = _extract_field(record, "targetsid", "target_sid")
        users.append({
            "username": username,
            "sid": sid,
            "rid": sid.split("-")[-1] if sid and "-" in sid else None,
            "well_known": None,
            "is_admin": False,
            "last_login": None,
            "created": created_time,
            "account_type": None,
            "preview": text[:200],
            "source": "event_4720",
        })
        seen_users.add(username.lower())

    if not users:
        return _missing_answer(
            "未能从 SAM 注册表或安全日志中提取用户账户列表。",
            required_kinds=["registry_sam", "event_logs_security"],
        )

    # 去重
    unique: dict[str, dict[str, Any]] = {}
    for u in users:
        key = (u.get("username") or "").lower()
        if key and key not in unique:
            unique[key] = u
    users = list(unique.values())

    admin_count = sum(1 for u in users if u.get("is_admin"))
    summary = f"共找到 {len(users)} 个用户账户。管理员: {admin_count}个。"
    user_names = [u["username"] for u in users]
    summary += f" 用户: {', '.join(user_names)}。"

    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(users) >= 2 else "medium",
        "evidence": users[:15],
        "notes": [
            f"Total: {len(users)} users.",
            "常见 RID: 500=Administrator, 501=Guest, 1000+=普通用户。",
            "SAM 路径: HKLM\\SAM\\SAM\\Domains\\Account\\Users",
        ],
    }


# --- 网络配置常量 ---
NETWORK_CONFIG_KEYWORDS: tuple[str, ...] = (
    "ipaddress", "ip_address", "ip地址", "dhcpipaddress", "dhcp_ip",
    "subnetmask", "subnet_mask", "子网掩码", "defaultgateway", "default_gateway",
    "网关", "nameserver", "dns", "macaddress", "mac_address", "mac地址",
    "physicaladdress", "physical_address", "物理地址",
)


def _answer_network_config(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """提取系统网络配置: IP地址、MAC地址、DNS、网关。"""
    interfaces: list[dict[str, Any]] = []

    records, files = _load_kind(export_dir, "registry_system", cache=cache)
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        if not any(kw in lower for kw in NETWORK_CONFIG_KEYWORDS):
            continue

        iface: dict[str, str | None] = {
            "ip_address": None,
            "dhcp_ip": None,
            "subnet_mask": None,
            "gateway": None,
            "dns": None,
            "mac_address": None,
            "adapter_name": None,
            "dhcp_enabled": None,
        }

        for key, value in record.items():
            if key.startswith("_"):
                continue
            nk = _normalize_key(key)
            val_str = str(value).strip() if value is not None else ""
            if not val_str:
                continue

            if "dhcpipaddress" in nk or "dhcp_ip" in nk:
                iface["dhcp_ip"] = val_str
            elif "ipaddress" in nk or "ip_address" in nk or "ip地址" in nk:
                iface["ip_address"] = val_str
            elif "subnetmask" in nk or "subnet_mask" in nk or "子网" in nk:
                iface["subnet_mask"] = val_str
            elif "defaultgateway" in nk or "gateway" in nk or "网关" in nk:
                iface["gateway"] = val_str
            elif "nameserver" in nk or "dns" in nk:
                iface["dns"] = val_str
            elif "macaddress" in nk or "physicaladdress" in nk or "mac地址" in nk or "物理地址" in nk:
                iface["mac_address"] = val_str
            elif "adaptername" in nk or "description" in nk or "网卡" in nk:
                iface["adapter_name"] = val_str
            elif "enabledhcp" in nk or "dhcp_enabled" in nk:
                iface["dhcp_enabled"] = val_str

        filled = {k: v for k, v in iface.items() if v}
        if filled:
            filled["preview"] = text[:200]
            filled["source_file"] = files[0] if files else "registry_system"
            interfaces.append(filled)

    # 也尝试从全文中用正则提取 IP
    if not interfaces:
        ip_pattern = re.compile(r'(?:ip\s*(?:address|地址)\s*[=:：]\s*)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE)
        mac_pattern = re.compile(r'(?:mac\s*(?:address|地址)\s*[=:：]\s*)([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})', re.IGNORECASE)
        for record in records:
            text = _record_text(record)
            ips = ip_pattern.findall(text)
            macs = mac_pattern.findall(text)
            if ips or macs:
                iface_data: dict[str, Any] = {"preview": text[:200]}
                if ips:
                    iface_data["ip_address"] = ips[0]
                if macs:
                    iface_data["mac_address"] = macs[0]
                interfaces.append(iface_data)

    if not interfaces:
        return _missing_answer(
            "未能从注册表导出中提取网络配置信息。",
            required_kinds=["registry_system"],
        )

    # 根据问题聚焦
    q_lower = question.lower()
    answer_parts: list[str] = []

    if any(kw in q_lower for kw in ("ip", "ip地址")):
        ips = [i.get("ip_address") or i.get("dhcp_ip") for i in interfaces if i.get("ip_address") or i.get("dhcp_ip")]
        answer_parts.append(f"IP地址: {', '.join(set(ips))}" if ips else "未提取到IP地址")
    elif any(kw in q_lower for kw in ("mac", "物理地址", "mac地址")):
        macs = [i["mac_address"] for i in interfaces if i.get("mac_address")]
        answer_parts.append(f"MAC地址: {', '.join(set(macs))}" if macs else "未提取到MAC地址")
    elif any(kw in q_lower for kw in ("dns", "域名服务器")):
        dns_list = [i["dns"] for i in interfaces if i.get("dns")]
        answer_parts.append(f"DNS: {', '.join(set(dns_list))}" if dns_list else "未提取到DNS")
    elif any(kw in q_lower for kw in ("网关", "gateway")):
        gws = [i["gateway"] for i in interfaces if i.get("gateway")]
        answer_parts.append(f"网关: {', '.join(set(gws))}" if gws else "未提取到网关")
    else:
        for iface in interfaces[:3]:
            parts = []
            if iface.get("adapter_name"):
                parts.append(f"网卡: {iface['adapter_name']}")
            if iface.get("ip_address"):
                parts.append(f"IP: {iface['ip_address']}")
            if iface.get("dhcp_ip"):
                parts.append(f"DHCP IP: {iface['dhcp_ip']}")
            if iface.get("mac_address"):
                parts.append(f"MAC: {iface['mac_address']}")
            if iface.get("gateway"):
                parts.append(f"网关: {iface['gateway']}")
            if iface.get("dns"):
                parts.append(f"DNS: {iface['dns']}")
            if parts:
                answer_parts.append(" | ".join(parts))

    return {
        "status": "answered",
        "answer": "\n".join(answer_parts) if answer_parts else f"找到 {len(interfaces)} 个网络接口配置",
        "confidence": "high" if len(interfaces) >= 1 else "medium",
        "evidence": interfaces[:10],
        "notes": [
            f"Total: {len(interfaces)} network interfaces.",
            "注册表路径: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        ],
    }


# ---------------------------------------------------------------------------
# 回收站分析 handler
# ---------------------------------------------------------------------------

def _answer_recycle_bin(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析回收站 ($Recycle.Bin) 中的已删除文件 — 支持 $I 文件解析和文本记录搜索。"""
    from .parsers import parse_recycle_bin_i_file

    deleted_items: list[dict[str, Any]] = []

    # 方式 1: 直接解析 $I 二进制文件 (如果 export_dir 下有)
    for i_file in export_dir.rglob("$I*"):
        if i_file.is_file() and i_file.stat().st_size >= 28:
            parsed = parse_recycle_bin_i_file(i_file)
            if parsed:
                parsed["source"] = "binary_$I"
                deleted_items.append(parsed)

    # 方式 2: 从已导出的 recycle_bin 文本记录加载
    records, files = _load_kind(export_dir, "recycle_bin", cache=cache)
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        datetimes = _extract_datetimes_from_record(record)
        event_time = max(datetimes) if datetimes else None
        # 提取原始路径
        original_path = _extract_field(record, "originalpath", "original_path", "原始路径",
                                        "filepath", "file_path", "文件路径", "path")
        original_filename = _extract_field(record, "filename", "file_name", "文件名",
                                            "originalfilename", "original_filename")
        if not original_filename and original_path:
            original_filename = original_path.rsplit("\\", 1)[-1] if "\\" in original_path else original_path
        file_size = _extract_field(record, "filesize", "file_size", "文件大小", "size",
                                    "originalfilesize", "original_file_size")
        deleted_items.append({
            "i_file": None,
            "original_path": original_path,
            "original_filename": original_filename,
            "original_file_size": file_size,
            "delete_time_utc": event_time.strftime("%Y-%m-%d %H:%M:%S UTC") if event_time else None,
            "preview": text[:200],
            "source": "exported_record",
            "source_file": files[0] if files else "recycle_bin",
        })

    # 方式 3: 在 file_listing 中搜索回收站路径
    fl_records, fl_files = _load_kind(export_dir, "file_listing", cache=cache)
    for record in fl_records:
        text = _record_text(record)
        lower = text.lower()
        if not any(kw in lower for kw in ("$recycle", "recycle.bin", "recycler", "回收站")):
            continue
        datetimes = _extract_datetimes_from_record(record)
        event_time = max(datetimes) if datetimes else None
        original_path = _extract_field(record, "path", "filepath", "file_path",
                                        "fullpath", "full_path")
        original_filename = _extract_field(record, "name", "filename", "file_name")
        file_size = _extract_field(record, "size", "filesize", "file_size")
        deleted_items.append({
            "i_file": None,
            "original_path": original_path,
            "original_filename": original_filename,
            "original_file_size": file_size,
            "delete_time_utc": event_time.strftime("%Y-%m-%d %H:%M:%S UTC") if event_time else None,
            "preview": text[:200],
            "source": "file_listing",
            "source_file": fl_files[0] if fl_files else "file_listing",
        })

    if not deleted_items:
        return _missing_answer(
            "未找到回收站相关数据。请确认已导出 $Recycle.Bin 或相关文件列表。",
            required_kinds=["recycle_bin", "file_listing"],
        )

    # 按删除时间排序
    deleted_items.sort(key=lambda e: e.get("delete_time_utc") or e.get("delete_time_cst") or "", reverse=True)

    # 按问题关键词过滤
    q_lower = question.lower()
    if any(kw in q_lower for kw in ("最近", "最新", "recent", "latest")):
        deleted_items = deleted_items[:10]
    else:
        # 检查是否问特定文件类型
        ext_match = re.search(r'\.(docx?|xlsx?|pptx?|pdf|txt|jpg|png|zip|rar|exe|mp4|avi)\b', q_lower)
        if ext_match:
            target_ext = ext_match.group(0)
            filtered = [item for item in deleted_items
                        if target_ext in (item.get("original_filename") or "").lower()
                        or target_ext in (item.get("original_path") or "").lower()]
            if filtered:
                deleted_items = filtered

    # 提取唯一文件扩展名统计
    ext_counts: dict[str, int] = {}
    for item in deleted_items:
        fname = item.get("original_filename") or ""
        if "." in fname:
            ext = fname.rsplit(".", 1)[-1].lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

    # 提取 SID 信息
    sids: set[str] = set()
    sid_pattern = re.compile(r'S-1-5-21-[\d-]+')
    for item in deleted_items:
        path = item.get("original_path") or item.get("preview") or ""
        m = sid_pattern.search(path)
        if m:
            sids.add(m.group(0))

    summary = f"共找到 {len(deleted_items)} 条回收站删除记录。"
    if ext_counts:
        top_exts = sorted(ext_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        summary += " 文件类型: " + ", ".join(f".{ext}({cnt})" for ext, cnt in top_exts) + "。"
    if sids:
        summary += f" 涉及 {len(sids)} 个用户SID。"

    top = deleted_items[:15]
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(deleted_items) >= 3 else "medium",
        "evidence": top,
        "notes": [
            f"Total: {len(deleted_items)} deleted items, showing top {len(top)}.",
            "$Recycle.Bin 路径: 卷根\\$Recycle.Bin\\{SID}\\",
            "$I 文件 = 元数据 (删除时间+原始路径), $R 文件 = 实际文件内容。",
            "v1=Vista/Win7/8, v2=Win10+。WinXP 使用 RECYCLER\\INFO2 格式。",
        ],
    }


# ---------------------------------------------------------------------------
# LNK 快捷方式分析 handler
# ---------------------------------------------------------------------------

def _answer_lnk_shortcut(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """解析 LNK 快捷方式文件 — 目标路径、MAC时间、卷序列号。"""
    from .parsers import parse_lnk_file

    lnk_items: list[dict[str, Any]] = []

    # 方式1: 从导出记录中加载 (如果 X-Ways 已导出 LNK 元数据为表格)
    records, files = _load_kind(export_dir, "lnk_files", cache=cache)
    if records:
        for record in records:
            text = _record_text(record)
            lnk_items.append({
                "source": "export_table",
                "preview": text[:300],
                **{k: v for k, v in record.items() if k != "_raw"},
            })

    # 方式2: 直接解析 .lnk 二进制文件
    lnk_dir = export_dir / "lnk_files"
    search_dirs = [lnk_dir, export_dir]
    for sdir in search_dirs:
        if not sdir.is_dir():
            continue
        for lnk_path in sdir.rglob("*.lnk"):
            parsed = parse_lnk_file(lnk_path)
            if parsed:
                parsed["source"] = "binary_parse"
                lnk_items.append(parsed)

    if not lnk_items:
        return _missing_answer(
            "未找到 LNK 快捷方式文件或相关导出数据。",
            required_kinds=["lnk_files"],
        )

    # 按问题过滤
    q_lower = question.lower()
    if lnk_items and any(kw in q_lower for kw in ("卷序列号", "volume serial", "serial")):
        filtered = [i for i in lnk_items if i.get("volume_serial")]
        if filtered:
            lnk_items = filtered
    elif any(kw in q_lower for kw in ("目标路径", "target", "路径")):
        filtered = [i for i in lnk_items if i.get("target_path") or i.get("local_base_path")]
        if filtered:
            lnk_items = filtered

    # 排序: 优先有 access_time 的记录
    lnk_items.sort(key=lambda e: e.get("access_time_utc") or e.get("time") or "", reverse=True)

    top = lnk_items[:15]
    # 统计
    unique_serials = {i["volume_serial"] for i in lnk_items if i.get("volume_serial")}
    unique_targets = {i.get("target_path") or i.get("local_base_path") for i in lnk_items
                      if i.get("target_path") or i.get("local_base_path")}
    summary = f"共解析 {len(lnk_items)} 个 LNK 快捷方式。"
    if unique_serials:
        summary += f" 卷序列号: {', '.join(sorted(unique_serials))}。"
    if unique_targets:
        summary += f" 涉及 {len(unique_targets)} 个不同目标路径。"

    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(lnk_items) >= 3 else "medium",
        "evidence": top,
        "notes": [
            "LNK Shell Link Binary Format: Header(76B) + LinkTargetIDList + LinkInfo + StringData",
            "MAC 时间: CreationTime, AccessTime, WriteTime (FILETIME 格式, 已转换为 UTC/CST)",
            "VolumeSerialNumber 来自 LinkInfo 段 VolumeID 结构",
            f"Total: {len(lnk_items)} items, showing top {len(top)}.",
        ],
    }


# ---------------------------------------------------------------------------
# JumpList 跳转列表分析 handler
# ---------------------------------------------------------------------------

# AppID → 应用名 映射缓存
_JUMPLIST_APP_NAMES: dict[str, str] | None = None


def _load_jumplist_app_names() -> dict[str, str]:
    """加载 Jump List Names.txt 映射文件。"""
    global _JUMPLIST_APP_NAMES
    if _JUMPLIST_APP_NAMES is not None:
        return _JUMPLIST_APP_NAMES
    _JUMPLIST_APP_NAMES = {}
    # 搜索可能的路径
    candidates = [
        Path(__file__).parent.parent.parent / "X-Ways Forensics_20.0" / "Jump List Names.txt",
        Path(__file__).parent.parent / "Jump List Names.txt",
        Path(__file__).parent / "Jump List Names.txt",
    ]
    for p in candidates:
        if p.is_file():
            try:
                for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        _JUMPLIST_APP_NAMES[parts[0].strip().lower()] = parts[1].strip()
            except OSError:
                pass
            break
    return _JUMPLIST_APP_NAMES


def _answer_jump_list(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析 JumpList (AutomaticDestinations / CustomDestinations)。"""
    from .parsers import parse_automatic_destinations, parse_custom_destinations

    all_entries: list[dict[str, Any]] = []
    app_names = _load_jumplist_app_names()

    # 方式1: 从导出表格加载
    records, files = _load_kind(export_dir, "jump_lists", cache=cache)
    if records:
        for record in records:
            text = _record_text(record)
            all_entries.append({
                "source": "export_table",
                "preview": text[:300],
                **{k: v for k, v in record.items() if k != "_raw"},
            })

    # 方式2: 直接解析二进制 JumpList 文件
    search_dirs = [export_dir / "jump_lists", export_dir / "AutomaticDestinations",
                   export_dir / "CustomDestinations", export_dir]
    for sdir in search_dirs:
        if not sdir.is_dir():
            continue
        for f in sdir.rglob("*.automaticDestinations-ms"):
            entries = parse_automatic_destinations(f)
            for e in entries:
                aid = (e.get("app_id") or "").lower()
                e["app_name"] = app_names.get(aid, aid)
            all_entries.extend(entries)
        for f in sdir.rglob("*.customDestinations-ms"):
            entries = parse_custom_destinations(f)
            for e in entries:
                aid = (e.get("app_id") or "").lower()
                e["app_name"] = app_names.get(aid, aid)
            all_entries.extend(entries)

    if not all_entries:
        return _missing_answer(
            "未找到 JumpList 文件或相关导出数据。",
            required_kinds=["jump_lists"],
        )

    # 按问题过滤
    q_lower = question.lower()
    if all_entries:
        # 检查是否查询特定应用
        for entry in all_entries:
            entry.setdefault("app_name", "")
        # 提取问题中的应用名关键词
        app_filter_tokens = [t for t in re.split(r'[\s,，;；、]+', q_lower)
                             if len(t) >= 2 and t not in ("jumplist", "跳转列表", "分析", "最近", "打开")]
        if app_filter_tokens:
            filtered = [e for e in all_entries
                        if any(t in (e.get("app_name") or "").lower() or
                               t in (e.get("target_path") or "").lower()
                               for t in app_filter_tokens)]
            if filtered:
                all_entries = filtered

    # 排序
    all_entries.sort(key=lambda e: e.get("access_time_utc") or e.get("time") or "", reverse=True)

    top = all_entries[:20]
    # 统计
    unique_apps = {e.get("app_name") or e.get("app_id") or "unknown" for e in all_entries}
    auto_count = sum(1 for e in all_entries if e.get("jumplist_type") == "AutomaticDestinations")
    custom_count = sum(1 for e in all_entries if e.get("jumplist_type") == "CustomDestinations")
    table_count = sum(1 for e in all_entries if e.get("source") == "export_table")

    summary = f"共解析 {len(all_entries)} 条 JumpList 记录。"
    if auto_count:
        summary += f" AutomaticDestinations: {auto_count}条。"
    if custom_count:
        summary += f" CustomDestinations: {custom_count}条。"
    if table_count:
        summary += f" 导出表格: {table_count}条。"
    if unique_apps:
        summary += f" 涉及 {len(unique_apps)} 个应用。"

    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(all_entries) >= 3 else "medium",
        "evidence": top,
        "notes": [
            "AutomaticDestinations: OLE 复合文档, 每个 stream 是一个 LNK",
            "CustomDestinations: 多个 LNK 按 magic(4C000000) 拼接",
            "AppID 通过 Jump List Names.txt 映射到应用程序名称",
            f"已加载 {len(app_names)} 个 AppID 映射。",
            f"Total: {len(all_entries)} entries, showing top {len(top)}.",
        ],
    }


# ---------------------------------------------------------------------------
# 注册表 RecentDocs MRU handler
# ---------------------------------------------------------------------------

RECENT_DOCS_KEYWORDS: tuple[str, ...] = (
    "recentdocs", "recent docs", "最近文档", "最近访问", "最近打开",
    "recently opened", "mrulistex", "mru", "最近使用",
)


def _answer_recent_docs(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析注册表 RecentDocs MRU — 最近访问/打开的文件记录。"""
    docs: list[dict[str, Any]] = []
    for kind in ("recent_items", "registry_ntuser"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            # 匹配 RecentDocs 相关记录
            is_recent = any(kw in lower for kw in RECENT_DOCS_KEYWORDS)
            if not is_recent:
                # 宽松: 包含文件扩展名 + recent 路径特征
                if not ("recent" in lower and any(ext in lower for ext in (".doc", ".xls", ".pdf", ".txt", ".jpg", ".png", ".zip"))):
                    continue
            datetimes = _extract_datetimes_from_record(record)
            event_time = max(datetimes) if datetimes else None
            # 提取文件名
            filename = _extract_field(record, "filename", "file_name", "文件名",
                                       "name", "valuename", "value_name", "值名称")
            # 提取扩展名/子键
            ext_key = _extract_field(record, "extension", "ext", "扩展名",
                                      "subkey", "sub_key", "子键")
            # 提取路径
            path = _extract_field(record, "path", "filepath", "file_path",
                                   "路径", "data", "值数据")
            docs.append({
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S") if event_time else None,
                "filename": filename,
                "extension": ext_key,
                "path": path,
                "preview": text[:250],
                "source_file": files[0] if files else kind,
            })
    if not docs:
        return _missing_answer(
            "未找到 RecentDocs MRU 相关记录。请确认已导出 NTUSER.DAT 注册表或 Recent Items。",
            required_kinds=["recent_items", "registry_ntuser"],
        )
    # 按问题中关键词过滤
    q_lower = question.lower()
    ext_filter = re.findall(r'\.(doc[x]?|xls[x]?|pdf|txt|jpg|png|zip|rar|exe|ppt[x]?)', q_lower)
    if ext_filter:
        filtered = [d for d in docs if any(
            ext in (d.get("extension") or "").lower() or ext in (d.get("filename") or "").lower() or ext in (d.get("preview") or "").lower()
            for ext in ext_filter
        )]
        if filtered:
            docs = filtered

    docs.sort(key=lambda d: d.get("time") or "", reverse=True)
    top = docs[:20]
    # 统计扩展名
    ext_counts: dict[str, int] = {}
    for d in docs:
        ext = d.get("extension") or "unknown"
        ext_counts[ext] = ext_counts.get(ext, 0) + 1
    summary = f"共找到 {len(docs)} 条最近访问文件记录。"
    if ext_counts:
        top_exts = sorted(ext_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        summary += " 扩展名: " + ", ".join(f"{e}({c})" for e, c in top_exts)

    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(docs) >= 3 else "medium",
        "evidence": top,
        "notes": [
            "注册表路径: NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
            "子键按扩展名分类, MRUListEx 值记录访问顺序。",
            f"Total: {len(docs)} records, showing top {len(top)}.",
        ],
    }


# --- UserAssist 常量 ---
USER_ASSIST_KEYWORDS: tuple[str, ...] = (
    "userassist", "user_assist", "rot13", "程序执行", "运行次数",
    "execution count", "run count", "程序启动", "launched",
    "cebff5cd", "f4e57c4b",
)


def _rot13(s: str) -> str:
    """对字符串执行 ROT13 解码。"""
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def _answer_user_assist(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """提取 UserAssist 程序执行记录: ROT13 解码 + 运行次数/时间。"""
    records, files = _load_kind(export_dir, "registry_ntuser", cache=cache)
    entries: list[dict[str, Any]] = []

    for record in records:
        text = _record_text(record)
        lower = text.lower()
        if "userassist" not in lower and "user assist" not in lower:
            continue

        # 尝试从字段中提取键名 / 值名
        raw_name = None
        run_count = None
        last_run = None
        for key, value in record.items():
            if key.startswith("_"):
                continue
            nk = _normalize_key(key)
            val_str = str(value).strip() if value is not None else ""
            if not val_str:
                continue
            if nk in ("valuename", "name", "keyname", "entry"):
                raw_name = val_str
            elif "count" in nk or "runcount" in nk or "运行次数" in nk:
                try:
                    run_count = int(val_str)
                except ValueError:
                    pass
            elif "lastrun" in nk or "last_run" in nk or "最后运行" in nk or "lastexecution" in nk:
                last_run = val_str
            elif nk in ("timestamp", "time", "modified", "时间") and last_run is None:
                last_run = val_str

        if raw_name:
            decoded_name = _rot13(raw_name)
            entry: dict[str, Any] = {
                "raw_name": raw_name,
                "decoded_name": decoded_name,
            }
            if run_count is not None:
                entry["run_count"] = run_count
            if last_run:
                entry["last_run"] = last_run
            entry["preview"] = text[:200]
            entry["source_file"] = files[0] if files else "registry_ntuser"
            entries.append(entry)

    if not entries:
        return _missing_answer(
            "未能从 registry_ntuser 导出中提取 UserAssist 记录。",
            required_kinds=["registry_ntuser"],
        )

    # 按运行次数降序排列
    entries.sort(key=lambda e: e.get("run_count", 0), reverse=True)

    # 根据问题聚焦
    q_lower = question.lower()
    # 如果用户问特定程序
    focused = entries
    for token in ("chrome", "firefox", "edge", "notepad", "explorer", "cmd", "powershell",
                  "word", "excel", "wechat", "qq", "todesk", "sunlogin"):
        if token in q_lower:
            focused = [e for e in entries if token in e["decoded_name"].lower()]
            break

    if not focused:
        focused = entries

    top = focused[:20]
    lines: list[str] = []
    for e in top:
        parts = [e["decoded_name"]]
        if "run_count" in e:
            parts.append(f"运行{e['run_count']}次")
        if "last_run" in e:
            parts.append(f"最后运行: {e['last_run']}")
        lines.append(" | ".join(parts))

    summary = f"UserAssist 记录 (共{len(entries)}条, 显示前{len(top)}条):\n" + "\n".join(lines)

    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(entries) >= 3 else "medium",
        "evidence": top,
        "notes": [
            "注册表路径: NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count",
            "键名使用 ROT13 编码, 已自动解码。",
            f"共提取 {len(entries)} 条 UserAssist 记录。",
        ],
    }


# --- browser_saved_password handler ---
BROWSER_PW_KEYWORDS: tuple[str, ...] = (
    "password", "密码", "login data", "credential", "凭据", "登录",
    "saved password", "保存密码", "浏览器密码",
)


def _answer_browser_saved_password(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从浏览器历史/Login Data导出中提取保存的密码/凭据。"""
    records, files = _load_kind(export_dir, "browser_history", cache=cache)
    creds: list[dict[str, Any]] = []
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        if not any(kw in lower for kw in BROWSER_PW_KEYWORDS):
            continue
        entry: dict[str, str | None] = {"url": None, "username": None, "password": None}
        for key, value in record.items():
            if key.startswith("_"):
                continue
            nk = _normalize_key(key)
            val_str = str(value).strip() if value is not None else ""
            if not val_str:
                continue
            if "url" in nk or "origin" in nk or "网址" in nk:
                entry["url"] = val_str
            elif "username" in nk or "用户名" in nk or "account" in nk or "帐号" in nk or "账号" in nk:
                entry["username"] = val_str
            elif "password" in nk or "密码" in nk:
                entry["password"] = val_str
        filled = {k: v for k, v in entry.items() if v}
        if filled:
            filled["preview"] = text[:200]
            filled["source_file"] = files[0] if files else "browser_history"
            creds.append(filled)
    if not creds:
        return _missing_answer(
            "未能从浏览器导出中提取保存的密码/凭据。",
            required_kinds=["browser_history"],
        )
    top = creds[:30]
    lines = []
    for c in top:
        parts = []
        if c.get("url"):
            parts.append(c["url"])
        if c.get("username"):
            parts.append(f"用户: {c['username']}")
        if c.get("password"):
            parts.append(f"密码: {c['password']}")
        lines.append(" | ".join(parts))
    summary = f"浏览器保存凭据 (共{len(creds)}条, 显示前{len(top)}条):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(creds) >= 2 else "medium",
        "evidence": top,
        "notes": ["来源: Chrome/Edge Login Data 或浏览器导出。"],
    }


# --- file_by_md5 handler ---
def _answer_file_by_md5(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """通过 MD5/SHA 哈希反查文件名。"""
    q_lower = question.lower()
    # 从问题中提取哈希值
    hash_pattern = re.compile(r'\b([0-9a-f]{32})\b|\b([0-9a-f]{40})\b|\b([0-9a-f]{64})\b', re.IGNORECASE)
    matches = hash_pattern.findall(q_lower)
    target_hashes = set()
    for groups in matches:
        for g in groups:
            if g:
                target_hashes.add(g.lower())

    results: list[dict[str, Any]] = []
    for kind in ("hash_inventory", "file_listing"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            matched_hash = None
            for h in target_hashes:
                if h in lower:
                    matched_hash = h
                    break
            if matched_hash is None and not target_hashes:
                if "md5" in lower or "sha" in lower or "hash" in lower:
                    matched_hash = "generic"
            if matched_hash is None:
                continue
            entry: dict[str, Any] = {"matched_hash": matched_hash}
            for key, value in record.items():
                if key.startswith("_"):
                    continue
                nk = _normalize_key(key)
                val_str = str(value).strip() if value is not None else ""
                if not val_str:
                    continue
                if "filename" in nk or "name" in nk or "文件名" in nk or "path" in nk or "路径" in nk:
                    entry["filename"] = val_str
                elif "md5" in nk:
                    entry["md5"] = val_str
                elif "sha1" in nk:
                    entry["sha1"] = val_str
                elif "sha256" in nk:
                    entry["sha256"] = val_str
                elif "size" in nk or "大小" in nk:
                    entry["size"] = val_str
            entry["preview"] = text[:200]
            results.append(entry)

    if not results:
        return _missing_answer(
            "未能根据哈希值找到匹配的文件。",
            required_kinds=["hash_inventory", "file_listing"],
        )
    top = results[:20]
    lines = []
    for r in top:
        parts = []
        if r.get("filename"):
            parts.append(r["filename"])
        if r.get("md5"):
            parts.append(f"MD5: {r['md5']}")
        if r.get("sha1"):
            parts.append(f"SHA1: {r['sha1']}")
        lines.append(" | ".join(parts) if parts else r.get("preview", "")[:100])
    summary = f"哈希匹配结果 (共{len(results)}条):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if target_hashes else "medium",
        "evidence": top,
        "notes": [f"搜索的哈希值: {', '.join(target_hashes) if target_hashes else '(通用搜索)'}"],
    }


# --- recent_audio_filename handler ---
AUDIO_EXTENSIONS: tuple[str, ...] = (
    ".mp3", ".wav", ".wma", ".aac", ".flac", ".ogg", ".m4a", ".amr", ".opus", ".ape",
)


def _answer_recent_audio_filename(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从最近访问记录中查找音频文件。"""
    audio_records: list[dict[str, Any]] = []
    for kind in ("recent_items", "jump_lists", "registry_ntuser", "file_listing"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            if not any(ext in lower for ext in AUDIO_EXTENSIONS):
                continue
            filename = None
            timestamp = None
            for key, value in record.items():
                if key.startswith("_"):
                    continue
                nk = _normalize_key(key)
                val_str = str(value).strip() if value is not None else ""
                if not val_str:
                    continue
                if nk in ("filename", "name", "target", "targetpath", "文件名", "路径"):
                    if any(ext in val_str.lower() for ext in AUDIO_EXTENSIONS):
                        filename = val_str
                elif nk in ("timestamp", "time", "modified", "accessed", "created", "时间"):
                    timestamp = val_str
            if filename is None:
                # 尝试从全文中提取
                for ext in AUDIO_EXTENSIONS:
                    idx = lower.find(ext)
                    if idx != -1:
                        start = max(0, lower.rfind(" ", max(0, idx - 60), idx) + 1)
                        candidate = text[start:idx + len(ext)].strip().split("\\")[-1].split("/")[-1]
                        if candidate:
                            filename = candidate
                            break
            if filename:
                entry: dict[str, Any] = {"filename": filename, "source_kind": kind}
                if timestamp:
                    entry["timestamp"] = timestamp
                entry["preview"] = text[:200]
                audio_records.append(entry)

    if not audio_records:
        return _missing_answer(
            "未找到最近访问的音频文件记录。",
            required_kinds=["recent_items", "file_listing"],
        )
    # 去重
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for r in audio_records:
        fn = r["filename"].lower()
        if fn not in seen:
            seen.add(fn)
            unique.append(r)
    top = unique[:20]
    lines = [f"{r['filename']}" + (f" ({r['timestamp']})" if r.get("timestamp") else "") for r in top]
    summary = f"最近访问的音频文件 (共{len(unique)}个):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(unique) >= 2 else "medium",
        "evidence": top,
        "notes": [f"音频扩展名: {', '.join(AUDIO_EXTENSIONS)}"],
    }


# --- backup_phone_number handler ---
PHONE_RE = re.compile(r'(?:1[3-9]\d{9})')
PHONE_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "便签", "备忘", "sticky", "note", "备用", "号码", "电话", "手机", "联系",
)


def _answer_backup_phone_number(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从便签/备忘录等提取电话号码。"""
    phone_entries: list[dict[str, Any]] = []
    for kind in ("sticky_notes", "user_docs", "file_listing", "recent_items"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            phones = PHONE_RE.findall(text)
            if not phones:
                continue
            lower = text.lower()
            # 优先匹配便签/备忘类上下文
            context_match = any(kw in lower for kw in PHONE_CONTEXT_KEYWORDS)
            for phone in phones:
                phone_entries.append({
                    "phone": phone,
                    "context_match": context_match,
                    "source_kind": kind,
                    "preview": text[:200],
                })
    if not phone_entries:
        return _missing_answer(
            "未能从便签/备忘录中提取电话号码。",
            required_kinds=["sticky_notes", "user_docs"],
        )
    # 优先显示便签上下文匹配的
    phone_entries.sort(key=lambda e: (not e["context_match"],))
    # 去重
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for e in phone_entries:
        if e["phone"] not in seen:
            seen.add(e["phone"])
            unique.append(e)
    top = unique[:20]
    lines = [f"{e['phone']}" + (" (便签/备忘)" if e["context_match"] else f" ({e['source_kind']})") for e in top]
    summary = f"提取到的电话号码 (共{len(unique)}个):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if any(e["context_match"] for e in unique) else "medium",
        "evidence": top,
        "notes": ["来源: 便签、备忘录、文档文件。"],
    }


# --- mnemonic_first_word handler ---
# BIP-39 English wordlist first few for detection (full list too large)
_BIP39_COMMON = {"abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "abuse", "access", "accident", "account", "accuse",
    "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor",
    "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair",
    "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air",
    "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley",
    "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur",
    "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer",
    "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple",
    "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed",
    "armor", "army", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma",
    "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit",
    "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid",
    "awake", "aware", "awesome", "awful", "awkward", "axis"}

MNEMONIC_KEYWORDS: tuple[str, ...] = (
    "助记词", "mnemonic", "seed phrase", "seed word", "钱包", "wallet",
    "recovery phrase", "恢复词", "12词", "24词",
)


def _answer_mnemonic_first_word(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从文件导出中查找助记词/种子短语。"""
    mnemonic_entries: list[dict[str, Any]] = []
    for kind in ("target_file_export", "user_docs", "sticky_notes", "file_listing"):
        records, files = _load_kind(export_dir, kind, cache=cache)
        for record in records:
            text = _record_text(record)
            lower = text.lower()
            if not any(kw in lower for kw in MNEMONIC_KEYWORDS):
                # 也尝试检测连续 BIP39 单词
                words = lower.split()
                bip_count = sum(1 for w in words if w in _BIP39_COMMON)
                if bip_count < 3:
                    continue

            # 尝试提取连续英文单词序列 (可能是助记词)
            word_sequences = re.findall(r'[a-z]{3,}(?:\s+[a-z]{3,}){11,23}', lower)
            entry: dict[str, Any] = {
                "preview": text[:300],
                "source_kind": kind,
            }
            if word_sequences:
                best = max(word_sequences, key=len)
                words_list = best.split()
                entry["mnemonic_candidate"] = best
                entry["word_count"] = len(words_list)
                entry["first_word"] = words_list[0]
            mnemonic_entries.append(entry)

    if not mnemonic_entries:
        return _missing_answer(
            "未能找到助记词/种子短语。",
            required_kinds=["target_file_export", "user_docs"],
        )
    top = mnemonic_entries[:10]
    lines = []
    for e in top:
        if e.get("mnemonic_candidate"):
            lines.append(f"助记词 ({e['word_count']}词): 首词={e['first_word']}, 全文={e['mnemonic_candidate'][:80]}...")
        else:
            lines.append(f"疑似助记词相关: {e['preview'][:100]}...")
    summary = f"助记词搜索结果 (共{len(mnemonic_entries)}条):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if any(e.get("mnemonic_candidate") for e in mnemonic_entries) else "low",
        "evidence": top,
        "notes": ["搜索范围: 文件导出、便签、文档。"],
    }


# --- audio_content_analysis handler ---
def _answer_audio_content_analysis(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """从音频转写文本中分析内容。"""
    records, files = _load_kind(export_dir, "audio_transcript", cache=cache)
    if not records:
        return _missing_answer(
            "未找到音频转写文本。请先导出音频并进行语音转写。",
            required_kinds=["audio_transcript"],
        )
    q_lower = question.lower()
    # 搜索用户感兴趣的关键词
    search_terms: list[str] = []
    for token in q_lower.split():
        if len(token) >= 2 and token not in ("音频", "录音", "内容", "分析", "转写", "语音"):
            search_terms.append(token)

    relevant: list[dict[str, Any]] = []
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        score = 0
        if search_terms:
            score = sum(1 for t in search_terms if t in lower)
            if score == 0:
                continue
        relevant.append({"text": text[:500], "score": score, "preview": text[:200]})

    if not relevant and records:
        # 返回全部转写内容摘要
        relevant = [{"text": _record_text(r)[:500], "score": 0, "preview": _record_text(r)[:200]} for r in records[:10]]

    relevant.sort(key=lambda e: e["score"], reverse=True)
    top = relevant[:10]
    lines = [e["text"][:200] for e in top]
    summary = f"音频转写内容 (共{len(relevant)}段):\n" + "\n---\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if search_terms and relevant else "medium",
        "evidence": top,
        "notes": ["来源: 音频转写文本导出。"],
    }


# --- SRUM 分析 handler ---
SRUM_KEYWORDS: tuple[str, ...] = (
    "srum", "srudb", "网络流量", "network usage", "bytes sent", "bytes received",
    "应用使用时长", "resource usage", "data usage", "流量统计",
)


def _answer_srum_analysis(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """分析 SRUM 数据: 应用网络流量、使用时长。"""
    records, files = _load_kind(export_dir, "srum", cache=cache)
    if not records:
        return _missing_answer(
            "未找到 SRUM 导出数据。请从 XWF 导出 SRUDB.dat 解析结果。",
            required_kinds=["srum"],
        )
    q_lower = question.lower()
    entries: list[dict[str, Any]] = []
    for record in records:
        text = _record_text(record)
        app_name = None
        bytes_sent = None
        bytes_recv = None
        duration = None
        timestamp = None
        for key, value in record.items():
            if key.startswith("_"):
                continue
            nk = _normalize_key(key)
            val_str = str(value).strip() if value is not None else ""
            if not val_str:
                continue
            if "appid" in nk or "application" in nk or "exeinfo" in nk or "程序" in nk or "app" in nk:
                app_name = val_str
            elif "bytessent" in nk or "bytes_sent" in nk or "上传" in nk:
                bytes_sent = val_str
            elif "bytesrecvd" in nk or "bytes_received" in nk or "bytesrecv" in nk or "下载" in nk:
                bytes_recv = val_str
            elif "foregroundcycletime" in nk or "duration" in nk or "使用时长" in nk:
                duration = val_str
            elif nk in ("timestamp", "time", "时间", "connectstarttime"):
                timestamp = val_str
        entry: dict[str, Any] = {}
        if app_name:
            entry["app_name"] = app_name
        if bytes_sent:
            entry["bytes_sent"] = bytes_sent
        if bytes_recv:
            entry["bytes_received"] = bytes_recv
        if duration:
            entry["duration"] = duration
        if timestamp:
            entry["timestamp"] = timestamp
        if entry:
            entry["preview"] = text[:200]
            entries.append(entry)

    if not entries:
        return _missing_answer(
            "SRUM 数据中未提取到有效记录。",
            required_kinds=["srum"],
        )
    # 如果问题指定了应用名，过滤
    focused = entries
    for token in ("chrome", "firefox", "edge", "wechat", "qq", "todesk", "explorer"):
        if token in q_lower:
            focused = [e for e in entries if token in e.get("app_name", "").lower()]
            break
    if not focused:
        focused = entries

    # 按流量排序
    def _parse_bytes(s: str | None) -> int:
        if not s:
            return 0
        try:
            return int(s.replace(",", ""))
        except ValueError:
            return 0

    focused.sort(key=lambda e: _parse_bytes(e.get("bytes_sent")) + _parse_bytes(e.get("bytes_received")), reverse=True)
    top = focused[:20]
    lines = []
    for e in top:
        parts = [e.get("app_name", "unknown")]
        if e.get("bytes_sent"):
            parts.append(f"发送: {e['bytes_sent']}")
        if e.get("bytes_received"):
            parts.append(f"接收: {e['bytes_received']}")
        if e.get("duration"):
            parts.append(f"时长: {e['duration']}")
        lines.append(" | ".join(parts))
    summary = f"SRUM 资源使用记录 (共{len(entries)}条, 显示前{len(top)}条):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(entries) >= 3 else "medium",
        "evidence": top,
        "notes": ["来源: SRUDB.dat (System Resource Usage Monitor)。"],
    }


# --- Prefetch 深度分析 handler ---
PREFETCH_KEYWORDS: tuple[str, ...] = (
    "prefetch", "pf", "预读取", "启动次数", "run count", "last run",
    "上次运行", "dll", "加载的dll",
)


def _answer_prefetch_deep(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """Prefetch 深度分析: 执行次数、运行时间、关联 DLL。"""
    records, files = _load_kind(export_dir, "prefetch", cache=cache)
    if not records:
        return _missing_answer(
            "未找到 Prefetch 导出数据。",
            required_kinds=["prefetch"],
        )
    q_lower = question.lower()
    entries: list[dict[str, Any]] = []
    for record in records:
        text = _record_text(record)
        exe_name = None
        run_count = None
        last_run = None
        dlls: list[str] = []
        for key, value in record.items():
            if key.startswith("_"):
                continue
            nk = _normalize_key(key)
            val_str = str(value).strip() if value is not None else ""
            if not val_str:
                continue
            if nk in ("executable", "filename", "name", "程序名", "exename"):
                exe_name = val_str
            elif "runcount" in nk or "run_count" in nk or "执行次数" in nk or "启动次数" in nk:
                try:
                    run_count = int(val_str)
                except ValueError:
                    pass
            elif "lastrun" in nk or "last_run" in nk or "最后运行" in nk or "上次运行" in nk:
                last_run = val_str
            elif "dll" in nk or "loaded" in nk or "reference" in nk:
                dlls.append(val_str)
        if exe_name:
            entry: dict[str, Any] = {"exe_name": exe_name}
            if run_count is not None:
                entry["run_count"] = run_count
            if last_run:
                entry["last_run"] = last_run
            if dlls:
                entry["dlls"] = dlls[:10]
            entry["preview"] = text[:200]
            entries.append(entry)

    if not entries:
        return _missing_answer(
            "Prefetch 数据中未提取到有效程序执行记录。",
            required_kinds=["prefetch"],
        )
    # 按问题过滤
    focused = entries
    for token in q_lower.split():
        if len(token) >= 3 and token not in ("prefetch", "分析", "查看", "运行", "执行"):
            filtered = [e for e in entries if token in e.get("exe_name", "").lower()]
            if filtered:
                focused = filtered
                break
    if not focused:
        focused = entries

    focused.sort(key=lambda e: e.get("run_count", 0), reverse=True)
    top = focused[:20]
    lines = []
    for e in top:
        parts = [e["exe_name"]]
        if "run_count" in e:
            parts.append(f"执行{e['run_count']}次")
        if e.get("last_run"):
            parts.append(f"最后运行: {e['last_run']}")
        if e.get("dlls"):
            parts.append(f"DLL: {len(e['dlls'])}个")
        lines.append(" | ".join(parts))
    summary = f"Prefetch 记录 (共{len(entries)}条, 显示前{len(top)}条):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(entries) >= 3 else "medium",
        "evidence": top,
        "notes": ["来源: C:\\Windows\\Prefetch\\*.pf"],
    }


# --- ShellBags 分析 handler ---
SHELLBAGS_KEYWORDS: tuple[str, ...] = (
    "shellbags", "shell bags", "bagmru", "bags", "文件夹历史", "folder history",
    "浏览历史", "usrclass", "已删除文件夹",
)


def _answer_shellbags(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """ShellBags 分析: 文件夹浏览历史。"""
    records, files = _load_kind(export_dir, "registry_ntuser", cache=cache)
    entries: list[dict[str, Any]] = []
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        if not any(kw in lower for kw in ("shellbags", "shell\\bag", "bagmru", "shell\\bags")):
            continue
        folder_path = None
        timestamp = None
        for key, value in record.items():
            if key.startswith("_"):
                continue
            nk = _normalize_key(key)
            val_str = str(value).strip() if value is not None else ""
            if not val_str:
                continue
            if nk in ("path", "folderpath", "folder", "路径", "value", "valuename"):
                folder_path = val_str
            elif nk in ("timestamp", "time", "modified", "lastwrite", "时间"):
                timestamp = val_str
        if folder_path:
            entry: dict[str, Any] = {"folder_path": folder_path}
            if timestamp:
                entry["timestamp"] = timestamp
            entry["preview"] = text[:200]
            entries.append(entry)

    if not entries:
        return _missing_answer(
            "未能从注册表导出中提取 ShellBags 记录。",
            required_kinds=["registry_ntuser"],
        )
    # 按问题过滤
    q_lower = question.lower()
    focused = entries
    for token in q_lower.split():
        if len(token) >= 3 and token not in ("shellbags", "分析", "查看", "历史", "文件夹"):
            filtered = [e for e in entries if token in e.get("folder_path", "").lower()]
            if filtered:
                focused = filtered
                break

    top = focused[:30]
    lines = [f"{e['folder_path']}" + (f" ({e['timestamp']})" if e.get("timestamp") else "") for e in top]
    summary = f"ShellBags 文件夹浏览记录 (共{len(entries)}条, 显示前{len(top)}条):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high" if len(entries) >= 3 else "medium",
        "evidence": top,
        "notes": [
            "来源: NTUSER.DAT/UsrClass.dat 中的 Shell\\BagMRU 和 Shell\\Bags。",
            "ShellBags 保留已删除文件夹和已移除USB设备的浏览记录。",
        ],
    }


# --- 文件签名/magic bytes 分析 handler ---
FILE_SIG_KEYWORDS: tuple[str, ...] = (
    "magic bytes", "文件签名", "file signature", "文件头", "file header",
    "伪装", "disguised", "隐藏文件", "mismatch", "扩展名不匹配", "type mismatch",
)


def _answer_file_signature(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """文件签名分析: 检测扩展名与实际类型不匹配。"""
    records, files = _load_kind(export_dir, "file_listing", cache=cache)
    if not records:
        return _missing_answer(
            "未找到 file_listing 导出数据。",
            required_kinds=["file_listing"],
        )
    mismatches: list[dict[str, Any]] = []
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        # 检查是否有 type/category/signature 不匹配的标记
        is_mismatch = False
        filename = None
        ext = None
        real_type = None
        for key, value in record.items():
            if key.startswith("_"):
                continue
            nk = _normalize_key(key)
            val_str = str(value).strip() if value is not None else ""
            if not val_str:
                continue
            if nk in ("filename", "name", "文件名", "path", "路径"):
                filename = val_str
                dot_idx = val_str.rfind(".")
                if dot_idx != -1:
                    ext = val_str[dot_idx:].lower()
            elif "type" in nk or "category" in nk or "signature" in nk or "类型" in nk:
                real_type = val_str
            elif "mismatch" in nk or "不匹配" in nk or "disguised" in nk or "伪装" in nk:
                is_mismatch = True

        if is_mismatch and filename:
            mismatches.append({
                "filename": filename,
                "extension": ext,
                "real_type": real_type,
                "preview": text[:200],
            })
        elif filename and ext and real_type:
            # 简单启发式: 如果 type 字段不包含扩展名关联类型
            ext_lower = ext.lstrip(".")
            type_lower = real_type.lower()
            if ext_lower not in type_lower and type_lower not in ("unknown", "", "data"):
                mismatches.append({
                    "filename": filename,
                    "extension": ext,
                    "real_type": real_type,
                    "preview": text[:200],
                })

    if not mismatches:
        return {
            "status": "answered",
            "answer": "未检测到文件扩展名与实际类型不匹配的文件。",
            "confidence": "medium",
            "evidence": [],
            "notes": ["检查范围: file_listing 导出中具有 type/signature 字段的记录。"],
        }

    top = mismatches[:20]
    lines = []
    for m in top:
        parts = [m["filename"]]
        if m.get("extension"):
            parts.append(f"扩展名: {m['extension']}")
        if m.get("real_type"):
            parts.append(f"实际类型: {m['real_type']}")
        lines.append(" | ".join(parts))
    summary = f"文件签名不匹配 (共{len(mismatches)}个):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high",
        "evidence": top,
        "notes": ["检测方法: 对比文件扩展名与 type/signature 字段。"],
    }


# --- 流量包定位 handler ---
PCAP_EXTENSIONS: tuple[str, ...] = (".pcap", ".pcapng", ".cap", ".snoop", ".netmon")


def _answer_pcap_locator(
    question: str,
    export_dir: Path,
    *,
    cache: dict[str, tuple[list[dict[str, Any]], list[str]]],
) -> dict[str, Any]:
    """在 file_listing 中定位流量包文件。"""
    records, files = _load_kind(export_dir, "file_listing", cache=cache)
    pcap_files: list[dict[str, Any]] = []
    for record in records:
        text = _record_text(record)
        lower = text.lower()
        if not any(ext in lower for ext in PCAP_EXTENSIONS):
            continue
        filename = None
        filepath = None
        size = None
        timestamp = None
        for key, value in record.items():
            if key.startswith("_"):
                continue
            nk = _normalize_key(key)
            val_str = str(value).strip() if value is not None else ""
            if not val_str:
                continue
            if nk in ("filename", "name", "文件名"):
                if any(ext in val_str.lower() for ext in PCAP_EXTENSIONS):
                    filename = val_str
            elif nk in ("path", "fullpath", "路径", "filepath"):
                filepath = val_str
            elif nk in ("size", "大小", "filesize"):
                size = val_str
            elif nk in ("timestamp", "time", "modified", "created", "时间"):
                timestamp = val_str
        if filename:
            entry: dict[str, Any] = {"filename": filename}
            if filepath:
                entry["path"] = filepath
            if size:
                entry["size"] = size
            if timestamp:
                entry["timestamp"] = timestamp
            entry["preview"] = text[:200]
            pcap_files.append(entry)

    if not pcap_files:
        return _missing_answer(
            "未在 file_listing 中找到流量包文件 (.pcap/.pcapng/.cap)。",
            required_kinds=["file_listing"],
        )
    top = pcap_files[:20]
    lines = []
    for p in top:
        parts = [p["filename"]]
        if p.get("path"):
            parts.append(f"路径: {p['path']}")
        if p.get("size"):
            parts.append(f"大小: {p['size']}")
        if p.get("timestamp"):
            parts.append(f"时间: {p['timestamp']}")
        lines.append(" | ".join(parts))
    summary = f"流量包文件 (共{len(pcap_files)}个):\n" + "\n".join(lines)
    return {
        "status": "answered",
        "answer": summary,
        "confidence": "high",
        "evidence": top,
        "notes": [f"搜索扩展名: {', '.join(PCAP_EXTENSIONS)}"],
    }


# ---------------------------------------------------------------------------
# Task 14: BitLocker / VeraCrypt 加密卷检测
# ---------------------------------------------------------------------------
BITLOCKER_KEYWORDS = re.compile(
    r"bitlocker|veracrypt|truecrypt|fve|full.volume.encryption|"
    r"bde|加密卷|encrypted.volume|recovery.key|恢复密钥|加密磁盘|加密分区",
    re.IGNORECASE,
)
_BEK_EXTENSIONS = {".bek", ".bde-svc"}
_RECOVERY_KEY_PATTERNS = re.compile(
    r"BitLocker\s*Recovery\s*Key|Recovery\s*Password|恢复密钥|FveReportedKey",
    re.IGNORECASE,
)
_VERACRYPT_INDICATORS = re.compile(
    r"VeraCrypt|TrueCrypt|vera.crypt|true.crypt", re.IGNORECASE,
)


def _answer_bitlocker_veracrypt(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """检测 BitLocker / VeraCrypt 加密卷和恢复密钥。"""
    findings: list[str] = []
    evidence: list[dict] = []

    # 1) 从 encrypted_files 导出查找
    enc_records = _get_records(export_dir, "encrypted_files", cache=cache)
    if enc_records:
        bl_items = []
        vc_items = []
        other_items = []
        for r in enc_records:
            txt = _record_text(r)
            if re.search(r"bitlocker|bde|fve", txt, re.IGNORECASE):
                bl_items.append(r)
            elif _VERACRYPT_INDICATORS.search(txt):
                vc_items.append(r)
            else:
                other_items.append(r)
        if bl_items:
            findings.append(f"BitLocker 相关加密文件: {len(bl_items)} 个")
            evidence.extend(bl_items[:10])
        if vc_items:
            findings.append(f"VeraCrypt/TrueCrypt 加密文件: {len(vc_items)} 个")
            evidence.extend(vc_items[:10])
        if other_items:
            findings.append(f"其他加密候选文件: {len(other_items)} 个")
            evidence.extend(other_items[:5])

    # 2) 从 file_listing 搜索恢复密钥文件
    fl_records = _get_records(export_dir, "file_listing", cache=cache)
    if fl_records:
        recovery_files = []
        for r in fl_records:
            fn = (r.get("filename") or r.get("name") or "").lower()
            ext = fn[fn.rfind("."):] if "." in fn else ""
            txt = _record_text(r)
            if ext in _BEK_EXTENSIONS or _RECOVERY_KEY_PATTERNS.search(txt):
                recovery_files.append(r)
        if recovery_files:
            findings.append(f"BitLocker 恢复密钥文件: {len(recovery_files)} 个")
            evidence.extend(recovery_files[:10])

    # 3) 从 registry_system 搜索 FVE 键
    reg_records = _get_records(export_dir, "registry_system", cache=cache)
    if reg_records:
        fve_items = [r for r in reg_records if re.search(r"FVE|BitLocker|FullVolumeEncryption", _record_text(r), re.IGNORECASE)]
        if fve_items:
            findings.append(f"注册表 FVE/BitLocker 键: {len(fve_items)} 条")
            evidence.extend(fve_items[:10])

    if not findings:
        return _missing_answer(
            "未检测到 BitLocker/VeraCrypt 加密卷或恢复密钥。",
            required_kinds=["encrypted_files", "file_listing", "registry_system"],
        )

    return {
        "status": "answered",
        "answer": "加密卷检测结果:\n" + "\n".join(f"• {f}" for f in findings),
        "confidence": "high",
        "evidence": evidence[:30],
        "notes": ["检测范围: BitLocker, VeraCrypt, TrueCrypt, BDE 恢复密钥"],
    }


# ---------------------------------------------------------------------------
# Task 15: 计划任务分析 (Task Scheduler)
# ---------------------------------------------------------------------------
SCHTASK_KEYWORDS = re.compile(
    r"计划任务|scheduled.task|schtasks|task.scheduler|任务计划|定时任务|TaskCache",
    re.IGNORECASE,
)
_TASK_SUSPICIOUS_PATHS = re.compile(
    r"\\Temp\\|\\tmp\\|\\AppData\\Local\\Temp|"
    r"powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin",
    re.IGNORECASE,
)


def _answer_scheduled_task(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """分析计划任务 — 关注可执行路径、运行账户、触发器。"""
    records = _get_records(export_dir, "scheduled_tasks", cache=cache)
    # 也尝试从 event_logs_security 获取 4698/4699 事件
    sec_records = _get_records(export_dir, "event_logs_security", cache=cache)

    tasks: list[dict] = []
    suspicious: list[dict] = []

    if records:
        for r in records:
            tasks.append(r)
            txt = _record_text(r)
            if _TASK_SUSPICIOUS_PATHS.search(txt):
                suspicious.append(r)

    # 从安全日志搜索计划任务创建/删除事件
    task_events: list[dict] = []
    if sec_records:
        for r in sec_records:
            eid = str(r.get("event_id") or r.get("EventID") or r.get("eventid") or "")
            if eid in ("4698", "4699", "4700", "4701", "4702"):
                task_events.append(r)

    if not tasks and not task_events:
        return _missing_answer(
            "未找到计划任务导出或相关安全事件。",
            required_kinds=["scheduled_tasks", "event_logs_security"],
        )

    lines = []
    if tasks:
        lines.append(f"计划任务总数: {len(tasks)}")
    if suspicious:
        lines.append(f"可疑计划任务 (含临时路径/脚本): {len(suspicious)}")
        for s in suspicious[:10]:
            name = s.get("name") or s.get("TaskName") or s.get("filename") or "unknown"
            path = s.get("command") or s.get("Actions") or s.get("path") or ""
            lines.append(f"  ⚠ {name}: {path}")
    if task_events:
        lines.append(f"安全日志中计划任务事件: {len(task_events)} 条")
        for e in task_events[:5]:
            eid = e.get("event_id") or e.get("EventID") or ""
            desc = {
                "4698": "创建", "4699": "删除", "4700": "启用",
                "4701": "禁用", "4702": "修改",
            }.get(str(eid), str(eid))
            lines.append(f"  EventID {eid} ({desc}): {_record_text(e)[:120]}")

    evidence = (suspicious or tasks)[:15] + task_events[:10]
    return {
        "status": "answered",
        "answer": "\n".join(lines),
        "confidence": "high" if tasks else "medium",
        "evidence": evidence,
        "notes": ["关注可疑路径: Temp目录, PowerShell, cmd.exe, certutil 等"],
    }


# ---------------------------------------------------------------------------
# Task 16: 服务/自启动项分析
# ---------------------------------------------------------------------------
AUTOSTART_KEYWORDS = re.compile(
    r"自启动|autostart|autorun|run.key|runonce|services|服务|启动项|开机启动|startup|imagepath",
    re.IGNORECASE,
)
_RUN_KEY_PATTERN = re.compile(
    r"\\CurrentVersion\\Run(?:Once)?\\|\\Run\\|\\RunOnce\\", re.IGNORECASE,
)
_SERVICE_KEY_PATTERN = re.compile(
    r"ControlSet\d+\\Services\\|CurrentControlSet\\Services\\", re.IGNORECASE,
)
_SUSPICIOUS_SERVICE_PATH = re.compile(
    r"\\Temp\\|\\tmp\\|\\AppData\\|\\Users\\.*\\Downloads\\|"
    r"powershell|cmd\.exe\s|svchost.*-k\s+netsvc",
    re.IGNORECASE,
)


def _answer_autostart_service(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """分析 Run/RunOnce 自启动项 + Services 注册表键。"""
    findings: list[str] = []
    evidence: list[dict] = []

    # 1) NTUSER — Run / RunOnce
    ntuser_records = _get_records(export_dir, "registry_ntuser", cache=cache)
    run_items: list[dict] = []
    if ntuser_records:
        for r in ntuser_records:
            txt = _record_text(r)
            if _RUN_KEY_PATTERN.search(txt):
                run_items.append(r)
    if run_items:
        findings.append(f"用户级自启动项 (NTUSER Run/RunOnce): {len(run_items)} 条")
        evidence.extend(run_items[:10])

    # 2) SOFTWARE — Run / RunOnce
    sw_records = _get_records(export_dir, "installed_software", cache=cache)
    sw_run: list[dict] = []
    if sw_records:
        for r in sw_records:
            txt = _record_text(r)
            if _RUN_KEY_PATTERN.search(txt):
                sw_run.append(r)
    if sw_run:
        findings.append(f"系统级自启动项 (SOFTWARE Run/RunOnce): {len(sw_run)} 条")
        evidence.extend(sw_run[:10])

    # 3) SYSTEM — Services
    sys_records = _get_records(export_dir, "registry_system", cache=cache)
    services: list[dict] = []
    suspicious_svc: list[dict] = []
    if sys_records:
        for r in sys_records:
            txt = _record_text(r)
            if _SERVICE_KEY_PATTERN.search(txt):
                services.append(r)
                if _SUSPICIOUS_SERVICE_PATH.search(txt):
                    suspicious_svc.append(r)
    if services:
        findings.append(f"注册表 Services 键: {len(services)} 条")
        if suspicious_svc:
            findings.append(f"可疑服务路径 (临时目录/脚本): {len(suspicious_svc)} 条")
            for s in suspicious_svc[:8]:
                findings.append(f"  ⚠ {_record_text(s)[:150]}")
        evidence.extend(suspicious_svc[:10] or services[:10])

    if not findings:
        return _missing_answer(
            "未找到 Run/RunOnce 或 Services 注册表记录。",
            required_kinds=["registry_system", "registry_ntuser", "installed_software"],
        )

    return {
        "status": "answered",
        "answer": "自启动/服务分析:\n" + "\n".join(findings),
        "confidence": "high",
        "evidence": evidence[:30],
        "notes": [
            "Start 类型: 0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled",
            "重点关注非标准路径、Temp目录、脚本类可执行文件",
        ],
    }


# ---------------------------------------------------------------------------
# Task 17: Windows Defender / 杀毒软件日志
# ---------------------------------------------------------------------------
DEFENDER_KEYWORDS = re.compile(
    r"defender|杀毒|antivirus|malware|quarantine|隔离|威胁|threat|病毒|mplog|实时保护",
    re.IGNORECASE,
)
_DEFENDER_EVENT_IDS = {
    "1006": "恶意软件扫描完成",
    "1007": "恶意软件操作已执行",
    "1116": "检测到威胁",
    "1117": "已对威胁采取操作",
    "1118": "对威胁的操作失败",
    "1119": "对威胁的操作严重失败",
    "5001": "实时保护已禁用",
    "5004": "实时保护配置已更改",
    "5007": "配置已更改",
    "5010": "反间谍软件扫描已禁用",
    "5012": "病毒扫描已禁用",
}


def _answer_defender_log(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """分析 Windows Defender 事件日志 — 检测/隔离/配置变更。"""
    findings: list[str] = []
    evidence: list[dict] = []

    # 1) 专用 defender 日志
    def_records = _get_records(export_dir, "event_logs_defender", cache=cache)
    # 2) 也搜索 application 日志中的 Defender 事件
    app_records = _get_records(export_dir, "event_logs_application", cache=cache)

    all_defender: list[dict] = []
    threat_events: list[dict] = []
    config_events: list[dict] = []

    for pool in (def_records or [], app_records or []):
        for r in pool:
            txt = _record_text(r)
            eid = str(r.get("event_id") or r.get("EventID") or r.get("eventid") or "")
            source = str(r.get("source") or r.get("Source") or r.get("provider") or "")
            is_defender = (
                "defender" in source.lower()
                or "antimalware" in source.lower()
                or eid in _DEFENDER_EVENT_IDS
                or re.search(r"Windows.Defender|Antimalware", txt, re.IGNORECASE)
            )
            if is_defender:
                all_defender.append(r)
                if eid in ("1116", "1117", "1118", "1119"):
                    threat_events.append(r)
                elif eid in ("5001", "5004", "5007", "5010", "5012"):
                    config_events.append(r)

    if not all_defender:
        return _missing_answer(
            "未找到 Windows Defender 事件日志。",
            required_kinds=["event_logs_defender", "event_logs_application"],
        )

    findings.append(f"Defender 事件总数: {len(all_defender)}")
    if threat_events:
        findings.append(f"威胁检测/处置事件: {len(threat_events)} 条")
        for t in threat_events[:8]:
            eid = str(t.get("event_id") or t.get("EventID") or "")
            label = _DEFENDER_EVENT_IDS.get(eid, eid)
            findings.append(f"  ⚠ EventID {eid} ({label}): {_record_text(t)[:150]}")
        evidence.extend(threat_events[:15])
    if config_events:
        findings.append(f"配置/保护状态变更事件: {len(config_events)} 条")
        for c in config_events[:5]:
            eid = str(c.get("event_id") or c.get("EventID") or "")
            label = _DEFENDER_EVENT_IDS.get(eid, eid)
            findings.append(f"  ℹ EventID {eid} ({label})")
        evidence.extend(config_events[:10])

    return {
        "status": "answered",
        "answer": "Windows Defender 分析:\n" + "\n".join(findings),
        "confidence": "high",
        "evidence": evidence[:30],
        "notes": ["关键事件: 1116(检测), 1117(操作), 5001(实时保护禁用)"],
    }


# ---------------------------------------------------------------------------
# Task 18: 剪贴板历史 (ActivitiesCache ActivityType=16)
# ---------------------------------------------------------------------------
CLIPBOARD_KEYWORDS = re.compile(
    r"剪贴板|clipboard|copy.paste|复制粘贴|cloud.clipboard|activitytype.16",
    re.IGNORECASE,
)


def _answer_clipboard_history(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """从 ActivitiesCache 提取剪贴板历史 (ActivityType=16)。"""
    records = _get_records(export_dir, "windows_timeline", cache=cache)
    if not records:
        return _missing_answer(
            "未找到 Windows Timeline (ActivitiesCache.db) 导出。",
            required_kinds=["windows_timeline"],
        )

    clipboard_items: list[dict] = []
    for r in records:
        atype = str(r.get("ActivityType") or r.get("activitytype") or r.get("activity_type") or "")
        if atype == "16":
            clipboard_items.append(r)

    # 如果按 ActivityType 没找到，尝试按内容模式搜索
    if not clipboard_items:
        for r in records:
            txt = _record_text(r)
            if re.search(r"clipboard|ClipboardPayload|剪贴板", txt, re.IGNORECASE):
                clipboard_items.append(r)

    if not clipboard_items:
        return {
            "status": "answered",
            "answer": "ActivitiesCache 中未发现剪贴板条目 (ActivityType=16)。可能剪贴板历史未启用或已清除。",
            "confidence": "medium",
            "evidence": [],
            "notes": ["Windows 10 1809+ 支持剪贴板历史，需在设置中启用。"],
        }

    lines = [f"剪贴板历史条目: {len(clipboard_items)} 条"]
    for idx, item in enumerate(clipboard_items[:20]):
        payload = item.get("ClipboardPayload") or item.get("clipboardpayload") or item.get("Payload") or ""
        app = item.get("AppId") or item.get("appid") or item.get("app") or ""
        ts = item.get("StartTime") or item.get("starttime") or item.get("timestamp") or ""
        content_preview = str(payload)[:100] if payload else _record_text(item)[:100]
        line = f"  [{idx+1}] {ts} | {content_preview}"
        if app:
            line += f" (来源: {app})"
        lines.append(line)

    return {
        "status": "answered",
        "answer": "\n".join(lines),
        "confidence": "high",
        "evidence": clipboard_items[:20],
        "notes": ["ActivityType=16 对应剪贴板条目", "ClipboardPayload 可能含 JSON 编码内容"],
    }


# ---------------------------------------------------------------------------
# Task 19: 打印记录分析 (PrintService 事件日志)
# ---------------------------------------------------------------------------
PRINT_KEYWORDS = re.compile(
    r"打印|print|printer|打印机|print.job|打印记录|printservice|print.spooler|spool",
    re.IGNORECASE,
)
_PRINT_EVENT_IDS = {
    "307": "打印任务完成",
    "805": "打印任务创建",
    "842": "打印任务失败",
    "801": "打印任务已发送到打印机",
    "800": "打印任务已添加到队列",
}


def _answer_print_history(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """分析 PrintService 事件日志 — 提取打印记录。"""
    findings: list[str] = []
    evidence: list[dict] = []

    # 1) PrintService 专用日志
    ps_records = _get_records(export_dir, "event_logs_printservice", cache=cache)
    # 2) 也搜索 System 日志中的 Print Spooler
    sys_records = _get_records(export_dir, "event_logs_system", cache=cache)

    print_events: list[dict] = []
    spooler_events: list[dict] = []

    if ps_records:
        for r in ps_records:
            eid = str(r.get("event_id") or r.get("EventID") or r.get("eventid") or "")
            if eid in _PRINT_EVENT_IDS:
                print_events.append(r)
            else:
                print_events.append(r)  # PrintService 日志所有事件都相关

    if sys_records:
        for r in sys_records:
            source = str(r.get("source") or r.get("Source") or r.get("provider") or "").lower()
            if "spooler" in source or "print" in source:
                spooler_events.append(r)

    if not print_events and not spooler_events:
        return _missing_answer(
            "未找到 PrintService 事件日志或打印相关记录。",
            required_kinds=["event_logs_printservice", "event_logs_system"],
        )

    if print_events:
        findings.append(f"PrintService 打印事件: {len(print_events)} 条")
        job_completed = [r for r in print_events
                         if str(r.get("event_id") or r.get("EventID") or "") == "307"]
        if job_completed:
            findings.append(f"已完成打印任务 (EventID 307): {len(job_completed)} 条")
            for j in job_completed[:10]:
                txt = _record_text(j)[:200]
                findings.append(f"  📄 {txt}")
            evidence.extend(job_completed[:15])
        else:
            evidence.extend(print_events[:15])

    if spooler_events:
        findings.append(f"Print Spooler 系统事件: {len(spooler_events)} 条")
        evidence.extend(spooler_events[:10])

    return {
        "status": "answered",
        "answer": "打印记录分析:\n" + "\n".join(findings),
        "confidence": "high",
        "evidence": evidence[:30],
        "notes": ["EventID 307=任务完成, 805=任务创建; 含文档名、打印机、页数"],
    }


# ---------------------------------------------------------------------------
# Task 20: USN Journal ($UsnJrnl:$J) 变更日志分析
# ---------------------------------------------------------------------------
USN_KEYWORDS = re.compile(
    r"usn|usnjrnl|\$usnjrnl|变更日志|change.journal|文件变更|file.changes|ntfs.journal",
    re.IGNORECASE,
)
_USN_REASON_FLAGS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000400: "EA_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD_NAME",
    0x00002000: "RENAME_NEW_NAME",
    0x00004000: "INDEXABLE_CHANGE",
    0x00008000: "BASIC_INFO_CHANGE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x80000000: "CLOSE",
}


def _answer_usn_journal(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """分析 USN Journal 变更日志 — 文件创建/删除/重命名追踪。"""
    records = _get_records(export_dir, "usn_journal", cache=cache)
    if not records:
        # 尝试从 file_listing 搜索 USN 相关导出
        fl = _get_records(export_dir, "file_listing", cache=cache)
        usn_files = []
        if fl:
            for r in fl:
                fn = (r.get("filename") or r.get("name") or "").lower()
                if "usnjrnl" in fn or "usn_journal" in fn or "$j" in fn:
                    usn_files.append(r)
        if usn_files:
            return {
                "status": "answered",
                "answer": f"发现 USN Journal 文件 ({len(usn_files)} 个), 但无解析后的导出。\n"
                          + "\n".join(r.get("filename", "") + " | " + (r.get("path") or "") for r in usn_files[:10]),
                "confidence": "medium",
                "evidence": usn_files[:10],
                "notes": ["需要使用 X-Ways 或 MFTECmd 解析 $UsnJrnl:$J 后再导出分析"],
            }
        return _missing_answer(
            "未找到 USN Journal 导出。", required_kinds=["usn_journal"],
        )

    # 分析 USN 记录
    q_lower = question.lower()
    creates = []
    deletes = []
    renames = []
    all_matched = []

    for r in records:
        reason_str = str(r.get("reason") or r.get("Reason") or r.get("change_reason") or "")
        filename = r.get("filename") or r.get("FileName") or r.get("name") or ""
        txt = _record_text(r)

        # 按问题关键词过滤
        if q_lower and any(kw in txt.lower() for kw in q_lower.split() if len(kw) > 2):
            all_matched.append(r)

        # 分类
        reason_upper = reason_str.upper()
        if "CREATE" in reason_upper or "0x100" in reason_str:
            creates.append(r)
        elif "DELETE" in reason_upper or "0x200" in reason_str:
            deletes.append(r)
        elif "RENAME" in reason_upper or "0x1000" in reason_str or "0x2000" in reason_str:
            renames.append(r)

    lines = [f"USN Journal 记录总数: {len(records)}"]
    if creates:
        lines.append(f"文件创建事件: {len(creates)}")
    if deletes:
        lines.append(f"文件删除事件: {len(deletes)}")
    if renames:
        lines.append(f"文件重命名事件: {len(renames)}")
    if all_matched:
        lines.append(f"与问题匹配的记录: {len(all_matched)}")
        for m in all_matched[:15]:
            fn = m.get("filename") or m.get("FileName") or ""
            ts = m.get("timestamp") or m.get("TimeStamp") or ""
            reason = m.get("reason") or m.get("Reason") or ""
            lines.append(f"  {ts} | {fn} | {reason}")

    evidence = (all_matched or deletes or creates or records)[:20]
    return {
        "status": "answered",
        "answer": "\n".join(lines),
        "confidence": "high" if all_matched else "medium",
        "evidence": evidence,
        "notes": [
            "Reason 标志: 0x100=创建, 0x200=删除, 0x1000/0x2000=重命名",
            "CLOSE (0x80000000) 表示操作已完成",
        ],
    }


# ---------------------------------------------------------------------------
# Task 21: MFT Entry 原始分析
# ---------------------------------------------------------------------------
MFT_KEYWORDS = re.compile(
    r"mft|\$mft|mft.entry|file.record|ntfs.mft|standard.information|"
    r"file.name.attribute|data.runs|timestomping|驻留|resident|mft时间",
    re.IGNORECASE,
)


def _answer_mft_entry(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """分析 MFT 导出 — 检测 timestomping, 驻留文件, ADS 等。"""
    records = _get_records(export_dir, "mft_export", cache=cache)
    if not records:
        # 从 file_listing 搜索可能的 MFT 相关记录
        fl = _get_records(export_dir, "file_listing", cache=cache)
        mft_files = []
        if fl:
            for r in fl:
                fn = (r.get("filename") or r.get("name") or "").lower()
                if "$mft" in fn or "mft_export" in fn or "mft-record" in fn:
                    mft_files.append(r)
        if mft_files:
            return {
                "status": "answered",
                "answer": f"发现 $MFT 文件 ({len(mft_files)} 个), 但无解析后的导出。\n"
                          + "\n".join(r.get("filename", "") + " | " + (r.get("path") or "") for r in mft_files[:5]),
                "confidence": "medium",
                "evidence": mft_files[:5],
                "notes": ["需要使用 MFTECmd/analyzeMFT 解析 $MFT 后再导出"],
            }
        return _missing_answer(
            "未找到 MFT 导出数据。", required_kinds=["mft_export"],
        )

    q_lower = question.lower()
    findings: list[str] = []
    evidence: list[dict] = []

    # 搜索 timestomping 痕迹 (SI vs FN 时间差异)
    timestomp_suspects: list[dict] = []
    ads_files: list[dict] = []
    resident_files: list[dict] = []
    matched: list[dict] = []

    for r in records:
        txt = _record_text(r)

        # 问题匹配
        if q_lower and any(kw in txt.lower() for kw in q_lower.split() if len(kw) > 2):
            matched.append(r)

        # timestomping 检测: SI_Created vs FN_Created 差异大
        si_created = r.get("SI_Created") or r.get("si_created") or r.get("StandardInfo_Created") or ""
        fn_created = r.get("FN_Created") or r.get("fn_created") or r.get("FileName_Created") or ""
        if si_created and fn_created and si_created != fn_created:
            timestomp_suspects.append(r)

        # ADS 检测
        if r.get("ads") or r.get("ADS") or r.get("alternate_data_stream"):
            ads_files.append(r)
        elif ":" in (r.get("filename") or "") and not (r.get("filename") or "").startswith("$"):
            ads_files.append(r)

        # 驻留文件
        is_resident = r.get("resident") or r.get("Resident") or r.get("is_resident")
        if str(is_resident).lower() in ("true", "1", "yes", "resident"):
            resident_files.append(r)

    findings.append(f"MFT 记录总数: {len(records)}")
    if timestomp_suspects:
        findings.append(f"⚠ 疑似 Timestomping (SI≠FN): {len(timestomp_suspects)} 个文件")
        for t in timestomp_suspects[:8]:
            fn = t.get("filename") or t.get("FileName") or ""
            si = t.get("SI_Created") or t.get("si_created") or ""
            fnc = t.get("FN_Created") or t.get("fn_created") or ""
            findings.append(f"  {fn}: SI={si} / FN={fnc}")
        evidence.extend(timestomp_suspects[:10])
    if ads_files:
        findings.append(f"含 ADS (替代数据流) 的文件: {len(ads_files)} 个")
        evidence.extend(ads_files[:10])
    if resident_files:
        findings.append(f"驻留文件 (数据存于 MFT): {len(resident_files)} 个")
    if matched:
        findings.append(f"与问题匹配的 MFT 记录: {len(matched)} 条")
        for m in matched[:10]:
            findings.append(f"  {_record_text(m)[:150]}")
        evidence.extend(matched[:10])

    return {
        "status": "answered",
        "answer": "MFT 分析:\n" + "\n".join(findings),
        "confidence": "high" if (timestomp_suspects or matched) else "medium",
        "evidence": evidence[:30],
        "notes": [
            "SI vs FN 时间差异大 = Timestomping (反取证)",
            "驻留文件 ≤700字节, 数据完整保存在 MFT Entry 内",
            "ADS 可隐藏恶意数据, 需检查所有 $DATA 属性",
        ],
    }


# ---------------------------------------------------------------------------
# Task 22: SQLite WAL 恢复
# ---------------------------------------------------------------------------
SQLITE_WAL_KEYWORDS = re.compile(
    r"sqlite.wal|wal.recovery|wal恢复|sqlite删除|deleted.records|"
    r"write.ahead.log|数据库恢复|freelist|wal.file",
    re.IGNORECASE,
)


def _answer_sqlite_wal(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """从 SQLite WAL 文件恢复/搜索已删除记录。"""
    records = _get_records(export_dir, "sqlite_wal", cache=cache)

    # 也尝试搜索 windows_timeline 和 browser_history
    timeline = _get_records(export_dir, "windows_timeline", cache=cache)
    browser = _get_records(export_dir, "browser_history", cache=cache)

    findings: list[str] = []
    evidence: list[dict] = []

    if records:
        findings.append(f"SQLite WAL 恢复记录: {len(records)} 条")
        q_lower = question.lower()
        matched = []
        for r in records:
            txt = _record_text(r)
            if q_lower and any(kw in txt.lower() for kw in q_lower.split() if len(kw) > 2):
                matched.append(r)
        if matched:
            findings.append(f"与问题匹配: {len(matched)} 条")
            for m in matched[:15]:
                findings.append(f"  {_record_text(m)[:150]}")
            evidence.extend(matched[:15])
        else:
            # 显示前几条
            for r in records[:10]:
                findings.append(f"  {_record_text(r)[:150]}")
            evidence.extend(records[:10])

    # 在 timeline/browser 中搜索已标记为 deleted/recovered 的记录
    for label, pool in [("Windows Timeline", timeline), ("Browser History", browser)]:
        if not pool:
            continue
        deleted = []
        for r in pool:
            status = str(r.get("status") or r.get("deleted") or r.get("recovered") or "")
            if status.lower() in ("deleted", "recovered", "1", "true"):
                deleted.append(r)
        if deleted:
            findings.append(f"{label} 中已恢复/已删除记录: {len(deleted)} 条")
            evidence.extend(deleted[:10])

    if not findings:
        return _missing_answer(
            "未找到 SQLite WAL 恢复数据。可尝试用 undark/sqlite-deleted-recovery 工具处理 WAL 文件。",
            required_kinds=["sqlite_wal", "windows_timeline", "browser_history"],
        )

    return {
        "status": "answered",
        "answer": "SQLite WAL 恢复分析:\n" + "\n".join(findings),
        "confidence": "high" if records else "medium",
        "evidence": evidence[:30],
        "notes": [
            "WAL 文件可能包含未 checkpoint 的旧页面数据",
            "FreeList 页面也可能保留已删除记录",
            "工具: undark, sqlite-deleted-recovery, belkasoft",
        ],
    }


# ---------------------------------------------------------------------------
# Task 23: 浏览器 Cookie / 下载记录
# ---------------------------------------------------------------------------
BROWSER_DL_KEYWORDS = re.compile(
    r"cookie|download|下载记录|下载历史|浏览器下载|browser.download|"
    r"chrome.download|edge.download|firefox.download|cookies",
    re.IGNORECASE,
)


def _answer_browser_download_cookie(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """分析浏览器 Cookie 和下载记录。"""
    records = _get_records(export_dir, "browser_history", cache=cache)
    if not records:
        return _missing_answer(
            "未找到浏览器历史/下载/Cookie 导出。",
            required_kinds=["browser_history"],
        )

    q_lower = question.lower()
    is_cookie_query = "cookie" in q_lower
    is_download_query = any(kw in q_lower for kw in ["download", "下载"])

    downloads: list[dict] = []
    cookies: list[dict] = []
    matched: list[dict] = []

    for r in records:
        txt = _record_text(r)
        rtype = (r.get("type") or r.get("record_type") or r.get("category") or "").lower()

        # 分类
        if rtype in ("download", "downloads") or r.get("target_path") or r.get("download_path"):
            downloads.append(r)
        elif rtype in ("cookie", "cookies") or r.get("host_key") or r.get("cookie_name"):
            cookies.append(r)

        # 按问题过滤
        if q_lower and any(kw in txt.lower() for kw in q_lower.split() if len(kw) > 2):
            matched.append(r)

    lines = [f"浏览器记录总数: {len(records)}"]

    if is_download_query or (not is_cookie_query and downloads):
        lines.append(f"下载记录: {len(downloads)} 条")
        for d in downloads[:15]:
            url = d.get("url") or d.get("download_url") or ""
            path = d.get("target_path") or d.get("download_path") or d.get("filename") or ""
            ts = d.get("start_time") or d.get("timestamp") or ""
            lines.append(f"  {ts} | {path} | {url[:80]}")

    if is_cookie_query or (not is_download_query and cookies):
        lines.append(f"Cookie 记录: {len(cookies)} 条")
        for c in cookies[:15]:
            host = c.get("host_key") or c.get("domain") or c.get("host") or ""
            name = c.get("name") or c.get("cookie_name") or ""
            value = c.get("value") or c.get("cookie_value") or ""
            lines.append(f"  {host} | {name}={value[:50]}")

    if matched and not downloads and not cookies:
        lines.append(f"匹配记录: {len(matched)} 条")
        for m in matched[:15]:
            lines.append(f"  {_record_text(m)[:150]}")

    evidence = (matched or downloads or cookies or records)[:20]
    return {
        "status": "answered",
        "answer": "\n".join(lines),
        "confidence": "high" if (downloads or cookies or matched) else "medium",
        "evidence": evidence,
        "notes": [
            "Chrome/Edge 时间格式: WebKit timestamp (微秒 since 1601-01-01)",
            "下载路径可揭示用户行为和文件来源",
        ],
    }


# ---------------------------------------------------------------------------
# Task 24: ETW Trace (.etl) 文件分析
# ---------------------------------------------------------------------------
ETW_KEYWORDS = re.compile(
    r"etw|etl|event.tracing|trace.log|etw.trace|wpr|xperf|事件跟踪|跟踪日志",
    re.IGNORECASE,
)
_ETL_EXTENSIONS = {".etl"}
_ETL_KNOWN_PATHS = re.compile(
    r"WDI|LogFiles\\WMI|Panther|Diagnosis|ETLLogs|BootPerf|Wifi\.etl|"
    r"ShutdownPerf|SleepStudy|AutoLogger",
    re.IGNORECASE,
)


def _answer_etw_trace(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """定位和分析 ETW Trace (.etl) 文件。"""
    records = _get_records(export_dir, "etw_traces", cache=cache)
    evidence: list[dict] = []

    # 如果有专门的 ETW 导出
    if records:
        q_lower = question.lower()
        matched = []
        for r in records:
            txt = _record_text(r)
            if q_lower and any(kw in txt.lower() for kw in q_lower.split() if len(kw) > 2):
                matched.append(r)
        lines = [f"ETW Trace 记录: {len(records)} 条"]
        if matched:
            lines.append(f"匹配记录: {len(matched)} 条")
            for m in matched[:15]:
                lines.append(f"  {_record_text(m)[:150]}")
            evidence = matched[:20]
        else:
            for r in records[:10]:
                lines.append(f"  {_record_text(r)[:150]}")
            evidence = records[:10]
        return {
            "status": "answered",
            "answer": "\n".join(lines),
            "confidence": "high",
            "evidence": evidence,
            "notes": ["ETL 文件需用 tracerpt/xperf/WPA 解析为可读格式"],
        }

    # 从 file_listing 搜索 .etl 文件
    fl = _get_records(export_dir, "file_listing", cache=cache)
    if not fl:
        return _missing_answer(
            "未找到 ETW Trace 导出或 .etl 文件。",
            required_kinds=["etw_traces", "file_listing"],
        )

    etl_files: list[dict] = []
    for r in fl:
        fn = (r.get("filename") or r.get("name") or "").lower()
        path = (r.get("path") or "").lower()
        if fn.endswith(".etl") or (fn and "." in fn and fn.rsplit(".", 1)[1] == "etl"):
            etl_files.append(r)

    if not etl_files:
        return _missing_answer(
            "未在 file_listing 中找到 .etl 文件。",
            required_kinds=["etw_traces", "file_listing"],
        )

    # 分类 ETL 文件
    wifi_etl = []
    boot_etl = []
    other_etl = []
    for f in etl_files:
        path = (f.get("path") or f.get("filename") or "").lower()
        if "wifi" in path or "wlan" in path:
            wifi_etl.append(f)
        elif "boot" in path or "shutdown" in path:
            boot_etl.append(f)
        else:
            other_etl.append(f)

    lines = [f"ETL 文件总数: {len(etl_files)}"]
    if wifi_etl:
        lines.append(f"WiFi 相关: {len(wifi_etl)} 个")
    if boot_etl:
        lines.append(f"Boot/Shutdown 相关: {len(boot_etl)} 个")
    lines.append("文件列表:")
    for f in etl_files[:20]:
        fn = f.get("filename") or f.get("name") or ""
        path = f.get("path") or ""
        size = f.get("size") or ""
        lines.append(f"  {fn} | {path} | {size}")

    return {
        "status": "answered",
        "answer": "\n".join(lines),
        "confidence": "medium",
        "evidence": etl_files[:20],
        "notes": [
            "ETL 文件需用 tracerpt.exe 转换: tracerpt file.etl -o output.csv",
            "WiFi.etl: 无线网络连接事件",
            "BootPerfDiagLogger.etl: 启动性能数据",
        ],
    }


# ---------------------------------------------------------------------------
# 分区表分析 handler
# ---------------------------------------------------------------------------

PARTITION_KEYWORDS: list[str] = [
    "分区表", "partition", "gpt", "mbr", "主引导", "guid",
    "分区数", "起始扇区", "start sector", "分区类型", "分区大小",
    "efi", "esp", "msr", "恢复分区", "recovery",
]

def _answer_partition_table(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """分区表/磁盘结构分析 — MBR/GPT/分区数/起始扇区/分区大小。"""
    q_lower = question.lower()

    # 尝试加载专用 disk_partition_info
    part_items = _get_records(export_dir, "disk_partition_info", cache=cache)

    # fallback: file_listing 中找分区相关文件
    if not part_items:
        fl_items = _get_records(export_dir, "file_listing", cache=cache)
        if fl_items:
            part_items = [
                r for r in fl_items
                if any(kw in _record_text(r).lower() for kw in ("partition", "mbr", "gpt", "$mft", "boot sector"))
            ]

    if not part_items:
        return _missing_answer(
            "未找到分区表/磁盘结构数据。请确保 XWF 已导出 disk_partition_info 或在 file_listing 中包含分区信息。",
            required_kinds=["disk_partition_info", "file_listing"],
        )

    # 尝试识别分区表类型
    all_text = " ".join(_record_text(r).lower() for r in part_items[:200])
    pt_type = "未知"
    if "gpt" in all_text or "guid partition" in all_text:
        pt_type = "GPT (GUID Partition Table)"
    elif "mbr" in all_text or "master boot record" in all_text:
        pt_type = "MBR (Master Boot Record)"

    # 按问题关键词过滤
    if any(kw in q_lower for kw in ("起始扇区", "start sector", "偏移", "offset")):
        filtered = [r for r in part_items if any(
            kw in _record_text(r).lower() for kw in ("sector", "offset", "lba", "扇区")
        )]
        if filtered:
            part_items = filtered

    summary = f"分区表类型: {pt_type}。共找到 {len(part_items)} 条分区相关记录。"

    # 尝试统计分区数
    partition_count = 0
    for r in part_items:
        txt = _record_text(r).lower()
        if any(kw in txt for kw in ("partition", "分区")) and any(
            c.isdigit() for c in txt
        ):
            partition_count += 1
    if partition_count:
        summary += f" 检测到约 {partition_count} 个分区条目。"

    return {
        "answered": True,
        "answer": summary,
        "detail_items": part_items[:50],
        "partition_table_type": pt_type,
    }


# ---------------------------------------------------------------------------
# 卷/文件系统信息 handler
# ---------------------------------------------------------------------------

VOLUME_FS_KEYWORDS: list[str] = [
    "文件系统", "file system", "ntfs", "fat32", "exfat", "ext4",
    "簇大小", "cluster size", "分配单元", "卷标", "volume label",
    "卷序列号", "volume serial", "总容量", "格式化",
]

def _answer_volume_filesystem(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """卷/文件系统信息 — FS类型/簇大小/卷标/卷序列号/容量。"""
    q_lower = question.lower()

    vol_items = _get_records(export_dir, "volume_info", cache=cache)
    part_items = _get_records(export_dir, "disk_partition_info", cache=cache)
    reg_items = _get_records(export_dir, "registry_system", cache=cache)

    all_items: list[dict] = []
    if vol_items:
        all_items.extend(vol_items)
    if part_items:
        all_items.extend(part_items)

    # 从 registry_system 中提取 MountedDevices
    if reg_items:
        mounted = [r for r in reg_items if "mounteddevices" in _record_text(r).lower()]
        if mounted:
            all_items.extend(mounted)

    if not all_items:
        return _missing_answer(
            "未找到卷/文件系统信息。请导出 volume_info 或 disk_partition_info。",
            required_kinds=["volume_info", "disk_partition_info"],
        )

    # 检测文件系统类型
    all_text = " ".join(_record_text(r).lower() for r in all_items[:200])
    fs_types: list[str] = []
    for fs in ("ntfs", "fat32", "fat16", "exfat", "ext4", "ext3", "hfs+", "apfs"):
        if fs in all_text:
            fs_types.append(fs.upper())

    # 提取卷序列号
    serial_re = re.compile(r"(?:serial|序列号)[:\s]*([0-9a-fA-F]{4,16})", re.IGNORECASE)
    serials: list[str] = []
    for r in all_items[:100]:
        m = serial_re.search(_record_text(r))
        if m:
            serials.append(m.group(1).upper())

    # 提取簇大小
    cluster_re = re.compile(r"(?:cluster|簇|allocation unit)[:\s]*(\d+)\s*(?:bytes|字节|kb)?", re.IGNORECASE)
    cluster_sizes: list[str] = []
    for r in all_items[:100]:
        m = cluster_re.search(_record_text(r))
        if m:
            cluster_sizes.append(m.group(1))

    summary_parts: list[str] = []
    if fs_types:
        summary_parts.append(f"文件系统类型: {', '.join(fs_types)}")
    if serials:
        summary_parts.append(f"卷序列号: {', '.join(sorted(set(serials)))}")
    if cluster_sizes:
        summary_parts.append(f"簇大小: {', '.join(sorted(set(cluster_sizes)))} bytes")
    summary_parts.append(f"总计 {len(all_items)} 条相关记录")

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": all_items[:50],
        "filesystem_types": fs_types,
        "volume_serials": list(set(serials)),
        "cluster_sizes": list(set(cluster_sizes)),
    }


# ---------------------------------------------------------------------------
# USB 设备取证时间线 handler
# ---------------------------------------------------------------------------

USB_TIMELINE_KEYWORDS: list[str] = [
    "usb时间线", "vid", "pid", "首次连接", "最后连接",
    "usb制造商", "usb品牌", "usb型号", "usb序列号", "setupapi",
    "usb serial", "drive letter", "盘符",
]

def _answer_usb_device_timeline(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """USB 设备取证时间线 — VID/PID/序列号/首次连接/最后连接/盘符。"""
    q_lower = question.lower()

    reg_items = _get_records(export_dir, "registry_devices", cache=cache)
    setup_items = _get_records(export_dir, "setupapi_logs", cache=cache)
    pnp_items = _get_records(export_dir, "event_logs_pnp", cache=cache)

    all_items: list[dict] = []
    usb_devices: list[dict] = []

    # 从注册表提取 USB 设备信息
    if reg_items:
        usb_entries = [r for r in reg_items if any(
            kw in _record_text(r).lower() for kw in ("usbstor", "usb\\vid", "mounteddevices", "wpdbusenum", "portable devices")
        )]
        all_items.extend(usb_entries)

        # 提取 VID/PID
        vidpid_re = re.compile(r"VID[_&]([0-9A-Fa-f]{4})[&_]PID[_&]([0-9A-Fa-f]{4})", re.IGNORECASE)
        # 提取序列号 (USBSTOR 路径中最后一段)
        serial_re = re.compile(r"USBSTOR\\[^\\]+\\([^\\&]+)", re.IGNORECASE)
        # 提取设备描述
        desc_re = re.compile(r"(?:Disk&Ven_|Disk_)([^&\\]+)(?:&Prod_|_)([^&\\]+)", re.IGNORECASE)

        for r in usb_entries:
            txt = _record_text(r)
            device: dict[str, str] = {}
            vm = vidpid_re.search(txt)
            if vm:
                device["vid"] = vm.group(1).upper()
                device["pid"] = vm.group(2).upper()
            sm = serial_re.search(txt)
            if sm:
                device["serial"] = sm.group(1)
            dm = desc_re.search(txt)
            if dm:
                device["vendor"] = dm.group(1).strip()
                device["product"] = dm.group(2).strip()
            if device:
                usb_devices.append(device)

    # 从 SetupAPI 提取首次连接时间
    first_install_times: dict[str, str] = {}
    if setup_items:
        all_items.extend(setup_items[:50])
        for r in setup_items:
            txt = _record_text(r)
            if "usbstor" in txt.lower() or "usb\\vid" in txt.lower():
                # 尝试提取时间戳
                for pat in DATETIME_PATTERNS:
                    m = pat.search(txt)
                    if m:
                        ts = f"{m.group('year')}-{m.group('month').zfill(2)}-{m.group('day').zfill(2)} {m.group('hour').zfill(2)}:{m.group('minute').zfill(2)}"
                        # 以设备路径前几个字符为 key
                        key = txt[:60]
                        first_install_times[key] = ts
                        break

    # 从 PnP 事件日志提取
    if pnp_items:
        usb_pnp = [r for r in pnp_items if any(
            kw in _record_text(r).lower() for kw in ("usb", "usbstor", "removable")
        )]
        all_items.extend(usb_pnp[:50])

    if not all_items:
        return _missing_answer(
            "未找到 USB 设备时间线数据。请确保导出了 registry_devices、setupapi_logs 或 event_logs_pnp。",
            required_kinds=["registry_devices", "setupapi_logs", "event_logs_pnp"],
        )

    # 构建摘要
    summary_parts: list[str] = []
    # 去重 usb_devices
    seen_serials: set[str] = set()
    unique_devices: list[dict] = []
    for d in usb_devices:
        key = d.get("serial", "") or f"{d.get('vid', '')}{d.get('pid', '')}"
        if key and key not in seen_serials:
            seen_serials.add(key)
            unique_devices.append(d)

    summary_parts.append(f"检测到 {len(unique_devices)} 个唯一 USB 设备")
    if first_install_times:
        summary_parts.append(f"SetupAPI 中找到 {len(first_install_times)} 条安装时间记录")

    # 如果问题问特定设备
    if any(kw in q_lower for kw in ("vid", "pid", "制造商", "品牌", "型号")):
        for d in unique_devices[:10]:
            parts = []
            if "vid" in d:
                parts.append(f"VID={d['vid']}")
            if "pid" in d:
                parts.append(f"PID={d['pid']}")
            if "vendor" in d:
                parts.append(f"Vendor={d['vendor']}")
            if "product" in d:
                parts.append(f"Product={d['product']}")
            if "serial" in d:
                parts.append(f"SN={d['serial']}")
            if parts:
                summary_parts.append(" | ".join(parts))

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": all_items[:80],
        "usb_devices": unique_devices[:20],
        "first_install_times": first_install_times,
    }


# ---------------------------------------------------------------------------
# 已删除/隐藏分区检测 handler
# ---------------------------------------------------------------------------

DELETED_PART_KEYWORDS: list[str] = [
    "已删除分区", "deleted partition", "隐藏分区", "hidden partition",
    "未分配空间", "unallocated", "分区残留", "分区恢复", "丢失分区",
]

def _answer_deleted_partition(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """已删除/隐藏分区检测。"""
    q_lower = question.lower()

    part_items = _get_records(export_dir, "disk_partition_info", cache=cache)
    fl_items = _get_records(export_dir, "file_listing", cache=cache)

    evidence: list[dict] = []

    if part_items:
        # 查找标记为 deleted/hidden/unallocated 的条目
        for r in part_items:
            txt = _record_text(r).lower()
            if any(kw in txt for kw in ("deleted", "已删除", "hidden", "隐藏", "unallocated", "未分配", "free space", "空闲")):
                evidence.append(r)

    if fl_items:
        # 在 file_listing 中查找可能表明隐藏分区的痕迹
        for r in fl_items:
            txt = _record_text(r).lower()
            if any(kw in txt for kw in ("unallocated", "orphan", "carved", "lost+found", "未分配")):
                evidence.append(r)

    if not part_items and not fl_items:
        return _missing_answer(
            "未找到磁盘分区数据。请导出 disk_partition_info 以进行已删除分区检测。",
            required_kinds=["disk_partition_info", "file_listing"],
        )

    if not evidence:
        return {
            "answered": True,
            "answer": "在当前导出数据中未发现明显的已删除或隐藏分区痕迹。分区表结构看似完整。",
            "detail_items": (part_items or [])[:20],
            "deleted_partitions_found": False,
        }

    summary = f"检测到 {len(evidence)} 条可能与已删除/隐藏分区相关的记录。"
    # 分类
    hidden_count = sum(1 for r in evidence if "hidden" in _record_text(r).lower() or "隐藏" in _record_text(r).lower())
    unalloc_count = sum(1 for r in evidence if "unallocated" in _record_text(r).lower() or "未分配" in _record_text(r).lower())
    if hidden_count:
        summary += f" 其中 {hidden_count} 条标记为隐藏。"
    if unalloc_count:
        summary += f" {unalloc_count} 条位于未分配空间。"

    return {
        "answered": True,
        "answer": summary,
        "detail_items": evidence[:50],
        "deleted_partitions_found": True,
        "hidden_count": hidden_count,
        "unallocated_count": unalloc_count,
    }


# ---------------------------------------------------------------------------
# 证据源/镜像元数据 handler
# ---------------------------------------------------------------------------

EVIDENCE_META_KEYWORDS: list[str] = [
    "镜像", "image", "证据源", "evidence source", "磁盘镜像",
    "e01", "dd", "原始大小", "扇区数", "采集工具", "镜像md5",
    "镜像sha", "制作时间", "镜像完整性",
]

def _answer_evidence_metadata(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """证据源/镜像元数据 — Hash/采集时间/原始大小/扇区数。"""
    q_lower = question.lower()

    meta_items = _get_records(export_dir, "evidence_metadata", cache=cache)
    part_items = _get_records(export_dir, "disk_partition_info", cache=cache)

    all_items: list[dict] = []
    if meta_items:
        all_items.extend(meta_items)
    if part_items:
        # 从分区信息中也可能找到镜像元数据
        img_related = [r for r in part_items if any(
            kw in _record_text(r).lower() for kw in ("image", "镜像", "e01", "dd", "raw", "acquisition", "采集")
        )]
        all_items.extend(img_related)

    if not all_items:
        return _missing_answer(
            "未找到证据源/镜像元数据。请导出 evidence_metadata (XWF 案件属性 → 证据对象信息)。",
            required_kinds=["evidence_metadata"],
        )

    # 提取关键信息
    all_text = " ".join(_record_text(r) for r in all_items[:100])

    # 提取 hash
    md5_re = re.compile(r"(?:md5)[:\s]*([0-9a-fA-F]{32})", re.IGNORECASE)
    sha1_re = re.compile(r"(?:sha-?1)[:\s]*([0-9a-fA-F]{40})", re.IGNORECASE)
    sha256_re = re.compile(r"(?:sha-?256)[:\s]*([0-9a-fA-F]{64})", re.IGNORECASE)

    hashes: dict[str, str] = {}
    for name, regex in [("MD5", md5_re), ("SHA1", sha1_re), ("SHA256", sha256_re)]:
        m = regex.search(all_text)
        if m:
            hashes[name] = m.group(1).upper()

    # 提取大小
    size_re = re.compile(r"(?:size|大小|容量)[:\s]*([\d,\.]+)\s*(bytes|gb|mb|tb|sectors|扇区)?", re.IGNORECASE)
    sizes: list[str] = []
    for m in size_re.finditer(all_text):
        sizes.append(f"{m.group(1)} {m.group(2) or 'bytes'}")

    # 提取时间
    acq_times: list[str] = []
    for pat in DATETIME_PATTERNS:
        for m in pat.finditer(all_text):
            acq_times.append(f"{m.group('year')}-{m.group('month').zfill(2)}-{m.group('day').zfill(2)} {m.group('hour').zfill(2)}:{m.group('minute').zfill(2)}")

    summary_parts: list[str] = []
    if hashes:
        for name, val in hashes.items():
            summary_parts.append(f"{name}: {val}")
    if sizes:
        summary_parts.append(f"大小: {sizes[0]}")
    if acq_times:
        summary_parts.append(f"采集/制作时间: {acq_times[0]}")
    if not summary_parts:
        summary_parts.append(f"共 {len(all_items)} 条元数据记录")

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": all_items[:50],
        "hashes": hashes,
        "sizes": sizes,
        "acquisition_times": acq_times[:5],
    }


# ---------------------------------------------------------------------------
# 存储介质总览 handler
# ---------------------------------------------------------------------------

STORAGE_OVERVIEW_KEYWORDS: list[str] = [
    "硬盘", "磁盘", "存储介质", "硬盘型号", "硬盘容量", "磁盘信息",
    "ssd", "hdd", "固态", "机械", "u盘容量", "tf卡", "sd卡", "存储卡",
]

def _answer_storage_media_overview(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """存储介质总览 — 磁盘型号/容量/分区布局/介质类型。"""
    q_lower = question.lower()

    meta_items = _get_records(export_dir, "evidence_metadata", cache=cache)
    part_items = _get_records(export_dir, "disk_partition_info", cache=cache)
    vol_items = _get_records(export_dir, "volume_info", cache=cache)
    reg_items = _get_records(export_dir, "registry_devices", cache=cache)

    all_items: list[dict] = []
    if meta_items:
        all_items.extend(meta_items)
    if part_items:
        all_items.extend(part_items)
    if vol_items:
        all_items.extend(vol_items)

    # 从注册表中提取磁盘硬件信息
    disk_hw: list[dict] = []
    if reg_items:
        hw_entries = [r for r in reg_items if any(
            kw in _record_text(r).lower() for kw in ("disk&ven", "ide\\disk", "scsi\\disk", "nvme", "diskdrive")
        )]
        all_items.extend(hw_entries)
        disk_hw = hw_entries

    if not all_items:
        return _missing_answer(
            "未找到存储介质信息。请导出 evidence_metadata、disk_partition_info 或 registry_devices。",
            required_kinds=["evidence_metadata", "disk_partition_info", "registry_devices"],
        )

    all_text = " ".join(_record_text(r).lower() for r in all_items[:200])

    # 识别介质类型
    media_types: list[str] = []
    if any(kw in all_text for kw in ("ssd", "solid state", "nvme", "固态")):
        media_types.append("SSD (固态硬盘)")
    if any(kw in all_text for kw in ("hdd", "mechanical", "机械", "rpm")):
        media_types.append("HDD (机械硬盘)")
    if any(kw in all_text for kw in ("usb", "removable", "u盘", "flash drive")):
        media_types.append("USB/可移动存储")
    if any(kw in all_text for kw in ("sd card", "tf card", "sd卡", "tf卡", "microsd")):
        media_types.append("SD/TF 存储卡")

    # 提取磁盘型号
    model_re = re.compile(r"(?:model|型号|product)[:\s]*([^\n,;]{3,50})", re.IGNORECASE)
    models: list[str] = []
    for r in all_items[:50]:
        m = model_re.search(_record_text(r))
        if m:
            models.append(m.group(1).strip())

    # 提取容量
    cap_re = re.compile(r"(\d+(?:\.\d+)?)\s*(tb|gb|mb)\b", re.IGNORECASE)
    capacities: list[str] = []
    for r in all_items[:50]:
        for m in cap_re.finditer(_record_text(r)):
            capacities.append(f"{m.group(1)} {m.group(2).upper()}")

    summary_parts: list[str] = []
    if media_types:
        summary_parts.append(f"介质类型: {', '.join(media_types)}")
    if models:
        summary_parts.append(f"型号: {', '.join(sorted(set(models))[:3])}")
    if capacities:
        summary_parts.append(f"容量: {', '.join(sorted(set(capacities))[:3])}")
    summary_parts.append(f"共 {len(all_items)} 条存储相关记录")

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": all_items[:60],
        "media_types": media_types,
        "disk_models": list(set(models))[:5],
        "capacities": list(set(capacities))[:5],
    }


# ---------------------------------------------------------------------------
# 引导扇区/VBR 详细解析 handler
# ---------------------------------------------------------------------------

BOOT_SECTOR_KEYWORDS: list[str] = [
    "引导扇区", "boot sector", "vbr", "bpb", "总扇区数",
    "total sectors", "隐藏扇区", "hidden sectors", "mft位置",
    "mft cluster", "fat大小", "保留扇区", "oem",
]

def _answer_boot_sector(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """引导扇区/VBR 详细解析 — 总扇区/隐藏扇区/MFT位置/FAT参数。"""
    q_lower = question.lower()

    part_items = _get_records(export_dir, "disk_partition_info", cache=cache)
    vol_items = _get_records(export_dir, "volume_info", cache=cache)

    all_items: list[dict] = []
    if part_items:
        all_items.extend(part_items)
    if vol_items:
        all_items.extend(vol_items)

    if not all_items:
        return _missing_answer(
            "未找到引导扇区数据。请导出 disk_partition_info 或 volume_info (XWF: 选中分区 → View → Template → Boot Sector)。",
            required_kinds=["disk_partition_info", "volume_info"],
        )

    all_text = " ".join(_record_text(r) for r in all_items[:100])
    all_text_lower = all_text.lower()

    # 提取关键 VBR 参数
    params: dict[str, str] = {}

    # 总扇区数
    total_sec_re = re.compile(r"(?:total\s*sectors?|总扇区)[:\s=]*(\d[\d,]*)", re.IGNORECASE)
    m = total_sec_re.search(all_text)
    if m:
        params["总扇区数"] = m.group(1).replace(",", "")

    # 隐藏扇区
    hidden_re = re.compile(r"(?:hidden\s*sectors?|隐藏扇区)[:\s=]*(\d[\d,]*)", re.IGNORECASE)
    m = hidden_re.search(all_text)
    if m:
        params["隐藏扇区"] = m.group(1).replace(",", "")

    # 每扇区字节
    bps_re = re.compile(r"(?:bytes?\s*/?\s*sector|每扇区字节)[:\s=]*(\d+)", re.IGNORECASE)
    m = bps_re.search(all_text)
    if m:
        params["每扇区字节"] = m.group(1)

    # 每簇扇区
    spc_re = re.compile(r"(?:sectors?\s*/?\s*cluster|每簇扇区)[:\s=]*(\d+)", re.IGNORECASE)
    m = spc_re.search(all_text)
    if m:
        params["每簇扇区"] = m.group(1)

    # MFT 簇号
    mft_re = re.compile(r"(?:\$?mft\s*(?:cluster|起始簇|lcn))[:\s=]*(\d[\d,]*)", re.IGNORECASE)
    m = mft_re.search(all_text)
    if m:
        params["MFT起始簇"] = m.group(1).replace(",", "")

    # OEM ID
    oem_re = re.compile(r"(?:oem\s*id|oem标识)[:\s=]*([^\n,;]{3,20})", re.IGNORECASE)
    m = oem_re.search(all_text)
    if m:
        params["OEM ID"] = m.group(1).strip()

    # FAT 相关
    fat_size_re = re.compile(r"(?:fat\s*size|sectors?\s*/?\s*fat|fat大小)[:\s=]*(\d+)", re.IGNORECASE)
    m = fat_size_re.search(all_text)
    if m:
        params["FAT大小(扇区)"] = m.group(1)

    reserved_re = re.compile(r"(?:reserved\s*sectors?|保留扇区)[:\s=]*(\d+)", re.IGNORECASE)
    m = reserved_re.search(all_text)
    if m:
        params["保留扇区"] = m.group(1)

    # 文件系统类型
    fs_type = "未知"
    if "ntfs" in all_text_lower:
        fs_type = "NTFS"
    elif "fat32" in all_text_lower:
        fs_type = "FAT32"
    elif "exfat" in all_text_lower:
        fs_type = "exFAT"
    elif "fat16" in all_text_lower or "fat12" in all_text_lower:
        fs_type = "FAT16/FAT12"

    summary_parts: list[str] = [f"文件系统: {fs_type}"]
    for k, v in params.items():
        summary_parts.append(f"{k}: {v}")

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": all_items[:50],
        "filesystem_type": fs_type,
        "boot_sector_params": params,
    }


# ---------------------------------------------------------------------------
# 文件雕刻/恢复分析 handler
# ---------------------------------------------------------------------------

CARVING_KEYWORDS: list[str] = [
    "文件雕刻", "carving", "数据恢复", "recovery", "文件恢复",
    "未分配空间恢复", "carved", "删除文件恢复", "orphan",
]

def _answer_file_carving(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """文件雕刻/恢复分析 — 从未分配空间恢复的文件统计。"""
    q_lower = question.lower()

    fl_items = _get_records(export_dir, "file_listing", cache=cache)
    if not fl_items:
        return _missing_answer(
            "未找到文件列表数据。请确保 XWF 已执行文件签名搜索并导出 file_listing。",
            required_kinds=["file_listing"],
        )

    # 分类文件状态
    carved_files: list[dict] = []
    deleted_files: list[dict] = []
    recovered_files: list[dict] = []

    status_keywords_carved = ("carved", "雕刻", "header signature")
    status_keywords_deleted = ("deleted", "已删除", "previously existing")
    status_keywords_recovered = ("recovered", "恢复", "recoverable")

    for r in fl_items:
        txt = _record_text(r).lower()
        if any(kw in txt for kw in status_keywords_carved):
            carved_files.append(r)
        elif any(kw in txt for kw in status_keywords_recovered):
            recovered_files.append(r)
        elif any(kw in txt for kw in status_keywords_deleted):
            deleted_files.append(r)

    total_recoverable = len(carved_files) + len(deleted_files) + len(recovered_files)

    if total_recoverable == 0:
        return {
            "answered": True,
            "answer": f"在 {len(fl_items)} 个文件记录中未发现明显的已删除/雕刻文件。所有文件状态正常。",
            "detail_items": [],
            "carved_count": 0,
            "deleted_count": 0,
        }

    # 按文件类型统计雕刻文件
    ext_stats: dict[str, int] = {}
    for r in carved_files + recovered_files:
        txt = _record_text(r)
        ext_match = re.search(r"\.(\w{2,5})(?:\s|$|,)", txt)
        if ext_match:
            ext = ext_match.group(1).lower()
            ext_stats[ext] = ext_stats.get(ext, 0) + 1

    summary_parts: list[str] = []
    summary_parts.append(f"共发现 {total_recoverable} 个可恢复文件")
    if carved_files:
        summary_parts.append(f"雕刻文件: {len(carved_files)} 个")
    if deleted_files:
        summary_parts.append(f"已删除文件: {len(deleted_files)} 个")
    if recovered_files:
        summary_parts.append(f"可恢复文件: {len(recovered_files)} 个")
    if ext_stats:
        top_exts = sorted(ext_stats.items(), key=lambda x: -x[1])[:5]
        ext_summary = ", ".join(f".{e}({c})" for e, c in top_exts)
        summary_parts.append(f"主要类型: {ext_summary}")

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": (carved_files + recovered_files + deleted_files)[:80],
        "carved_count": len(carved_files),
        "deleted_count": len(deleted_files),
        "recovered_count": len(recovered_files),
        "extension_stats": ext_stats,
    }


# ---------------------------------------------------------------------------
# 磁盘活动时间线 handler
# ---------------------------------------------------------------------------

DISK_TIMELINE_KEYWORDS: list[str] = [
    "磁盘活动", "disk activity", "磁盘时间线", "文件操作时间线",
    "文件创建时间", "文件修改时间", "操作顺序", "timeline",
    "最早文件", "最晚文件", "活动高峰",
]

def _answer_disk_activity_timeline(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """磁盘活动时间线 — 综合 USN/MFT/文件时间戳的操作时间线。"""
    q_lower = question.lower()

    usn_items = _get_records(export_dir, "usn_journal", cache=cache)
    mft_items = _get_records(export_dir, "mft_export", cache=cache)
    fl_items = _get_records(export_dir, "file_listing", cache=cache)

    all_items: list[dict] = []
    if usn_items:
        all_items.extend(usn_items)
    if mft_items:
        all_items.extend(mft_items)
    if fl_items:
        all_items.extend(fl_items)

    if not all_items:
        return _missing_answer(
            "未找到磁盘活动数据。请导出 usn_journal、mft_export 或 file_listing。",
            required_kinds=["usn_journal", "mft_export", "file_listing"],
        )

    # 提取所有时间戳
    timestamps: list[str] = []
    ts_re = re.compile(r"(20\d{2}[-/]\d{1,2}[-/]\d{1,2}[ T]\d{1,2}:\d{1,2}(?::\d{1,2})?)")
    for r in all_items[:500]:
        txt = _record_text(r)
        for m in ts_re.finditer(txt):
            timestamps.append(m.group(1))

    # 提取日期分布 (按天)
    date_counts: dict[str, int] = {}
    date_re = re.compile(r"(20\d{2}[-/]\d{1,2}[-/]\d{1,2})")
    for ts in timestamps:
        dm = date_re.match(ts)
        if dm:
            date_counts[dm.group(1)] = date_counts.get(dm.group(1), 0) + 1

    summary_parts: list[str] = []
    summary_parts.append(f"数据来源: USN={len(usn_items or [])}, MFT={len(mft_items or [])}, FileList={len(fl_items or [])}")

    if timestamps:
        sorted_ts = sorted(timestamps)
        summary_parts.append(f"时间范围: {sorted_ts[0]} ~ {sorted_ts[-1]}")

    if date_counts:
        # 找活动最密集的日期
        peak_date = max(date_counts, key=date_counts.get)  # type: ignore[arg-type]
        summary_parts.append(f"活动高峰日: {peak_date} ({date_counts[peak_date]} 条记录)")
        summary_parts.append(f"活跃天数: {len(date_counts)} 天")

    # 按问题过滤
    if any(kw in q_lower for kw in ("最早", "earliest", "第一个")):
        if timestamps:
            summary_parts.append(f"最早活动: {sorted(timestamps)[0]}")
    elif any(kw in q_lower for kw in ("最晚", "latest", "最后", "最近")):
        if timestamps:
            summary_parts.append(f"最晚活动: {sorted(timestamps)[-1]}")

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": all_items[:80],
        "timestamp_count": len(timestamps),
        "date_distribution": dict(sorted(date_counts.items())[-10:]) if date_counts else {},
        "time_range": {"earliest": sorted(timestamps)[0], "latest": sorted(timestamps)[-1]} if timestamps else {},
    }


# ---------------------------------------------------------------------------
# 加密恢复密钥分析 handler
# ---------------------------------------------------------------------------

ENCRYPT_KEY_KEYWORDS: list[str] = [
    "恢复密钥", "recovery key", "bitlocker密钥", "fvek",
    "tpm", "恢复id", "key protector", "数字密码",
    "启动密钥", "bek文件",
]

def _answer_encryption_key_recovery(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """加密恢复密钥分析 — BitLocker恢复密钥/TPM/FVEK。"""
    q_lower = question.lower()

    reg_items = _get_records(export_dir, "registry_system", cache=cache)
    enc_items = _get_records(export_dir, "encrypted_files", cache=cache)
    fl_items = _get_records(export_dir, "file_listing", cache=cache)

    evidence: list[dict] = []
    recovery_keys: list[str] = []

    # BitLocker 恢复密钥格式: 123456-789012-345678-901234-567890-123456-789012-345678
    key_re = re.compile(r"\b(\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6}-\d{6})\b")
    # 恢复密钥 ID (GUID)
    key_id_re = re.compile(r"(?:recovery|恢复).*?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})", re.IGNORECASE)

    # 从注册表搜索
    if reg_items:
        fve_entries = [r for r in reg_items if any(
            kw in _record_text(r).lower() for kw in ("fve", "bitlocker", "recovery", "恢复密钥", "encrypt")
        )]
        evidence.extend(fve_entries)
        for r in fve_entries:
            txt = _record_text(r)
            for m in key_re.finditer(txt):
                recovery_keys.append(m.group(1))

    # 从加密文件列表搜索
    if enc_items:
        for r in enc_items:
            txt = _record_text(r)
            if any(kw in txt.lower() for kw in ("bitlocker", "recovery", "fvek", "bek")):
                evidence.append(r)
            for m in key_re.finditer(txt):
                recovery_keys.append(m.group(1))

    # 从文件列表中查找 .BEK 文件和恢复密钥文本文件
    bek_files: list[dict] = []
    if fl_items:
        for r in fl_items:
            txt = _record_text(r).lower()
            if ".bek" in txt or "bitlocker recovery key" in txt or "恢复密钥" in txt:
                bek_files.append(r)
                evidence.append(r)

    if not evidence:
        return _missing_answer(
            "未找到加密恢复密钥数据。请确保导出 registry_system (FVE 键) 或检查是否存在 .BEK 文件。",
            required_kinds=["registry_system", "encrypted_files"],
        )

    summary_parts: list[str] = []
    if recovery_keys:
        summary_parts.append(f"找到 {len(set(recovery_keys))} 个 BitLocker 恢复密钥")
        for key in sorted(set(recovery_keys))[:3]:
            summary_parts.append(f"密钥: {key}")
    if bek_files:
        summary_parts.append(f"找到 {len(bek_files)} 个 BEK/恢复密钥文件")
    if not recovery_keys and not bek_files:
        summary_parts.append(f"找到 {len(evidence)} 条加密相关记录，但未提取到完整恢复密钥")

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": evidence[:50],
        "recovery_keys": list(set(recovery_keys)),
        "bek_files": bek_files[:10],
    }


# ---------------------------------------------------------------------------
# 外接设备完整历史 handler
# ---------------------------------------------------------------------------

EXT_DEVICE_KEYWORDS: list[str] = [
    "外接设备", "external device", "设备历史", "所有usb",
    "全部设备", "设备清单", "设备列表", "连接历史",
    "移动硬盘", "外接硬盘", "设备统计",
]

def _answer_external_device_history(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """外接设备完整历史 — 多源交叉的设备连接记录综合分析。"""
    q_lower = question.lower()

    reg_items = _get_records(export_dir, "registry_devices", cache=cache)
    setup_items = _get_records(export_dir, "setupapi_logs", cache=cache)
    pnp_items = _get_records(export_dir, "event_logs_pnp", cache=cache)
    sys_events = _get_records(export_dir, "event_logs_system", cache=cache)
    reg_sys = _get_records(export_dir, "registry_system", cache=cache)

    # 综合所有来源
    all_devices: list[dict] = []
    device_timeline: list[dict] = []

    # 1. 注册表 USBSTOR/USB
    if reg_items:
        usb_entries = [r for r in reg_items if any(
            kw in _record_text(r).lower() for kw in ("usbstor", "usb\\vid", "mounteddevices",
                                                      "portable devices", "wpdbusenum")
        )]
        all_devices.extend(usb_entries)

    # 2. SetupAPI — 首次安装时间
    install_records: list[dict] = []
    if setup_items:
        for r in setup_items:
            txt = _record_text(r).lower()
            if any(kw in txt for kw in ("usbstor", "usb\\vid", "disk&ven")):
                install_records.append(r)
        all_devices.extend(install_records[:30])

    # 3. PnP 事件日志 — 连接/断开事件
    pnp_usb: list[dict] = []
    if pnp_items:
        pnp_usb = [r for r in pnp_items if any(
            kw in _record_text(r).lower() for kw in ("usb", "removable", "disk")
        )]
        device_timeline.extend(pnp_usb[:30])

    # 4. System 事件日志 — DriverFrameworks-UserMode
    if sys_events:
        driver_events = [r for r in sys_events if any(
            kw in _record_text(r).lower() for kw in ("2003", "2100", "2101", "usb", "removable")
        )]
        device_timeline.extend(driver_events[:20])

    # 5. registry_system — MountedDevices
    mounted: list[dict] = []
    if reg_sys:
        mounted = [r for r in reg_sys if "mounteddevices" in _record_text(r).lower()]
        all_devices.extend(mounted[:20])

    total_records = len(all_devices) + len(device_timeline)
    if total_records == 0:
        return _missing_answer(
            "未找到外接设备历史数据。请确保导出 registry_devices、setupapi_logs 和 event_logs_pnp。",
            required_kinds=["registry_devices", "setupapi_logs", "event_logs_pnp"],
        )

    # 统计唯一设备
    serial_re = re.compile(r"USBSTOR\\[^\\]+\\([^\\&]+)", re.IGNORECASE)
    unique_serials: set[str] = set()
    for r in all_devices:
        m = serial_re.search(_record_text(r))
        if m:
            unique_serials.add(m.group(1))

    summary_parts: list[str] = []
    summary_parts.append(f"综合 {total_records} 条设备相关记录")
    if unique_serials:
        summary_parts.append(f"唯一设备序列号: {len(unique_serials)} 个")
    summary_parts.append(f"数据来源: 注册表={len(all_devices)}, 事件时间线={len(device_timeline)}")
    if install_records:
        summary_parts.append(f"SetupAPI 安装记录: {len(install_records)} 条")
    if mounted:
        summary_parts.append(f"MountedDevices: {len(mounted)} 条盘符映射")

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": (all_devices + device_timeline)[:100],
        "unique_device_serials": list(unique_serials)[:20],
        "install_records_count": len(install_records),
        "timeline_events_count": len(device_timeline),
    }


# ---------------------------------------------------------------------------
# 反取证/数据擦除检测 handler
# ---------------------------------------------------------------------------

ANTI_FORENSICS_KEYWORDS: list[str] = [
    "反取证", "anti-forensics", "擦除", "wipe", "eraser",
    "sdelete", "bleachbit", "timestomping", "日志清除",
    "证据销毁", "secure delete", "痕迹清除",
]

# 已知擦除/反取证工具
_WIPE_TOOLS: list[str] = [
    "eraser", "sdelete", "bleachbit", "ccleaner", "dban",
    "cipher", "wipe", "shred", "srm", "privazer",
    "evidence eliminator", "tracks eraser", "privacy eraser",
    "wise disk cleaner", "disk wipe",
]

def _answer_anti_forensics(question: str, export_dir: Path, *, cache: dict) -> dict[str, Any]:
    """反取证/数据擦除检测 — 擦除工具痕迹/异常时间戳/隐藏操作。"""
    q_lower = question.lower()

    pf_items = _get_records(export_dir, "prefetch", cache=cache)
    amc_items = _get_records(export_dir, "amcache", cache=cache)
    usn_items = _get_records(export_dir, "usn_journal", cache=cache)
    fl_items = _get_records(export_dir, "file_listing", cache=cache)
    sys_events = _get_records(export_dir, "event_logs_system", cache=cache)
    sec_events = _get_records(export_dir, "event_logs_security", cache=cache)

    findings: list[dict] = []
    wipe_tools_found: list[str] = []

    # 1. 在 Prefetch/Amcache 中检测擦除工具
    for items, source in [(pf_items, "Prefetch"), (amc_items, "Amcache")]:
        if items:
            for r in items:
                txt = _record_text(r).lower()
                for tool in _WIPE_TOOLS:
                    if tool in txt:
                        wipe_tools_found.append(f"{tool} ({source})")
                        findings.append(r)
                        break

    # 2. 事件日志清除检测 (EventID 1102/104)
    log_cleared: list[dict] = []
    if sec_events:
        for r in sec_events:
            txt = _record_text(r)
            if any(kw in txt for kw in ("1102", "audit log was cleared", "日志已清除")):
                log_cleared.append(r)
                findings.append(r)
    if sys_events:
        for r in sys_events:
            txt = _record_text(r)
            if any(kw in txt for kw in ("104", "log file was cleared", "日志已清除")):
                log_cleared.append(r)
                findings.append(r)

    # 3. USN Journal 中大量连续删除
    mass_deletion = False
    delete_count = 0
    if usn_items:
        for r in usn_items:
            txt = _record_text(r).lower()
            if any(kw in txt for kw in ("delete", "0x200", "删除")):
                delete_count += 1
        if delete_count > 100:
            mass_deletion = True

    # 4. 文件列表中检查异常 (大量同时间删除、擦除工具文件)
    if fl_items:
        for r in fl_items[:500]:
            txt = _record_text(r).lower()
            for tool in _WIPE_TOOLS:
                if tool in txt and r not in findings:
                    wipe_tools_found.append(f"{tool} (FileList)")
                    findings.append(r)
                    break

    if not findings and not mass_deletion:
        return {
            "answered": True,
            "answer": "未检测到明显的反取证/数据擦除痕迹。",
            "detail_items": [],
            "anti_forensics_detected": False,
        }

    summary_parts: list[str] = []
    if wipe_tools_found:
        unique_tools = sorted(set(wipe_tools_found))
        summary_parts.append(f"检测到擦除工具: {', '.join(unique_tools)}")
    if log_cleared:
        summary_parts.append(f"事件日志被清除: {len(log_cleared)} 次")
    if mass_deletion:
        summary_parts.append(f"USN Journal 中大量删除操作: {delete_count} 条")
    if not summary_parts:
        summary_parts.append(f"发现 {len(findings)} 条可疑反取证记录")

    return {
        "answered": True,
        "answer": "; ".join(summary_parts) + "。",
        "detail_items": findings[:60],
        "anti_forensics_detected": True,
        "wipe_tools": list(set(wipe_tools_found)),
        "log_cleared_count": len(log_cleared),
        "mass_deletion": mass_deletion,
        "usn_delete_count": delete_count,
    }


def _wrap_no_question(fn):
    """将 (export_dir, *, cache) 签名适配为 (question, export_dir, cache)。"""
    def wrapper(_question: str, export_dir: Path, cache: dict) -> dict[str, Any]:
        return fn(export_dir, cache=cache)
    return wrapper


def _wrap_with_question(fn):
    """将 (question, export_dir, *, cache) 签名适配为 (question, export_dir, cache)。"""
    def wrapper(question: str, export_dir: Path, cache: dict) -> dict[str, Any]:
        return fn(question, export_dir, cache=cache)
    return wrapper


register_topic_handler("last_boot_time", _wrap_no_question(_answer_last_boot_time))
register_topic_handler("wechat_version", _wrap_no_question(_answer_wechat_version))
register_topic_handler("remote_control_software", _wrap_no_question(_answer_remote_control_software))
register_topic_handler("sunlogin_log_filename", _wrap_with_question(_answer_sunlogin_log_filename))
register_topic_handler("sunlogin_remote_ip_port", _wrap_with_question(_answer_sunlogin_remote_ip_port))
register_topic_handler("recent_usb_device", _wrap_no_question(_answer_recent_usb_device))
# 日志分析类 handler
register_topic_handler("last_shutdown_time", _wrap_no_question(_answer_last_shutdown_time))
register_topic_handler("user_logon_activity", _wrap_with_question(_answer_user_logon_activity))
register_topic_handler("service_installation", _wrap_no_question(_answer_service_installation))
register_topic_handler("account_management", _wrap_no_question(_answer_account_management))
register_topic_handler("application_error_analysis", _wrap_no_question(_answer_application_error))
register_topic_handler("generic_log_timeline", _wrap_with_question(_answer_generic_log_timeline))
# 终端命令解析类 handler
register_topic_handler("command_history_analysis", _wrap_with_question(_answer_command_history))
register_topic_handler("program_execution_history", _wrap_with_question(_answer_program_execution_history))
register_topic_handler("suspicious_command_detection", _wrap_with_question(_answer_suspicious_command_detection))
register_topic_handler("powershell_script_analysis", _wrap_with_question(_answer_powershell_script_analysis))

# Windows 时间信息取证类 handler
register_topic_handler("timestamp_decode", _wrap_with_question(_answer_timestamp_decode))
register_topic_handler("timezone_analysis", _wrap_no_question(_answer_timezone_analysis))
register_topic_handler("file_timestamp_analysis", _wrap_with_question(_answer_file_timestamp_analysis))

# Windows 时间线类 handler
register_topic_handler("windows_timeline_analysis", _wrap_with_question(_answer_windows_timeline))

# Windows 事件日志取证类 handler
register_topic_handler("user_profile_service_events", _wrap_with_question(_answer_user_profile_service))
register_topic_handler("rdp_remote_access", _wrap_with_question(_answer_rdp_remote_access))
register_topic_handler("pnp_device_events", _wrap_with_question(_answer_pnp_device_events))
register_topic_handler("system_time_change", _wrap_with_question(_answer_system_time_change))
register_topic_handler("wlan_network_events", _wrap_with_question(_answer_wlan_network_events))
register_topic_handler("event_log_filter", _wrap_with_question(_answer_event_log_filter))

# 回收站分析 handler
register_topic_handler("recycle_bin_analysis", _wrap_with_question(_answer_recycle_bin))

# 操作系统基本信息 handler
register_topic_handler("os_basic_info", _wrap_with_question(_answer_os_basic_info))
register_topic_handler("user_account_list", _wrap_with_question(_answer_user_account_list))
register_topic_handler("network_config", _wrap_with_question(_answer_network_config))

# LNK 快捷方式类 handler
register_topic_handler("lnk_shortcut_analysis", _wrap_with_question(_answer_lnk_shortcut))

# JumpList 跳转列表类 handler
register_topic_handler("jump_list_analysis", _wrap_with_question(_answer_jump_list))

# RecentDocs 最近文档类 handler
register_topic_handler("recent_docs_analysis", _wrap_with_question(_answer_recent_docs))

# UserAssist 程序执行类 handler
register_topic_handler("user_assist_analysis", _wrap_with_question(_answer_user_assist))

# 浏览器凭据 handler
register_topic_handler("browser_saved_password", _wrap_with_question(_answer_browser_saved_password))

# 文件哈希反查 handler
register_topic_handler("file_by_md5", _wrap_with_question(_answer_file_by_md5))

# 最近音频文件 handler
register_topic_handler("recent_audio_filename", _wrap_with_question(_answer_recent_audio_filename))

# 便签电话号码 handler
register_topic_handler("backup_phone_number", _wrap_with_question(_answer_backup_phone_number))

# 助记词提取 handler
register_topic_handler("mnemonic_first_word", _wrap_with_question(_answer_mnemonic_first_word))

# 音频内容分析 handler
register_topic_handler("audio_content_analysis", _wrap_with_question(_answer_audio_content_analysis))

# SRUM 资源使用 handler
register_topic_handler("srum_analysis", _wrap_with_question(_answer_srum_analysis))

# Prefetch 深度分析 handler
register_topic_handler("prefetch_deep_analysis", _wrap_with_question(_answer_prefetch_deep))

# ShellBags 文件夹浏览 handler
register_topic_handler("shellbags_analysis", _wrap_with_question(_answer_shellbags))

# 文件签名分析 handler
register_topic_handler("file_signature_analysis", _wrap_with_question(_answer_file_signature))

# 流量包定位 handler
register_topic_handler("pcap_file_locator", _wrap_with_question(_answer_pcap_locator))

# BitLocker/VeraCrypt 检测 handler
register_topic_handler("bitlocker_veracrypt_detection", _wrap_with_question(_answer_bitlocker_veracrypt))

# 计划任务 handler
register_topic_handler("scheduled_task_analysis", _wrap_with_question(_answer_scheduled_task))

# 服务/自启动项 handler
register_topic_handler("autostart_service_analysis", _wrap_with_question(_answer_autostart_service))

# Windows Defender handler
register_topic_handler("defender_antivirus_log", _wrap_with_question(_answer_defender_log))

# 剪贴板历史 handler
register_topic_handler("clipboard_history_analysis", _wrap_with_question(_answer_clipboard_history))

# 打印记录 handler
register_topic_handler("print_history", _wrap_with_question(_answer_print_history))

# USN Journal handler
register_topic_handler("usn_journal_analysis", _wrap_with_question(_answer_usn_journal))

# MFT Entry 分析 handler
register_topic_handler("mft_entry_analysis", _wrap_with_question(_answer_mft_entry))

# SQLite WAL 恢复 handler
register_topic_handler("sqlite_wal_recovery", _wrap_with_question(_answer_sqlite_wal))

# 浏览器下载/Cookie handler
register_topic_handler("browser_download_cookie", _wrap_with_question(_answer_browser_download_cookie))

# ETW Trace handler
register_topic_handler("etw_trace_analysis", _wrap_with_question(_answer_etw_trace))

# 分区表分析 handler
register_topic_handler("partition_table_analysis", _wrap_with_question(_answer_partition_table))

# 卷/文件系统信息 handler
register_topic_handler("volume_filesystem_info", _wrap_with_question(_answer_volume_filesystem))

# USB 设备取证时间线 handler
register_topic_handler("usb_device_forensic_timeline", _wrap_with_question(_answer_usb_device_timeline))

# 已删除分区检测 handler
register_topic_handler("deleted_partition_detection", _wrap_with_question(_answer_deleted_partition))

# 证据源/镜像元数据 handler
register_topic_handler("evidence_source_metadata", _wrap_with_question(_answer_evidence_metadata))

# 存储介质总览 handler
register_topic_handler("storage_media_overview", _wrap_with_question(_answer_storage_media_overview))

# 引导扇区分析 handler
register_topic_handler("boot_sector_analysis", _wrap_with_question(_answer_boot_sector))

# 文件雕刻/恢复 handler
register_topic_handler("file_carving_analysis", _wrap_with_question(_answer_file_carving))

# 磁盘活动时间线 handler
register_topic_handler("disk_activity_timeline", _wrap_with_question(_answer_disk_activity_timeline))

# 加密恢复密钥 handler
register_topic_handler("encryption_key_recovery", _wrap_with_question(_answer_encryption_key_recovery))

# 外接设备完整历史 handler
register_topic_handler("external_device_full_history", _wrap_with_question(_answer_external_device_history))

# 反取证检测 handler
register_topic_handler("anti_forensics_detection", _wrap_with_question(_answer_anti_forensics))
