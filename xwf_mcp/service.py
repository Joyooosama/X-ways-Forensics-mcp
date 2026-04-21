from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .config import XWaysConfig
from .legacy_qa_bank import build_legacy_answer
from .offline_qa_plan import build_offline_question_plan
from .offline_qa_answers import (
    answer_offline_qa as build_offline_qa_answers,
    get_offline_artifact_inventory as build_offline_artifact_inventory,
)
from .models import (
    AnalysisSessionManifest,
    CaseSummary,
    EvidencePlan,
    EvidencePlanEntry,
    JobRecord,
    JobStatus,
    RiskLevel,
    SearchListManifest,
)
from .parsers import (
    build_encrypted_candidates,
    extract_encrypted_messages,
    extract_names_from_file,
    extract_search_messages,
    extract_snapshot_summary,
    filter_messages,
    inventory_files,
    load_table_file,
    load_export_records,
    parse_msglog,
    read_text_auto,
    sanitize_filename,
)


@dataclass(frozen=True)
class ResolvedCase:
    name: str
    case_file: Path
    case_dir: Path
    msglog_path: Path
    password_file: Path
    export_dir: Path
    list_dir: Path


class XWaysService:
    def __init__(self, config: XWaysConfig) -> None:
        self.config = config
        self.config.ensure_directories()
        self._jobs_lock = threading.Lock()
        self._case_locks: dict[str, threading.Lock] = {}
        self._recover_jobs()

    def list_cases(self) -> dict[str, Any]:
        stems: set[str] = set()
        if self.config.cases_root.exists():
            for case_file in self.config.cases_root.glob("*.xfc"):
                stems.add(case_file.stem)
            for child in self.config.cases_root.iterdir():
                if child.is_dir() and not child.name.startswith("!"):
                    stems.add(child.name)
        cases = [self.case_summary(name).model_dump(mode="json") for name in sorted(stems)]
        return {"config": self.config.public_dict(), "cases": cases}

    def case_summary(self, case_ref: str) -> CaseSummary:
        case = self.resolve_case(case_ref)
        return CaseSummary(
            name=case.name,
            case_file=str(case.case_file) if case.case_file.exists() else None,
            case_dir=str(case.case_dir) if case.case_dir.exists() else None,
            msglog_path=str(case.msglog_path) if case.msglog_path.exists() else None,
            password_file=str(case.password_file) if case.password_file.exists() else None,
            export_dir=str(case.export_dir),
            list_dir=str(case.list_dir),
            has_case_file=case.case_file.exists(),
            has_case_dir=case.case_dir.exists(),
            has_message_log=case.msglog_path.exists(),
            has_password_file=case.password_file.exists(),
        )

    def open_case(self, case_ref: str) -> dict[str, Any]:
        snapshot = self.get_volume_snapshot_summary(case_ref)
        snapshot_count = snapshot.get("log_summary", {}).get("count", 0)
        snapshot_ready = snapshot_count > 0
        return {
            "case": self.case_summary(case_ref).model_dump(mode="json"),
            "evidence_sources": self.get_case_evidence_sources(case_ref),
            "messages": self.read_case_messages(case_ref, limit=20),
            "snapshot": snapshot,
            "snapshot_ready": snapshot_ready,
            "snapshot_hint": (
                None if snapshot_ready
                else "No snapshot found. Call ensure_snapshot(case_ref, scope='new') to create one before analysis."
            ),
            "exports": self.get_case_exports(case_ref),
            "offline_artifacts": self.get_offline_artifact_inventory(case_ref),
            "search_lists": self.list_search_terms(case_ref),
            "evidence_plan": self.get_evidence_plan(case_ref),
        }

    def get_case_evidence_sources(self, case_ref: str) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        if not case.case_file.exists():
            return {
                "case_name": case.name,
                "case_file": str(case.case_file),
                "exists": False,
                "evidence_objects": [],
            }
        data = case.case_file.read_bytes()
        decoded = data.decode("utf-16le", errors="ignore")
        seen: set[str] = set()
        evidence_objects: list[dict[str, Any]] = []
        for raw in re.findall(r"\[[^\]]+\]", decoded):
            value = raw.strip("[]").strip().replace("\x00", "")
            if not value or value in seen:
                continue
            if not re.search(r"\.[A-Za-z0-9]{2,4}$", value):
                continue
            seen.add(value)
            evidence_path = Path(value)
            evidence_objects.append(
                {
                    "path": value,
                    "exists": evidence_path.exists(),
                    "suffix": evidence_path.suffix,
                    "name": evidence_path.name,
                    "source": "xfc-utf16-string",
                }
            )
        session = self._load_analysis_session_manifest(case.name)
        if session and session.evidence_path not in seen:
            evidence_path = Path(session.evidence_path)
            evidence_objects.append(
                {
                    "path": session.evidence_path,
                    "exists": evidence_path.exists(),
                    "suffix": evidence_path.suffix,
                    "name": evidence_path.name,
                    "source": "analysis-session-manifest",
                }
            )
        return {
            "case_name": case.name,
            "case_file": str(case.case_file),
            "exists": True,
            "evidence_objects": evidence_objects,
        }

    def answer_legacy_qa(
        self,
        case_ref: str,
        questions: list[str],
    ) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        answers = [build_legacy_answer(question) for question in questions]
        answered = sum(1 for item in answers if item.get("status") == "answered")
        needs_live_validation = sum(
            1 for item in answers if item.get("status") == "needs_live_validation"
        )
        unmapped = sum(1 for item in answers if item.get("status") == "unmapped")
        return {
            "case_name": case.name,
            "case_file": str(case.case_file),
            "evidence_sources": self.get_case_evidence_sources(case.name),
            "summary": {
                "question_count": len(questions),
                "answered_count": answered,
                "needs_live_validation_count": needs_live_validation,
                "unmapped_count": unmapped,
            },
            "answers": answers,
            "notes": [
                "当前第一批能力基于公开 WP 归纳出的题库与证据提示。",
                "标记为 needs_live_validation 的题目存在公开答案冲突，后续应以检材原始证据为准。",
            ],
        }

    def plan_offline_qa(
        self,
        case_ref: str,
        questions: list[str],
    ) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        plans = [build_offline_question_plan(question) for question in questions]
        planned = sum(1 for item in plans if item.get("status") == "planned")
        unmapped = sum(1 for item in plans if item.get("status") == "unmapped")
        artifact_groups: list[str] = []
        for item in plans:
            for group in item.get("artifact_groups", []):
                if group not in artifact_groups:
                    artifact_groups.append(group)
        return {
            "case_name": case.name,
            "case_file": str(case.case_file),
            "evidence_sources": self.get_case_evidence_sources(case.name),
            "summary": {
                "question_count": len(questions),
                "planned_count": planned,
                "unmapped_count": unmapped,
                "artifact_groups": artifact_groups,
            },
            "plans": plans,
            "notes": [
                "这一步只做离线题目规划，不使用联网答案。",
                "后续每新增一个 artifact 提取器，就会直接挂到这些 artifact_groups 下。",
            ],
        }

    def get_offline_artifact_inventory(self, case_ref: str) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        payload = build_offline_artifact_inventory(case.export_dir)
        ready_kinds = payload.get("ready_kinds", [])
        known_kinds = payload.get("known_kinds", [])
        coverage = len(ready_kinds) / max(len(known_kinds), 1)
        return {
            "case_name": case.name,
            "export_dir": str(case.export_dir),
            **payload,
            "snapshot_hint": (
                f"Only {len(ready_kinds)}/{len(known_kinds)} artifact kinds available ({coverage:.0%}). "
                "Call ensure_snapshot(case_ref, scope='new') to populate missing data."
                if coverage < 0.3 else None
            ),
        }

    def answer_offline_qa(
        self,
        case_ref: str,
        questions: list[str],
    ) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        payload = build_offline_qa_answers(case.export_dir, questions)

        # 检查是否有 needs_artifacts 的问题，生成快照建议
        snapshot_hint: dict[str, Any] | None = None
        needs_count = payload.get("summary", {}).get("needs_artifacts_count", 0)
        if needs_count > 0:
            # 收集所有缺失的 export kinds
            missing_kinds: set[str] = set()
            for ans in payload.get("answers", []):
                if ans.get("status") == "needs_artifacts":
                    missing_kinds.update(ans.get("missing_export_kinds", []))
            snapshot_hint = {
                "recommendation": "Some questions need artifacts not yet available. Consider running ensure_snapshot to populate data.",
                "missing_export_kinds": sorted(missing_kinds),
                "suggested_action": "ensure_snapshot",
                "suggested_params": {"case_ref": case_ref, "scope": "new"},
            }

        return {
            "case_name": case.name,
            "case_file": str(case.case_file),
            "evidence_sources": self.get_case_evidence_sources(case.name),
            **payload,
            "snapshot_hint": snapshot_hint,
            "notes": [
                "这一路径只依赖本地案件、X-Ways 导出结果和离线解析逻辑，不使用联网答案源。",
                "如有缺失数据，可调用 ensure_snapshot(scope='new') 执行增量快照后重试。",
            ],
        }

    def create_case(
        self,
        case_name: str,
        *,
        overwrite_existing: bool = False,
        override: int | None = None,
        auto: bool = True,
    ) -> dict[str, Any]:
        self._ensure_xways_present()
        override_value = self._effective_override(override)
        base_name = Path(case_name).stem
        case_base = self._select_case_base_path(
            sanitize_filename(base_name),
            overwrite_existing=overwrite_existing,
        )
        desired_case = case_base.with_suffix(".xfc")
        before = {
            path.resolve()
            for path in self.config.cases_root.glob(f"{desired_case.stem}*.xfc")
        }
        cmd = self._build_new_case_command(
            case_base,
            override=override_value,
            auto=auto,
        )

        def after_run() -> dict[str, Any]:
            if overwrite_existing and desired_case.exists():
                actual_case = desired_case
            else:
                matches = [
                    path.resolve()
                    for path in self.config.cases_root.glob(f"{desired_case.stem}*.xfc")
                ]
                new_matches = [path for path in matches if path not in before]
                if not (new_matches or matches):
                    return {"requested_case_file": str(desired_case)}
                actual_case = max(new_matches or matches, key=lambda path: path.stat().st_mtime)
            actual_dir = actual_case.with_suffix("")
            return {
                "requested_case_file": str(desired_case),
                "actual_case_file": str(actual_case),
                "actual_case_name": actual_case.stem,
                "actual_case_dir": str(actual_dir),
            }

        return self._submit_process_job(
            action="create_case",
            description=f"Create case {base_name}",
            risk_level=RiskLevel.modifying,
            case_name=base_name,
            case_key=str(desired_case),
            command=cmd,
            log_paths=[
                self.config.global_msglog_path,
                desired_case.with_suffix("") / "!log" / "msglog.txt",
            ],
            initial_result={
                "requested_case_name": base_name,
                "requested_case_file": str(desired_case),
            },
            after_run=after_run,
        )

    def launch_xways_gui(self, case_ref: str | None = None) -> dict[str, Any]:
        self._ensure_xways_present()
        case: ResolvedCase | None = None
        command = [str(self.config.xways_exe)]
        if case_ref:
            case = self.resolve_case(case_ref)
            if case.case_file.exists():
                command.append(str(case.case_file))
            else:
                raise FileNotFoundError(f"未找到案件文件: {case.case_file}")
        process = subprocess.Popen(
            command,
            cwd=str(self.config.xways_exe.parent),
        )
        self._audit(
            "launch_xways_gui",
            {
                "case_name": case.name if case else None,
                "command_line": subprocess.list2cmdline(command),
                "pid": process.pid,
            },
        )
        return {
            "pid": process.pid,
            "visible": True,
            "case_name": case.name if case else None,
            "case_file": str(case.case_file) if case else None,
            "command_line": subprocess.list2cmdline(command),
        }

    def prepare_visual_analysis_session(
        self,
        request_text: str,
        *,
        force_reload_evidence: bool = False,
        override: int | None = None,
    ) -> dict[str, Any]:
        self._ensure_xways_present()
        parsed = self._parse_analysis_request(request_text)
        case_name = self._derive_analysis_case_name(
            parsed["drive"],
            parsed["evidence_label"],
        )
        case = self.resolve_case(case_name)
        override_value = self._effective_override(override)
        created_case = False
        session = self._load_analysis_session_manifest(case.name)
        existing_process = (
            self._find_xways_case_process(case.case_file)
            if case.case_file.exists()
            else None
        )
        if existing_process and session and not force_reload_evidence:
            return {
                "request_text": request_text,
                "case_name": case.name,
                "case_file": str(case.case_file),
                "case_dir": str(case.case_dir),
                "evidence_path": session.evidence_path,
                "drive": parsed["drive"],
                "evidence_label": parsed["evidence_label"],
                "created_case": False,
                "added_evidence_on_launch": False,
                "launch_reason": "already_open",
                "pid": existing_process["pid"],
                "visible": True,
                "command_line": existing_process["command_line"],
                "session_manifest_path": str(self._analysis_session_path(case.name)),
                "evidence_plan": self.get_evidence_plan(case.name),
                "notes": ["案件已在现有 X-Ways 窗口中打开，本次未再次启动新实例。"],
            }

        evidence_path = self._resolve_evidence_candidate(
            parsed["drive"],
            parsed["aliases"],
        )

        if not case.case_file.exists():
            create_command = self._build_new_case_command(
                case.case_dir,
                override=override_value,
                auto=True,
            )
            self._run_blocking_command(
                create_command,
                case_key=str(case.case_file),
            )
            created_case = True
            case = self.resolve_case(case_name)
            if not case.case_file.exists():
                raise RuntimeError(f"未能创建案件文件: {case.case_file}")

        session = self._load_analysis_session_manifest(case.name)
        should_add_evidence = force_reload_evidence or session is None
        launch_reason = "first_launch" if session is None else "resume_existing_case"
        previous_evidence_path = None
        if session is not None:
            previous_evidence_path = session.evidence_path
            try:
                previous_resolved = Path(session.evidence_path).expanduser().resolve()
            except OSError:
                previous_resolved = Path(session.evidence_path).expanduser()
            if previous_resolved != evidence_path:
                should_add_evidence = True
                launch_reason = "evidence_path_changed"
        if force_reload_evidence:
            launch_reason = "force_reload_evidence"
        existing_process = self._find_xways_case_process(case.case_file)
        if existing_process:
            if should_add_evidence:
                raise RuntimeError(
                    "该案件已经在另一个 X-Ways 进程中打开，无法再启动第二个实例去自动加载检材。"
                    "请先关闭当前案件窗口，再重新执行分析会话准备。"
                )
            self._audit(
                "prepare_visual_analysis_session_reuse_process",
                {
                    "request_text": request_text,
                    "case_name": case.name,
                    "pid": existing_process["pid"],
                    "command_line": existing_process["command_line"],
                },
            )
            return {
                "request_text": request_text,
                "case_name": case.name,
                "case_file": str(case.case_file),
                "case_dir": str(case.case_dir),
                "evidence_path": str(evidence_path),
                "drive": parsed["drive"],
                "evidence_label": parsed["evidence_label"],
                "created_case": created_case,
                "added_evidence_on_launch": False,
                "launch_reason": "already_open",
                "pid": existing_process["pid"],
                "visible": True,
                "command_line": existing_process["command_line"],
                "session_manifest_path": str(self._analysis_session_path(case.name)),
                "evidence_plan": self.get_evidence_plan(case.name),
                "notes": ["案件已在现有 X-Ways 窗口中打开，本次未再次启动新实例。"],
            }

        self.stage_evidence_plan(
            case.name,
            [
                {
                    "kind": "image",
                    "path": str(evidence_path),
                    "label": parsed["evidence_label"],
                    "include": True,
                    "note": f"Auto-staged from request: {request_text}",
                }
            ],
            replace=False,
            title=f"{parsed['drive']}\u76d8\u5206\u6790\u51c6\u5907",
            note=request_text,
        )

        launch_command = [str(self.config.xways_exe), str(case.case_file)]
        if should_add_evidence:
            if override_value is not None:
                launch_command.append(f"Override:{override_value}")
            launch_command.append(f"AddImage:{evidence_path}")
        process = subprocess.Popen(
            launch_command,
            cwd=str(self.config.xways_exe.parent),
        )

        now = datetime.now().isoformat()
        manifest = AnalysisSessionManifest(
            request_text=request_text,
            case_name=case.name,
            case_file=str(case.case_file),
            evidence_path=str(evidence_path),
            drive=parsed["drive"],
            evidence_label=parsed["evidence_label"],
            created_at=session.created_at if session else now,
            updated_at=now,
        )
        self._save_analysis_session_manifest(manifest)
        self._audit(
            "prepare_visual_analysis_session",
            {
                "request_text": request_text,
                "case_name": case.name,
                "evidence_path": str(evidence_path),
                "created_case": created_case,
                "should_add_evidence": should_add_evidence,
                "launch_reason": launch_reason,
                "command_line": subprocess.list2cmdline(launch_command),
                "pid": process.pid,
            },
        )
        notes: list[str] = []
        if created_case:
            notes.append("已为该检材创建新的 X-Ways 案件。")
        else:
            notes.append("复用了现有案件。")
        if should_add_evidence:
            notes.append("启动时会把匹配到的检材作为 AddImage 参数加载。")
        else:
            notes.append("检测到此前已为同一请求准备过会话，这次只重新打开案件窗口。")
        if previous_evidence_path and previous_evidence_path != str(evidence_path):
            notes.append(f"此前记录的检材路径为 {previous_evidence_path}，这次已切换到新的匹配路径。")
        return {
            "request_text": request_text,
            "case_name": case.name,
            "case_file": str(case.case_file),
            "case_dir": str(case.case_dir),
            "evidence_path": str(evidence_path),
            "drive": parsed["drive"],
            "evidence_label": parsed["evidence_label"],
            "created_case": created_case,
            "added_evidence_on_launch": should_add_evidence,
            "launch_reason": launch_reason,
            "pid": process.pid,
            "visible": True,
            "command_line": subprocess.list2cmdline(launch_command),
            "session_manifest_path": str(self._analysis_session_path(case.name)),
            "evidence_plan": self.get_evidence_plan(case.name),
            "notes": notes,
        }

    def add_image(
        self,
        case_ref: str,
        image_path: str,
        *,
        force_as: str | None = None,
        sector_size: int | None = None,
        override: int | None = None,
        auto: bool = True,
    ) -> dict[str, Any]:
        case = self._require_case_file(case_ref)
        if sector_size is not None and not force_as:
            raise ValueError("sector_size 只有在 force_as='P' 或 'V' 时才能使用。")
        self._assert_path_or_glob_exists(image_path)
        sub = ""
        if force_as:
            force_mode = force_as.upper().strip()
            if force_mode not in {"P", "V"}:
                raise ValueError("force_as 只能是 'P' 或 'V'。")
            sub = f"#{force_mode}"
            if sector_size is not None:
                sub += f",{sector_size}"
            sub += "#"
        cmd = self._build_command(
            case_file=case.case_file,
            params=[f"AddImage:{sub}{image_path}"],
            override=self._effective_override(override),
            auto=auto,
        )
        return self._submit_process_job(
            action="add_image",
            description=f"Add image to case {case.name}",
            risk_level=RiskLevel.modifying,
            case_name=case.name,
            case_key=str(case.case_file),
            command=cmd,
            log_paths=[case.msglog_path, self.config.global_msglog_path],
            initial_result={"case_name": case.name, "image_path": image_path},
        )

    def add_dir(
        self,
        case_ref: str,
        directory_path: str,
        *,
        override: int | None = None,
        auto: bool = True,
    ) -> dict[str, Any]:
        case = self._require_case_file(case_ref)
        self._assert_path_or_glob_exists(directory_path)
        cmd = self._build_command(
            case_file=case.case_file,
            params=[f"AddDir:{directory_path}"],
            override=self._effective_override(override),
            auto=auto,
        )
        return self._submit_process_job(
            action="add_dir",
            description=f"Add directory to case {case.name}",
            risk_level=RiskLevel.modifying,
            case_name=case.name,
            case_key=str(case.case_file),
            command=cmd,
            log_paths=[case.msglog_path, self.config.global_msglog_path],
            initial_result={"case_name": case.name, "directory_path": directory_path},
        )

    def load_search_terms(
        self,
        case_ref: str,
        list_name: str,
        terms: list[str],
        *,
        overwrite_existing: bool = False,
    ) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        case.list_dir.mkdir(parents=True, exist_ok=True)
        safe_name = sanitize_filename(Path(list_name).stem)
        path = case.list_dir / f"{safe_name}.lst"
        if path.exists() and not overwrite_existing:
            raise FileExistsError(f"搜索词文件已存在: {path}")
        normalized_terms = [term.strip() for term in terms if term.strip()]
        if not normalized_terms:
            raise ValueError("至少需要一个搜索词。")
        path.write_text(
            "\r\n".join(normalized_terms) + "\r\n",
            encoding="utf-8-sig",
            newline="",
        )
        manifest = SearchListManifest(
            case_name=case.name,
            list_name=safe_name,
            path=str(path),
            term_count=len(normalized_terms),
            encoding="utf-8-sig",
        )
        self._audit(
            "load_search_terms",
            {
                "case_name": case.name,
                "path": str(path),
                "term_count": len(normalized_terms),
            },
        )
        return {
            "manifest": manifest.model_dump(mode="json"),
            "terms_preview": normalized_terms[:20],
        }

    def stage_evidence_plan(
        self,
        case_ref: str,
        entries: list[dict[str, Any]],
        *,
        replace: bool = False,
        title: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        case_name = self.resolve_case(case_ref).name
        now = datetime.now().isoformat()
        plan_path = self._evidence_plan_path(case_name)
        existing = self._load_evidence_plan_model(case_name)

        normalized_entries = [self._normalize_evidence_entry(item) for item in entries]
        if replace or existing is None:
            merged_entries = normalized_entries
            created_at = existing.created_at if existing else now
        else:
            merged_entries = list(existing.entries)
            merged_entries = self._merge_evidence_entries(merged_entries, normalized_entries)
            created_at = existing.created_at

        plan = EvidencePlan(
            case_name=case_name,
            plan_path=str(plan_path),
            created_at=created_at,
            updated_at=now,
            title=title if title is not None else (existing.title if existing else None),
            note=note if note is not None else (existing.note if existing else None),
            entries=merged_entries,
        )
        plan_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
        self._audit(
            "stage_evidence_plan",
            {
                "case_name": case_name,
                "plan_path": str(plan_path),
                "entry_count": len(plan.entries),
                "replace": replace,
            },
        )
        return self._evidence_plan_payload(plan)

    def prepare_case_bridge(
        self,
        case_ref: str,
        *,
        overwrite_existing: bool = False,
    ) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        case.export_dir.mkdir(parents=True, exist_ok=True)
        raw_dir = case.export_dir / "raw"
        inbox_dir = case.export_dir / "inbox"
        schema_dir = case.export_dir / "schemas"
        raw_dir.mkdir(parents=True, exist_ok=True)
        inbox_dir.mkdir(parents=True, exist_ok=True)
        schema_dir.mkdir(parents=True, exist_ok=True)

        created: list[str] = []
        skipped: list[str] = []
        for name in (
            "search-hits.schema.json",
            "encrypted-files.schema.json",
            "volume-snapshot.schema.json",
            "registry-system.schema.json",
            "event-logs-system.schema.json",
            "installed-software.schema.json",
            "registry-devices.schema.json",
            "sunlogin-logs.schema.json",
        ):
            src = self.config.templates_dir / "schemas" / name
            dst = schema_dir / name
            self._copy_if_allowed(src, dst, overwrite_existing, created, skipped)

        guide_path = case.export_dir / "README.md"
        guide_text = self._render_bridge_guide(case)
        if guide_path.exists() and not overwrite_existing:
            skipped.append(str(guide_path))
        else:
            guide_path.write_text(guide_text, encoding="utf-8")
            created.append(str(guide_path))

        manifest_path = case.export_dir / "bridge-manifest.json"
        manifest = {
            "case_name": case.name,
            "case_file": str(case.case_file) if case.case_file.exists() else None,
            "case_dir": str(case.case_dir) if case.case_dir.exists() else None,
            "export_dir": str(case.export_dir),
            "inbox_dir": str(inbox_dir),
            "raw_dir": str(raw_dir),
            "schema_dir": str(schema_dir),
            "expected_outputs": {
                "search_hits": "search-hits-*.jsonl",
                "encrypted_files": "encrypted-files-*.jsonl",
                "volume_snapshot": "volume-snapshot-*.jsonl",
                "registry_system": "registry-system-*.jsonl",
                "event_logs_system": "event-logs-system-*.jsonl",
                "installed_software": "installed-software-*.jsonl",
                "registry_devices": "registry-devices-*.jsonl",
                "sunlogin_logs": "sunlogin-logs-*.jsonl",
            },
        }
        if manifest_path.exists() and not overwrite_existing:
            skipped.append(str(manifest_path))
        else:
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            created.append(str(manifest_path))

        self._audit(
            "prepare_case_bridge",
            {"case_name": case.name, "export_dir": str(case.export_dir)},
        )
        return {
            "case_name": case.name,
            "export_dir": str(case.export_dir),
            "created_files": created,
            "skipped_files": skipped,
            "manifest": manifest,
        }

    def ingest_export_file(
        self,
        case_ref: str,
        kind: str,
        source_path: str,
        *,
        copy_source: bool = True,
        title: str | None = None,
    ) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        prefix_map = {
            "search_hits": "search-hits",
            "encrypted_files": "encrypted-files",
            "volume_snapshot": "volume-snapshot",
            "registry_system": "registry-system",
            "event_logs_system": "event-logs-system",
            "installed_software": "installed-software",
            "registry_devices": "registry-devices",
            "sunlogin_logs": "sunlogin-logs",
        }
        if kind not in prefix_map:
            raise ValueError(
                "kind 只能是 search_hits / encrypted_files / volume_snapshot / "
                "registry_system / event_logs_system / installed_software / "
                "registry_devices / sunlogin_logs。"
            )
        source = Path(source_path).expanduser()
        if not source.exists() or not source.is_file():
            raise FileNotFoundError(f"未找到导出文件: {source}")

        case.export_dir.mkdir(parents=True, exist_ok=True)
        raw_dir = case.export_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        records = load_table_file(source, limit=200000)
        if not records and kind == "sunlogin_logs":
            records = [
                {"line": line, "_source_file": str(source)}
                for line in read_text_auto(source).splitlines()
                if line.strip()
            ]
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        label = sanitize_filename(title or source.stem)
        canonical_name = f"{prefix_map[kind]}-{timestamp}-{label}.jsonl"
        canonical_path = case.export_dir / canonical_name
        with canonical_path.open("w", encoding="utf-8", newline="") as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")

        raw_copy_path: Path | None = None
        if copy_source:
            raw_copy_path = raw_dir / f"{timestamp}-{sanitize_filename(source.name)}"
            shutil.copy2(source, raw_copy_path)

        self._audit(
            "ingest_export_file",
            {
                "case_name": case.name,
                "kind": kind,
                "source_path": str(source),
                "canonical_path": str(canonical_path),
                "record_count": len(records),
            },
        )
        return {
            "case_name": case.name,
            "kind": kind,
            "source_path": str(source),
            "raw_copy_path": str(raw_copy_path) if raw_copy_path else None,
            "canonical_path": str(canonical_path),
            "record_count": len(records),
            "notes": (
                []
                if records
                else [
                    "没有从源文件中解析出结构化记录，请确认导出格式是否为 CSV/TSV/HTML/TXT/JSON/JSONL。"
                ]
            ),
        }

    def run_rvs(
        self,
        case_ref: str,
        *,
        scope: str = "new",
        search_list_name: str | None = None,
        search_list_path: str | None = None,
        override: int | None = None,
        auto: bool = True,
    ) -> dict[str, Any]:
        case = self._require_case_file(case_ref)
        if scope not in {"new", "all"}:
            raise ValueError("scope 只能是 'new' 或 'all'。")
        rvs_cmd = "RVS:~+" if scope == "new" else "RVS:~"
        params: list[str] = []
        list_path: Path | None = None
        if search_list_name and search_list_path:
            raise ValueError("search_list_name 和 search_list_path 只能传一个。")
        if search_list_name:
            list_path = case.list_dir / f"{sanitize_filename(Path(search_list_name).stem)}.lst"
        elif search_list_path:
            list_path = Path(search_list_path).expanduser()
        if list_path is not None:
            if not list_path.exists():
                raise FileNotFoundError(f"未找到搜索词文件: {list_path}")
            params.append(f"LST:{list_path}")
        params.append(rvs_cmd)
        cmd = self._build_command(
            case_file=case.case_file,
            params=params,
            override=self._effective_override(override),
            auto=auto,
        )
        return self._submit_process_job(
            action="run_rvs",
            description=f"Run {rvs_cmd} for case {case.name}",
            risk_level=RiskLevel.modifying,
            case_name=case.name,
            case_key=str(case.case_file),
            command=cmd,
            log_paths=[case.msglog_path, self.config.global_msglog_path],
            initial_result={
                "case_name": case.name,
                "scope": scope,
                "search_list_path": str(list_path) if list_path else None,
            },
        )

    def run_whs_script(
        self,
        script_path: str,
        *,
        case_ref: str | None = None,
        override: int | None = None,
        auto: bool = True,
    ) -> dict[str, Any]:
        self._ensure_xways_present()
        resolved_script = self._resolve_script_path(script_path)
        if not resolved_script.exists():
            raise FileNotFoundError(f"未找到脚本: {resolved_script}")
        case: ResolvedCase | None = None
        if case_ref:
            case = self.resolve_case(case_ref)
        cmd = self._build_command(
            case_file=case.case_file if case and case.case_file.exists() else None,
            params=[str(resolved_script)],
            override=self._effective_override(override),
            auto=auto,
        )
        return self._submit_process_job(
            action="run_whs_script",
            description=f"Run WHS script {resolved_script.name}",
            risk_level=RiskLevel.modifying,
            case_name=case.name if case else None,
            case_key=str(case.case_file) if case and case.case_file.exists() else None,
            command=cmd,
            log_paths=[*( [case.msglog_path] if case else [] ), self.config.global_msglog_path],
            initial_result={
                "case_name": case.name if case else None,
                "script_path": str(resolved_script),
            },
        )

    def get_job_status(self, job_id: str) -> dict[str, Any]:
        return self._load_job(job_id).model_dump(mode="json")

    def read_case_activity_log(self, case_ref: str) -> str:
        case = self.resolve_case(case_ref)
        if not case.msglog_path.exists():
            raise FileNotFoundError(f"未找到案件日志: {case.msglog_path}")
        return read_text_auto(case.msglog_path)

    def read_case_messages(
        self, case_ref: str, *, limit: int = 100, contains: str | None = None
    ) -> dict[str, Any]:
        entries = filter_messages(
            self._parse_case_messages(case_ref),
            contains=contains,
            limit=limit,
        )
        return {
            "case_name": self.resolve_case(case_ref).name,
            "count": len(entries),
            "messages": entries,
        }

    def read_password_dictionary(self, case_ref: str, *, limit: int = 500) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        if not case.password_file.exists():
            return {
                "case_name": case.name,
                "password_file": str(case.password_file),
                "count": 0,
                "passwords": [],
            }
        passwords = [
            line.strip()
            for line in read_text_auto(case.password_file).splitlines()
            if line.strip()
        ]
        return {
            "case_name": case.name,
            "password_file": str(case.password_file),
            "count": len(passwords),
            "passwords": passwords[:limit],
        }

    def get_evidence_plan(self, case_ref: str) -> dict[str, Any]:
        case_name = self.resolve_case(case_ref).name
        plan = self._load_evidence_plan_model(case_name)
        if plan is None:
            return {
                "case_name": case_name,
                "plan_path": str(self._evidence_plan_path(case_name)),
                "exists": False,
                "title": None,
                "note": None,
                "entry_count": 0,
                "included_count": 0,
                "entries": [],
            }
        return self._evidence_plan_payload(plan)

    def get_case_exports(self, case_ref: str) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        return {
            "case_name": case.name,
            "export_dir": str(case.export_dir),
            "files": inventory_files(case.export_dir, limit=500),
            "offline_artifacts": self.get_offline_artifact_inventory(case.name),
        }

    def list_search_terms(self, case_ref: str) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        return {
            "case_name": case.name,
            "list_dir": str(case.list_dir),
            "files": inventory_files(case.list_dir, limit=200) if case.list_dir.exists() else [],
        }

    def get_volume_snapshot_summary(self, case_ref: str) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        messages = self._parse_case_messages(case_ref)
        log_summary = extract_snapshot_summary(messages)
        export_records, export_files = load_export_records(case.export_dir, "snapshot", limit=200)
        return {
            "case_name": case.name,
            "log_summary": log_summary,
            "export_files": export_files,
            "export_records_preview": export_records[:50],
        }

    def ensure_snapshot(
        self,
        case_ref: str,
        *,
        scope: str = "new",
        force: bool = False,
        override: int | None = None,
        auto: bool = True,
    ) -> dict[str, Any]:
        """按需执行磁盘快照。

        经济高效策略:
        - 默认 scope='new' (RVS:~+) 只处理新增项，避免全量重跑
        - 先检查是否已有快照，如有且 force=False 则跳过
        - 返回快照状态和建议
        """
        case = self._require_case_file(case_ref)
        snapshot_summary = self.get_volume_snapshot_summary(case_ref)
        log_summary = snapshot_summary.get("log_summary", {})
        existing_count = log_summary.get("count", 0)
        latest = log_summary.get("latest")

        # 已有快照且不强制 → 跳过执行，返回现有状态
        if existing_count > 0 and not force:
            return {
                "case_name": case.name,
                "action": "skipped",
                "reason": f"Snapshot already exists ({existing_count} snapshot(s) found). Use force=true to re-run.",
                "existing_snapshot": latest,
                "snapshot_summary": snapshot_summary,
            }

        # 容量评估：若目标检材超过 50GB，预估初始扫描超 40 分钟，进行拦截询问
        plan = self.get_evidence_plan(case_ref)
        if existing_count == 0 and not force:
            total_size_bytes = 0
            from pathlib import Path
            for entry in plan.get("entries", []):
                if entry.get("include", True):
                    p = Path(entry.get("path", ""))
                    if p.exists() and p.is_file():
                        total_size_bytes += p.stat().st_size
            
            # 50GB 阈值 (50 * 1024 * 1024 * 1024)
            if total_size_bytes > 53687091200:
                size_gb = total_size_bytes / 1073741824
                return {
                    "case_name": case.name,
                    "action": "needs_confirmation",
                    "reason": f"目标检材源文件尺寸庞大（约 {size_gb:.1f} GB），首次带参数 RVS:~+ 进行全面深度解析（递归压缩包与图片解析等）时可能超过 40 分钟。请确认是否强制挂机扫全盘，如确认请附加 force=true 参数重试，或尝试使用 WHS 小脚本局部提取。",
                    "existing_snapshot": None,
                    "snapshot_summary": snapshot_summary,
                }

        # 执行 RVS
        rvs_result = self.run_rvs(
            case_ref,
            scope=scope,
            override=override,
            auto=auto,
        )
        return {
            "case_name": case.name,
            "action": "executed",
            "scope": scope,
            "rvs_command": "RVS:~+" if scope == "new" else "RVS:~",
            "rvs_result": rvs_result,
            "notes": [
                f"Scope '{scope}': {'Only new/changed items (economic)' if scope == 'new' else 'Full re-scan (thorough)'}.",
                "Use get_volume_snapshot_summary to check progress after job completes.",
                "Use get_job_status to check if the RVS job is still running.",
            ],
        }

    def get_string_search_matches(
        self,
        case_ref: str,
        *,
        search_term: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        export_records, export_files = load_export_records(
            case.export_dir, "search_hits", limit=max(limit, 100)
        )
        if search_term:
            needle = search_term.lower()
            export_records = [
                record
                for record in export_records
                if needle in json.dumps(record, ensure_ascii=False).lower()
            ]
        if export_records:
            return {
                "case_name": case.name,
                "source": "export",
                "search_term": search_term,
                "export_files": export_files,
                "matches": export_records[:limit],
                "count": len(export_records[:limit]),
                "notes": [],
            }
        message_results = extract_search_messages(
            self._parse_case_messages(case_ref), search_term=search_term
        )
        return {
            "case_name": case.name,
            "source": "messages" if message_results else "unavailable",
            "search_term": search_term,
            "export_files": export_files,
            "matches": [],
            "summaries": message_results[:limit],
            "count": len(message_results[:limit]),
            "notes": [
                "未发现结构化 search-hits 导出文件。",
                f"可将命中结果导出到 {case.export_dir} 下的 search-hits*.json/jsonl/csv/tsv。",
            ],
        }

    def find_encrypted_files(
        self,
        case_ref: str,
        *,
        limit: int = 100,
        mode: str = "auto",
    ) -> dict[str, Any]:
        case = self.resolve_case(case_ref)
        if mode not in {"auto", "authoritative", "candidates"}:
            raise ValueError("mode 只能是 auto / authoritative / candidates。")
        export_records, export_files = load_export_records(
            case.export_dir, "encrypted_files", limit=max(limit, 100)
        )
        if export_records and mode in {"auto", "authoritative"}:
            return {
                "case_name": case.name,
                "source": "export",
                "export_files": export_files,
                "records": export_records[:limit],
                "count": len(export_records[:limit]),
                "notes": [],
            }
        message_records = extract_encrypted_messages(self._parse_case_messages(case_ref))
        if message_records and mode in {"auto", "authoritative"}:
            return {
                "case_name": case.name,
                "source": "messages",
                "export_files": export_files,
                "records": message_records[:limit],
                "count": len(message_records[:limit]),
                "notes": ["当前结果来自消息日志，而不是结构化导出。"],
            }

        candidates: list[dict[str, Any]] = []
        if case.case_dir.exists():
            for names_file in sorted(case.case_dir.rglob("Names")):
                names = extract_names_from_file(names_file, limit=3000)
                candidates.extend(
                    build_encrypted_candidates(
                        names,
                        source_file=str(names_file),
                        limit=max(limit - len(candidates), 0),
                    )
                )
                if len(candidates) >= limit:
                    break
        return {
            "case_name": case.name,
            "source": "names-heuristic",
            "export_files": export_files,
            "records": candidates[:limit],
            "count": len(candidates[:limit]),
            "notes": [
                "当前结果是基于 Names 文件的启发式候选，不等同于 X-Ways 内部的加密识别结果。",
                f"如需更可靠结果，可导出 encrypted-files*.json/jsonl/csv/tsv 到 {case.export_dir}。",
            ],
        }

    def resolve_case(self, case_ref: str) -> ResolvedCase:
        raw = Path(case_ref)
        if raw.suffix.lower() == ".xfc":
            case_file = raw.expanduser()
            if not case_file.is_absolute():
                case_file = (self.config.cases_root / case_file.name).resolve()
            case_name = case_file.stem
            case_dir = case_file.with_suffix("")
        elif raw.exists() and raw.is_dir():
            case_dir = raw.resolve()
            case_name = case_dir.name
            case_file = (case_dir.parent / f"{case_name}.xfc").resolve()
        else:
            case_name = Path(case_ref).stem
            case_file = (self.config.cases_root / f"{case_name}.xfc").resolve()
            case_dir = (self.config.cases_root / case_name).resolve()
        return ResolvedCase(
            name=case_name,
            case_file=case_file,
            case_dir=case_dir,
            msglog_path=case_dir / "!log" / "msglog.txt",
            password_file=case_dir / "Passwords.txt",
            export_dir=self.config.exports_dir / case_name,
            list_dir=self.config.lists_dir / case_name,
        )

    def _submit_process_job(
        self,
        *,
        action: str,
        description: str,
        risk_level: RiskLevel,
        command: list[str],
        log_paths: list[Path],
        initial_result: dict[str, Any],
        case_name: str | None = None,
        case_key: str | None = None,
        after_run: Callable[[], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if case_key and risk_level == RiskLevel.modifying:
            self._assert_case_idle(case_key)

        job_id = uuid.uuid4().hex[:12]
        stdout_path = self.config.jobs_dir / f"{job_id}.stdout.log"
        stderr_path = self.config.jobs_dir / f"{job_id}.stderr.log"
        job = JobRecord(
            job_id=job_id,
            action=action,
            description=description,
            status=JobStatus.queued,
            risk_level=risk_level,
            created_at=datetime.now().isoformat(),
            case_name=case_name,
            case_file=case_key,
            command=command,
            command_line=subprocess.list2cmdline(command),
            working_directory=str(self.config.xways_exe.parent),
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            log_paths=[str(path) for path in log_paths],
            result=initial_result,
        )
        self._save_job(job)
        self._audit(
            action,
            {
                "job_id": job_id,
                "case_name": case_name,
                "command_line": job.command_line,
                "risk_level": risk_level.value,
            },
        )

        thread = threading.Thread(
            target=self._run_process_job,
            args=(job_id, case_key, after_run),
            daemon=True,
            name=f"xwf-job-{job_id}",
        )
        thread.start()
        return {
            "job_id": job_id,
            "status": job.status.value,
            "action": action,
            "case_name": case_name,
            "command_line": job.command_line,
        }

    def _run_process_job(
        self,
        job_id: str,
        case_key: str | None,
        after_run: Callable[[], dict[str, Any]] | None,
    ) -> None:
        case_lock = self._case_lock(case_key) if case_key else None
        if case_lock:
            case_lock.acquire()
        try:
            job = self._load_job(job_id).model_copy(
                update={"status": JobStatus.running, "started_at": datetime.now().isoformat()}
            )
            self._save_job(job)
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            with open(job.stdout_path, "wb") as stdout_handle, open(
                job.stderr_path, "wb"
            ) as stderr_handle:
                process = subprocess.Popen(
                    job.command,
                    cwd=job.working_directory,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    creationflags=creationflags,
                )
                while True:
                    return_code = process.poll()
                    progress = self._build_progress(self._load_job(job_id))
                    if progress:
                        self._save_job(self._load_job(job_id).model_copy(update=progress))
                    if return_code is not None:
                        break
                    time.sleep(self.config.poll_interval_seconds)
            result = dict(self._load_job(job_id).result)
            if after_run:
                try:
                    result.update(after_run())
                except Exception as exc:
                    result["post_process_error"] = str(exc)
            final_progress = self._build_progress(self._load_job(job_id))
            final_job = self._load_job(job_id).model_copy(
                update={
                    "status": JobStatus.succeeded if return_code == 0 else JobStatus.failed,
                    "finished_at": datetime.now().isoformat(),
                    "exit_code": return_code,
                    "result": result,
                    **final_progress,
                }
            )
            self._save_job(final_job)
        except Exception as exc:
            failed_job = self._load_job(job_id).model_copy(
                update={
                    "status": JobStatus.failed,
                    "finished_at": datetime.now().isoformat(),
                    "error": str(exc),
                }
            )
            self._save_job(failed_job)
        finally:
            if case_lock:
                case_lock.release()

    def _build_progress(self, job: JobRecord) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        for path_text in job.log_paths:
            path = Path(path_text)
            if not path.exists():
                continue
            try:
                messages = parse_msglog(read_text_auto(path))
            except OSError:
                continue
            if messages:
                break
        if not messages:
            return {}
        started_at = job.started_at or job.created_at
        relevant = [
            entry
            for entry in messages
            if not entry.get("timestamp") or entry["timestamp"] >= started_at
        ]
        if not relevant:
            relevant = messages[-20:]
        tail = [
            entry.get("message", "")
            for entry in relevant[-10:]
            if entry.get("message", "").strip()
        ]
        return {
            "progress_message": tail[-1] if tail else None,
            "progress_log_tail": tail,
        }

    def _save_job(self, job: JobRecord) -> None:
        with self._jobs_lock:
            path = self.config.jobs_dir / f"{job.job_id}.json"
            path.write_text(job.model_dump_json(indent=2), encoding="utf-8")

    def _load_job(self, job_id: str) -> JobRecord:
        path = self.config.jobs_dir / f"{job_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"未找到 job: {job_id}")
        return JobRecord.model_validate_json(path.read_text(encoding="utf-8"))

    def _recover_jobs(self) -> None:
        for path in self.config.jobs_dir.glob("*.json"):
            try:
                job = JobRecord.model_validate_json(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if job.status in {JobStatus.queued, JobStatus.running}:
                recovered = job.model_copy(
                    update={
                        "status": JobStatus.orphaned,
                        "finished_at": datetime.now().isoformat(),
                        "error": "Server restarted before the previous process state could be recovered.",
                    }
                )
                path.write_text(recovered.model_dump_json(indent=2), encoding="utf-8")

    def _assert_case_idle(self, case_key: str) -> None:
        if self._case_lock(case_key).locked():
            raise RuntimeError(f"案件当前有运行中的写任务: {case_key}")
        for path in self.config.jobs_dir.glob("*.json"):
            try:
                job = JobRecord.model_validate_json(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if (
                job.case_file == case_key
                and job.status in {JobStatus.queued, JobStatus.running}
            ):
                raise RuntimeError(
                    f"案件当前已有 job {job.job_id} 正在运行，不能并发写入。"
                )
        existing_process = self._find_xways_case_process(Path(case_key))
        if existing_process:
            raise RuntimeError(
                "案件当前已在可见的 X-Ways 进程中打开。"
                "为避免重复弹窗或案件锁冲突，请先在现有窗口里完成操作，"
                "或者先关闭该窗口，再通过 MCP 发起修改型任务。"
            )

    def _case_lock(self, case_key: str) -> threading.Lock:
        if case_key not in self._case_locks:
            self._case_locks[case_key] = threading.Lock()
        return self._case_locks[case_key]

    def _audit(self, action: str, payload: dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "payload": payload,
        }
        with self.config.audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _list_xways_processes(self) -> list[dict[str, Any]]:
        script = (
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
            "$OutputEncoding = [Console]::OutputEncoding; "
            "Get-CimInstance Win32_Process | "
            "Where-Object { $_.Name -eq 'xwforensics64.exe' } | "
            "Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress"
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if completed.returncode != 0:
            return []
        payload = completed.stdout.strip()
        if not payload:
            return []
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return []
        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
        return []

    def _find_xways_case_process(self, case_file: Path) -> dict[str, Any] | None:
        case_text = str(case_file).lower()
        case_name = case_file.name.lower()
        for process in self._list_xways_processes():
            command_line = str(process.get("CommandLine") or "")
            lower_command = command_line.lower()
            if case_text in lower_command or case_name in lower_command:
                return {
                    "pid": int(process.get("ProcessId")),
                    "command_line": command_line,
                }
        return None

    def _build_command(
        self,
        *,
        case_file: Path | None,
        params: list[str],
        override: int | None,
        auto: bool,
    ) -> list[str]:
        self._ensure_xways_present()
        command = [str(self.config.xways_exe)]
        if case_file is not None:
            command.append(str(case_file))
        if override is not None:
            command.append(f"Override:{override}")
        command.extend(params)
        if auto:
            command.append("auto")
        return command

    def _build_new_case_command(
        self,
        case_base: Path,
        *,
        override: int | None,
        auto: bool,
    ) -> list[str]:
        self._ensure_xways_present()
        command = [str(self.config.xways_exe), f"NewCase:{case_base}"]
        if override is not None:
            command.append(f"Override:{override}")
        if auto:
            command.append("auto")
        return command

    def _effective_override(self, override: int | None) -> int | None:
        return self.config.default_override if override is None else override

    def _resolve_script_path(self, script_path: str) -> Path:
        candidate = Path(script_path).expanduser()
        if candidate.exists():
            return candidate.resolve()
        in_scripts = self.config.scripts_dir / script_path
        if in_scripts.exists():
            return in_scripts.resolve()
        in_project = self.config.project_root / script_path
        if in_project.exists():
            return in_project.resolve()
        return candidate.resolve()

    def _require_case_file(self, case_ref: str) -> ResolvedCase:
        case = self.resolve_case(case_ref)
        if not case.case_file.exists():
            raise FileNotFoundError(f"未找到案件文件: {case.case_file}")
        return case

    def _parse_case_messages(self, case_ref: str) -> list[dict[str, Any]]:
        case = self.resolve_case(case_ref)
        if not case.msglog_path.exists():
            return []
        return parse_msglog(read_text_auto(case.msglog_path))

    def _ensure_xways_present(self) -> None:
        if not self.config.xways_exe.exists():
            raise FileNotFoundError(
                f"未找到 X-Ways 可执行文件，请设置 XWF_XWAYS_EXE。当前值: {self.config.xways_exe}"
            )

    def _assert_path_or_glob_exists(self, value: str) -> None:
        if "*" in value or "?" in value:
            return
        path = Path(value).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"未找到路径: {path}")

    def _evidence_plan_path(self, case_name: str) -> Path:
        return self.config.plans_dir / f"{sanitize_filename(case_name)}.evidence-plan.json"

    def _select_case_base_path(self, safe_base_name: str, *, overwrite_existing: bool) -> Path:
        base = self.config.cases_root / safe_base_name
        if overwrite_existing or not self._case_base_exists(base):
            return base
        index = 2
        while True:
            candidate = self.config.cases_root / f"{safe_base_name}_{index}"
            if not self._case_base_exists(candidate):
                return candidate
            index += 1

    def _case_base_exists(self, case_base: Path) -> bool:
        return case_base.exists() or case_base.with_suffix(".xfc").exists()

    def _analysis_session_path(self, case_name: str) -> Path:
        return self.config.sessions_dir / f"{sanitize_filename(case_name)}.analysis-session.json"

    def _load_analysis_session_manifest(
        self, case_name: str
    ) -> AnalysisSessionManifest | None:
        path = self._analysis_session_path(case_name)
        if not path.exists():
            return None
        return AnalysisSessionManifest.model_validate_json(path.read_text(encoding="utf-8"))

    def _save_analysis_session_manifest(self, manifest: AnalysisSessionManifest) -> None:
        path = self._analysis_session_path(manifest.case_name)
        path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    def _parse_analysis_request(self, request_text: str) -> dict[str, Any]:
        text = request_text.strip()
        if not text:
            raise ValueError("request_text cannot be empty.")
        drive_match = re.search(r"([A-Za-z])\s*:", text)
        if drive_match is None:
            drive_match = re.search(r"(?<![A-Za-z0-9])([A-Za-z])(?=\s*[^A-Za-z0-9\s])", text)
        if drive_match is None:
            raise ValueError("Could not infer the target drive letter from the request.")
        drive = drive_match.group(1).upper()

        numbers = re.findall(r"(\d+)", text)
        if not numbers:
            raise ValueError("Could not infer the evidence index from the request.")
        index = numbers[-1]
        short_label = f"\u68c0\u6750{index}"
        full_label = f"\u8ba1\u7b97\u673a\u68c0\u6750{index}"
        return {
            "drive": drive,
            "evidence_index": index,
            "evidence_label": full_label,
            "aliases": [full_label, short_label, f"{short_label}.E01"],
        }

    def _derive_analysis_case_name(self, drive: str, evidence_label: str) -> str:
        return f"{drive}\u76d8_{evidence_label}"

    def _resolve_evidence_candidate(self, drive: str, aliases: list[str]) -> Path:
        root = Path(f"{drive}:\\")
        if not root.exists():
            raise FileNotFoundError(f"未找到 {drive}: 盘，请确认检材磁盘已挂载。")
        candidates = [path for path in root.iterdir() if path.is_file()]
        if not candidates:
            raise FileNotFoundError(f"{root} 下没有发现可加载的检材文件。")

        alias_set = {alias.lower() for alias in aliases if alias}
        short_number_match = re.search(r"(\d+)", aliases[0]) if aliases else None
        short_number = short_number_match.group(1) if short_number_match else None
        scored: list[tuple[int, Path]] = []
        for path in candidates:
            lower_name = path.name.lower()
            score = 0
            if lower_name in alias_set:
                score += 100
            stem_lower = path.stem.lower()
            for alias in alias_set:
                alias_stem = Path(alias).stem.lower()
                if alias_stem and alias_stem == stem_lower:
                    score += 90
                elif alias_stem and alias_stem in stem_lower:
                    score += 60
                elif alias and alias in lower_name:
                    score += 50
            if short_number and short_number in stem_lower:
                score += 20
            suffix = path.suffix.lower()
            if suffix in {".e01", ".ex01"}:
                score += 40
            elif suffix in {".001", ".dd", ".img", ".raw", ".ad1"}:
                score += 30
            elif suffix in {".tar", ".rar", ".zip", ".7z"}:
                score += 5
            if score > 0:
                scored.append((score, path.resolve()))

        if not scored:
            target = aliases[1] if len(aliases) > 1 else aliases[0]
            raise FileNotFoundError(f"在 {root} 根目录下没有找到与 {target} 匹配的检材文件。")
        scored.sort(
            key=lambda item: (
                item[0],
                item[1].suffix.lower() == ".e01",
                item[1].name.lower(),
            ),
            reverse=True,
        )
        return scored[0][1]

    def _run_blocking_command(
        self,
        command: list[str],
        *,
        case_key: str | None = None,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        if case_key:
            self._assert_case_idle(case_key)
        case_lock = self._case_lock(case_key) if case_key else None
        if case_lock:
            case_lock.acquire()
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            completed = subprocess.run(
                command,
                cwd=str(self.config.xways_exe.parent),
                capture_output=True,
                timeout=timeout_seconds or self.config.default_timeout_seconds,
                creationflags=creationflags,
            )
        finally:
            if case_lock:
                case_lock.release()
        stdout_text = self._decode_console_bytes(completed.stdout)
        stderr_text = self._decode_console_bytes(completed.stderr)
        if completed.returncode != 0:
            detail = stderr_text.strip() or stdout_text.strip() or f"exit code {completed.returncode}"
            raise RuntimeError(f"X-Ways 命令执行失败: {detail}")
        return {
            "returncode": completed.returncode,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "command_line": subprocess.list2cmdline(command),
        }

    def _decode_console_bytes(self, data: bytes) -> str:
        for encoding in ("utf-8", "utf-8-sig", "utf-16", "gb18030", "cp936", "cp1252"):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return data.decode("latin-1", errors="replace")

    def _load_evidence_plan_model(self, case_name: str) -> EvidencePlan | None:
        path = self._evidence_plan_path(case_name)
        if not path.exists():
            return None
        return EvidencePlan.model_validate_json(path.read_text(encoding="utf-8"))

    def _normalize_evidence_entry(self, entry: dict[str, Any]) -> EvidencePlanEntry:
        kind = str(entry.get("kind", "")).strip().lower()
        if kind not in {"image", "dir"}:
            raise ValueError("evidence entry.kind 只能是 'image' 或 'dir'。")
        path = str(entry.get("path", "")).strip()
        if not path:
            raise ValueError("evidence entry.path 不能为空。")
        include = bool(entry.get("include", True))
        label = str(entry["label"]).strip() if entry.get("label") is not None else None
        note = str(entry["note"]).strip() if entry.get("note") is not None else None
        force_as = str(entry["force_as"]).strip().upper() if entry.get("force_as") else None
        if force_as and force_as not in {"P", "V"}:
            raise ValueError("evidence entry.force_as 只能是 'P' 或 'V'。")
        sector_size = entry.get("sector_size")
        if sector_size is not None:
            sector_size = int(sector_size)
        if kind != "image":
            force_as = None
            sector_size = None
        elif sector_size is not None and not force_as:
            raise ValueError("image 类型只有在 force_as='P' 或 'V' 时才能设置 sector_size。")
        return EvidencePlanEntry(
            kind=kind,
            path=path,
            include=include,
            label=label,
            force_as=force_as,
            sector_size=sector_size,
            note=note,
        )

    def _merge_evidence_entries(
        self,
        existing: list[EvidencePlanEntry],
        new_entries: list[EvidencePlanEntry],
    ) -> list[EvidencePlanEntry]:
        merged: list[EvidencePlanEntry] = list(existing)
        index = {
            self._evidence_entry_key(entry): pos for pos, entry in enumerate(merged)
        }
        for entry in new_entries:
            key = self._evidence_entry_key(entry)
            if key in index:
                merged[index[key]] = entry
            else:
                index[key] = len(merged)
                merged.append(entry)
        return merged

    def _evidence_entry_key(self, entry: EvidencePlanEntry) -> tuple[Any, ...]:
        return (entry.kind, entry.path, entry.force_as, entry.sector_size)

    def _evidence_plan_payload(self, plan: EvidencePlan) -> dict[str, Any]:
        entries = []
        included_count = 0
        for entry in plan.entries:
            path_exists = self._path_or_glob_exists(entry.path)
            if entry.include:
                included_count += 1
            item = entry.model_dump(mode="json")
            item["path_exists"] = path_exists
            entries.append(item)
        return {
            "case_name": plan.case_name,
            "plan_path": plan.plan_path,
            "exists": True,
            "created_at": plan.created_at,
            "updated_at": plan.updated_at,
            "title": plan.title,
            "note": plan.note,
            "entry_count": len(entries),
            "included_count": included_count,
            "entries": entries,
        }

    def _path_or_glob_exists(self, value: str) -> bool:
        if "*" in value or "?" in value:
            parent = Path(value).expanduser().parent
            return parent.exists()
        return Path(value).expanduser().exists()

    def _copy_if_allowed(
        self,
        src: Path,
        dst: Path,
        overwrite_existing: bool,
        created: list[str],
        skipped: list[str],
    ) -> None:
        if not src.exists():
            return
        if dst.exists() and not overwrite_existing:
            skipped.append(str(dst))
            return
        shutil.copy2(src, dst)
        created.append(str(dst))

    def _render_bridge_guide(self, case: ResolvedCase) -> str:
        return (
            f"# {case.name} Export Bridge\n\n"
            "把 X-Ways 导出的搜索命中、加密文件列表、快照摘要或离线答题相关 artifact 放到本目录，"
            "再通过 `ingest_export_file` 归一成 MCP 可读的 JSONL。\n\n"
            f"- 案件文件: `{case.case_file}`\n"
            f"- 案件目录: `{case.case_dir}`\n"
            f"- 导出目录: `{case.export_dir}`\n"
            f"- 原始导出建议放入: `{case.export_dir / 'inbox'}`\n"
            f"- 原始导出归档位置: `{case.export_dir / 'raw'}`\n\n"
            "推荐命名：\n\n"
            "- `search-hits-*.csv/html/txt/json/jsonl`\n"
            "- `encrypted-files-*.csv/html/txt/json/jsonl`\n"
            "- `volume-snapshot-*.csv/html/txt/json/jsonl`\n"
            "- `registry-system-*.csv/html/txt/json/jsonl`\n"
            "- `event-logs-system-*.csv/html/txt/json/jsonl`\n"
            "- `installed-software-*.csv/html/txt/json/jsonl`\n"
            "- `registry-devices-*.csv/html/txt/json/jsonl`\n"
            "- `sunlogin-logs-*.txt/json/jsonl`\n\n"
            "建议流程：\n\n"
            "1. 在 X-Ways 中完成 RVS / 搜索 / 加密文件识别。\n"
            "2. 把导出结果保存到 `inbox/`。\n"
            "3. 调用 `ingest_export_file(case_ref, kind, source_path)`。\n"
            "4. 再调用 `get_string_search_matches` / `find_encrypted_files` / "
            "`get_volume_snapshot_summary` 读取标准化结果。\n"
            "5. 对离线导出数据，可继续调用 `answer_offline_qa` 自动尝试作答。\n\n"
            "首批离线答题建议优先准备：\n\n"
            "- `registry_system`：System 注册表报告，用于开机时间等系统痕迹。\n"
            "- `event_logs_system`：System 事件日志导出，用于交叉验证启动时间。\n"
            "- `installed_software`：软件安装清单，用于微信版本和远控软件识别。\n"
            "- `registry_devices`：设备/USB 报告，用于最近 USB 设备。\n"
            "- `sunlogin_logs`：向日葵原始日志或整理时间线，用于日志文件名和公网 IP:端口。\n"
        )
