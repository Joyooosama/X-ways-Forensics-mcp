from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class XWaysConfig:
    project_root: Path
    xways_exe: Path
    cases_root: Path
    runtime_dir: Path
    jobs_dir: Path
    plans_dir: Path
    sessions_dir: Path
    exports_dir: Path
    lists_dir: Path
    scripts_dir: Path
    templates_dir: Path
    audit_log_path: Path
    global_msglog_path: Path
    default_override: int
    default_timeout_seconds: int
    poll_interval_seconds: float

    @classmethod
    def from_env(cls) -> "XWaysConfig":
        project_root = Path(
            os.getenv("XWF_PROJECT_ROOT", Path(__file__).resolve().parents[1])
        ).resolve()
        workspace_root = project_root.parent

        xways_exe = Path(
            os.getenv(
                "XWF_XWAYS_EXE",
                workspace_root / "X-Ways Forensics_20.0" / "xwforensics64.exe",
            )
        ).resolve()
        cases_root = Path(
            os.getenv(
                "XWF_CASES_ROOT",
                workspace_root / "X-Ways_Forensics_Case_Files" / "Cases",
            )
        ).resolve()
        runtime_dir = Path(os.getenv("XWF_RUNTIME_DIR", project_root / "runtime")).resolve()
        exports_dir = Path(os.getenv("XWF_EXPORTS_DIR", project_root / "exports")).resolve()
        lists_dir = Path(os.getenv("XWF_LISTS_DIR", project_root / "lists")).resolve()
        scripts_dir = Path(os.getenv("XWF_SCRIPTS_DIR", project_root / "scripts")).resolve()
        templates_dir = (project_root / "templates").resolve()
        jobs_dir = runtime_dir / "jobs"
        plans_dir = runtime_dir / "plans"
        sessions_dir = runtime_dir / "sessions"
        audit_log_path = runtime_dir / "audit.jsonl"
        global_msglog_path = Path(
            os.getenv("XWF_GLOBAL_MSGLOG", xways_exe.parent / "msglog.txt")
        ).resolve()

        return cls(
            project_root=project_root,
            xways_exe=xways_exe,
            cases_root=cases_root,
            runtime_dir=runtime_dir,
            jobs_dir=jobs_dir,
            plans_dir=plans_dir,
            sessions_dir=sessions_dir,
            exports_dir=exports_dir,
            lists_dir=lists_dir,
            scripts_dir=scripts_dir,
            templates_dir=templates_dir,
            audit_log_path=audit_log_path,
            global_msglog_path=global_msglog_path,
            default_override=int(os.getenv("XWF_DEFAULT_OVERRIDE", "1")),
            default_timeout_seconds=int(
                os.getenv("XWF_DEFAULT_TIMEOUT_SECONDS", "3600")
            ),
            poll_interval_seconds=float(os.getenv("XWF_POLL_INTERVAL_SECONDS", "2.0")),
        )

    def ensure_directories(self) -> None:
        for path in (
            self.runtime_dir,
            self.jobs_dir,
            self.plans_dir,
            self.sessions_dir,
            self.exports_dir,
            self.lists_dir,
            self.scripts_dir,
            self.templates_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def public_dict(self) -> dict[str, object]:
        return {
            "project_root": str(self.project_root),
            "xways_exe": str(self.xways_exe),
            "xways_exe_exists": self.xways_exe.exists(),
            "cases_root": str(self.cases_root),
            "cases_root_exists": self.cases_root.exists(),
            "runtime_dir": str(self.runtime_dir),
            "plans_dir": str(self.plans_dir),
            "sessions_dir": str(self.sessions_dir),
            "exports_dir": str(self.exports_dir),
            "lists_dir": str(self.lists_dir),
            "scripts_dir": str(self.scripts_dir),
            "global_msglog_path": str(self.global_msglog_path),
            "global_msglog_exists": self.global_msglog_path.exists(),
            "default_override": self.default_override,
            "default_timeout_seconds": self.default_timeout_seconds,
            "poll_interval_seconds": self.poll_interval_seconds,
        }
