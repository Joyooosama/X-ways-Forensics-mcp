from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    orphaned = "orphaned"


class RiskLevel(str, Enum):
    read_only = "read_only"
    modifying = "modifying"


class CaseSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    case_file: str | None = None
    case_dir: str | None = None
    msglog_path: str | None = None
    password_file: str | None = None
    export_dir: str
    list_dir: str
    has_case_file: bool
    has_case_dir: bool
    has_message_log: bool
    has_password_file: bool


class SearchListManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_name: str
    list_name: str
    path: str
    term_count: int
    encoding: str


class EvidencePlanEntry(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: str
    path: str
    include: bool = True
    label: str | None = None
    force_as: str | None = None
    sector_size: int | None = None
    note: str | None = None


class EvidencePlan(BaseModel):
    model_config = ConfigDict(extra="allow")

    case_name: str
    plan_path: str
    created_at: str
    updated_at: str
    title: str | None = None
    note: str | None = None
    entries: list[EvidencePlanEntry] = Field(default_factory=list)


class AnalysisSessionManifest(BaseModel):
    model_config = ConfigDict(extra="allow")

    request_text: str
    case_name: str
    case_file: str
    evidence_path: str
    drive: str
    evidence_label: str
    created_at: str
    updated_at: str


class JobRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    job_id: str
    action: str
    description: str
    status: JobStatus
    risk_level: RiskLevel
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    case_name: str | None = None
    case_file: str | None = None
    command: list[str] = Field(default_factory=list)
    command_line: str = ""
    working_directory: str
    stdout_path: str
    stderr_path: str
    log_paths: list[str] = Field(default_factory=list)
    progress_message: str | None = None
    progress_log_tail: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    error: str | None = None
    result: dict[str, Any] = Field(default_factory=dict)
