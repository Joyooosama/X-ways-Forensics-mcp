from __future__ import annotations

import time
from typing import Any


_TERMINAL_JOB_STATUSES = {"succeeded", "failed", "orphaned"}


def _validate_wait_args(timeout_seconds: int, poll_interval_seconds: float) -> None:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than 0.")
    if poll_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be greater than 0.")


def _wait_for_job_completion(
    service: Any,
    job_id: str,
    *,
    timeout_seconds: int,
    poll_interval_seconds: float,
) -> dict[str, Any]:
    _validate_wait_args(timeout_seconds, poll_interval_seconds)

    started = time.monotonic()
    last_job: dict[str, Any] | None = None

    while True:
        last_job = service.get_job_status(job_id)
        status = str(last_job.get("status") or "")
        elapsed_seconds = round(time.monotonic() - started, 3)

        if status in _TERMINAL_JOB_STATUSES:
            return {
                "job_id": job_id,
                "timed_out": False,
                "terminal": True,
                "elapsed_seconds": elapsed_seconds,
                "job": last_job,
            }

        if elapsed_seconds >= timeout_seconds:
            return {
                "job_id": job_id,
                "timed_out": True,
                "terminal": False,
                "elapsed_seconds": elapsed_seconds,
                "job": last_job,
            }

        time.sleep(poll_interval_seconds)


def _submit_and_wait(
    submit_result: dict[str, Any],
    service: Any,
    *,
    timeout_seconds: int,
    poll_interval_seconds: float,
) -> dict[str, Any]:
    job_id = str(submit_result.get("job_id") or "").strip()
    if not job_id:
        raise ValueError("The submitted action did not return a job_id.")

    return {
        "submission": submit_result,
        "wait": _wait_for_job_completion(
            service,
            job_id,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        ),
    }


def register_addon_tools(mcp: Any, service: Any) -> None:
    @mcp.tool(
        description=(
            "Wait for one async X-Ways job to finish. Preferred in chat clients that "
            "would otherwise call get_job_status repeatedly."
        )
    )
    def wait_for_job(
        job_id: str,
        timeout_seconds: int = 900,
        poll_interval_seconds: float = 5.0,
    ) -> dict[str, Any]:
        return _wait_for_job_completion(
            service,
            job_id,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )

    @mcp.tool(
        description=(
            "Create a case and wait for the async job to finish. Preferred over "
            "create_case + repeated get_job_status in chat clients."
        )
    )
    def create_case_and_wait(
        case_name: str,
        overwrite_existing: bool = False,
        override: int | None = None,
        auto: bool = True,
        timeout_seconds: int = 300,
        poll_interval_seconds: float = 2.0,
    ) -> dict[str, Any]:
        submit_result = service.create_case(
            case_name,
            overwrite_existing=overwrite_existing,
            override=override,
            auto=auto,
        )
        return _submit_and_wait(
            submit_result,
            service,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )

    @mcp.tool(
        description=(
            "Add one image to an existing case and wait for completion. Preferred over "
            "add_image + repeated get_job_status in chat clients."
        )
    )
    def add_image_and_wait(
        case_ref: str,
        image_path: str,
        force_as: str | None = None,
        sector_size: int | None = None,
        override: int | None = None,
        auto: bool = True,
        timeout_seconds: int = 1800,
        poll_interval_seconds: float = 5.0,
    ) -> dict[str, Any]:
        submit_result = service.add_image(
            case_ref,
            image_path,
            force_as=force_as,
            sector_size=sector_size,
            override=override,
            auto=auto,
        )
        return _submit_and_wait(
            submit_result,
            service,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )

    @mcp.tool(
        description=(
            "Add one directory to an existing case and wait for completion. Preferred over "
            "add_dir + repeated get_job_status in chat clients."
        )
    )
    def add_dir_and_wait(
        case_ref: str,
        directory_path: str,
        override: int | None = None,
        auto: bool = True,
        timeout_seconds: int = 1800,
        poll_interval_seconds: float = 5.0,
    ) -> dict[str, Any]:
        submit_result = service.add_dir(
            case_ref,
            directory_path,
            override=override,
            auto=auto,
        )
        return _submit_and_wait(
            submit_result,
            service,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )

    @mcp.tool(
        description=(
            "Run RVS and wait for the async job to finish. Preferred over "
            "run_rvs + repeated get_job_status in chat clients."
        )
    )
    def run_rvs_and_wait(
        case_ref: str,
        scope: str = "new",
        search_list_name: str | None = None,
        search_list_path: str | None = None,
        override: int | None = None,
        auto: bool = True,
        timeout_seconds: int = 7200,
        poll_interval_seconds: float = 10.0,
    ) -> dict[str, Any]:
        submit_result = service.run_rvs(
            case_ref,
            scope=scope,
            search_list_name=search_list_name,
            search_list_path=search_list_path,
            override=override,
            auto=auto,
        )
        return _submit_and_wait(
            submit_result,
            service,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )

    @mcp.tool(
        description=(
            "Run one WHS script and wait for completion. Preferred over "
            "run_whs_script + repeated get_job_status in chat clients."
        )
    )
    def run_whs_script_and_wait(
        script_path: str,
        case_ref: str | None = None,
        override: int | None = None,
        auto: bool = True,
        timeout_seconds: int = 1800,
        poll_interval_seconds: float = 5.0,
    ) -> dict[str, Any]:
        submit_result = service.run_whs_script(
            script_path,
            case_ref=case_ref,
            override=override,
            auto=auto,
        )
        return _submit_and_wait(
            submit_result,
            service,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )
