"""
Dynamic sandbox integration layer.

IMPORTANT: This codebase does not, and cannot, provide an actual malware
execution sandbox by itself. Real dynamic analysis requires a hypervisor
(VirtualBox/KVM/QEMU), prepared golden VM snapshots, an in-guest agent, and
strict network isolation -- infrastructure that has to be provisioned and
operated separately (see README.md "Deployment & Isolation Strategy").

What this module provides is the *orchestration interface* the rest of the
app talks to, plus two concrete providers:

- StubDynamicSandbox: the default. It NEVER executes the uploaded file. It
  returns a clearly-labeled placeholder result so the pipeline, DB schema,
  and UI all work end-to-end without any sandbox infrastructure. This is
  what you'll see out of the box after `docker-compose up`.

- CuckooDynamicSandbox: a thin REST client for a real Cuckoo Sandbox
  instance that *you* deploy and own, on your own isolated hypervisor.
  MalLens submits the sample and polls for the report; MalLens itself never
  runs the VM.

Swap providers with DYNAMIC_SANDBOX_PROVIDER in backend/.env.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

import httpx


class DynamicSandbox(ABC):
    @abstractmethod
    def run(self, data: bytes, filename: str, timeout_seconds: int) -> dict[str, Any]:
        """Submit a sample for dynamic analysis and return a dict shaped for
        the DynamicResult model."""
        raise NotImplementedError


class StubDynamicSandbox(DynamicSandbox):
    """Safe default. Performs no execution of any kind."""

    def run(self, data: bytes, filename: str, timeout_seconds: int) -> dict[str, Any]:
        return {
            "provider": "stub",
            "process_logs": [],
            "file_changes": [],
            "registry_changes": [],
            "network_log": [],
            "behavior_timeline": [
                {
                    "time": 0,
                    "event": (
                        "No dynamic sandbox is configured (DYNAMIC_SANDBOX_PROVIDER=stub). "
                        "The sample was NOT executed. Connect a real Cuckoo Sandbox instance "
                        "and set DYNAMIC_SANDBOX_PROVIDER=cuckoo to enable behavioral execution."
                    ),
                }
            ],
            "runtime_seconds": 0.0,
            "notes": "Dynamic analysis skipped: no sandbox provider configured.",
        }


class CuckooDynamicSandbox(DynamicSandbox):
    """Thin client for the Cuckoo Sandbox REST API.

    Requires CUCKOO_API_URL (and optionally CUCKOO_API_TOKEN) to point at a
    Cuckoo instance you run and isolate yourself. See
    https://cuckoosandbox.org/ and README.md for isolation requirements.
    """

    def __init__(self, api_url: str, api_token: str | None = None):
        self.api_url = api_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}

    def run(self, data: bytes, filename: str, timeout_seconds: int) -> dict[str, Any]:
        with httpx.Client(base_url=self.api_url, headers=self.headers, timeout=30) as client:
            submit = client.post("/tasks/create/file", files={"file": (filename, data)})
            submit.raise_for_status()
            task_id = submit.json()["task_id"]

            deadline = time.time() + timeout_seconds
            status = "pending"
            while time.time() < deadline:
                view = client.get(f"/tasks/view/{task_id}")
                view.raise_for_status()
                status = view.json().get("task", {}).get("status")
                if status in ("reported", "completed"):
                    break
                time.sleep(5)

            if status not in ("reported", "completed"):
                return {
                    "provider": "cuckoo",
                    "process_logs": [],
                    "file_changes": [],
                    "registry_changes": [],
                    "network_log": [],
                    "behavior_timeline": [],
                    "runtime_seconds": float(timeout_seconds),
                    "notes": f"Cuckoo task {task_id} did not finish within {timeout_seconds}s.",
                }

            report = client.get(f"/tasks/report/{task_id}")
            report.raise_for_status()
            j = report.json()

            behavior = j.get("behavior", {})
            return {
                "provider": "cuckoo",
                "process_logs": behavior.get("processes", []),
                "file_changes": behavior.get("summary", {}).get("files", []),
                "registry_changes": behavior.get("summary", {}).get("keys", []),
                "network_log": j.get("network", {}),
                "behavior_timeline": behavior.get("processtree", []),
                "runtime_seconds": j.get("info", {}).get("duration"),
                "notes": f"Cuckoo task {task_id} completed.",
            }


def get_sandbox(provider: str, cuckoo_url: str | None, cuckoo_token: str | None) -> DynamicSandbox:
    if provider == "cuckoo":
        if not cuckoo_url:
            raise ValueError("DYNAMIC_SANDBOX_PROVIDER=cuckoo requires CUCKOO_API_URL to be set.")
        return CuckooDynamicSandbox(cuckoo_url, cuckoo_token)
    return StubDynamicSandbox()
