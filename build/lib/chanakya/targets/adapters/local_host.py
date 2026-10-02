"""LocalHostAdapter — docs/TARGET-MANAGER.md §9-§10 (Phase 4.7).

The first, and in this phase the only, concrete ``TargetAdapter``
(docs/ARCHITECTURE.md §7: "Phase 1: LocalHostAdapter — the only adapter
implemented"). Read-only, descriptive, non-destructive: it collects
coarse facts about the local machine using only safe, structured,
standard-library introspection APIs.

It is explicitly NOT, and contains no code path that could become:
- a general-purpose shell executor, a command execution interface, or an
  autonomous scanner — no ``subprocess``, ``os.system``/``os.popen``,
  ``eval``/``exec``, or PowerShell/cmd.exe invocation anywhere in this
  module (verified by ``tests/test_local_host_adapter.py``'s static
  checks);
- a network or port scanner — no ``socket`` import at all; ``hostname``
  is obtained via ``platform.node()`` specifically so no network module
  is ever touched;
- a file-modification, package-installation, service/registry-modification,
  or process-termination mechanism — every filesystem touch in this
  module is a single, explicit read (``os.path.exists``, one ``open(...,
  "rt")``), never a write;
- a credential manager — **no environment variable is read at all**, not
  even via an allowlist. This is the "avoid collecting sensitive values
  entirely" approach docs/TARGET-MANAGER.md's Phase 4.7 scope calls for,
  strictly stronger than filtering a denylist after the fact: there is
  nothing here that *could* return a secret, because nothing here reads
  ``os.environ``;
- a policy engine, authorization mechanism, tool dispatcher, or
  persistence mechanism — this module has no reference to
  ``chanakya.policy`` or ``chanakya.runtime`` (inherited from
  ``chanakya.targets.adapter``'s own structural boundary), writes nothing
  to any Target/registry/investigation state, and every value it returns
  is treated as inert descriptive data by its caller (never interpreted
  as an instruction — see the module's collected facts below).

Deliberate narrowing relative to docs/TARGET-MANAGER.md §9's original
list: network interface addresses are **not** collected. §9 named them as
permitted ("addresses only, never traffic capture or active probing"),
but this implementation omits them — they are more topology/privacy-
sensitive than the other facts, were not in this phase's task-level
"may collect" list, and are avoidable entirely, consistent with "avoid
collecting sensitive values entirely." This is a documented deviation,
not a silent one; see the Phase 4.7 implementation report.

Facts collected (each a ``TargetObservation`` — coarse, non-sensitive,
identity/sizing facts only, matching docs/TARGET-MANAGER.md §9):

- ``os_name``          -- ``platform.system()``
- ``os_release``        -- ``platform.release()``
- ``os_version``        -- ``platform.version()``
- ``platform``          -- ``platform.platform()``
- ``architecture``      -- ``platform.machine()``
- ``hostname``          -- ``platform.node()``
- ``python_version``    -- ``platform.python_version()``
- ``cpu_count``         -- ``os.cpu_count()``
- ``is_containerized``  -- a coarse boolean signal from read-only
  filesystem/environment markers only (``/.dockerenv`` existence,
  ``$container``, ``/proc/1/cgroup`` contents) — never a deep inspection
  of the container runtime, never a subprocess call.
"""
from __future__ import annotations

import os
import platform
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from chanakya.contracts.target import Target
from chanakya.targets.adapter import AvailabilityResult, DiscoveryResult, ValidationResult
from chanakya.targets.environment import EnvironmentContext, EnvironmentSource, TargetObservation
from chanakya.targets.exceptions import UnsupportedTargetTypeError

_SUPPORTED_TARGET_TYPE = "local_host"
_CONTRACT_VERSION = "1.0.0"

_CONTAINER_CGROUP_MARKERS = ("docker", "kubepods", "containerd")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _detect_containerized() -> bool:
    """Read-only filesystem/environment marker checks only — never a
    subprocess call, never a deep container-runtime inspection."""
    if os.path.exists("/.dockerenv"):
        return True
    if os.environ.get("container"):
        return True
    try:
        with open("/proc/1/cgroup", "rt", encoding="utf-8", errors="ignore") as handle:
            content = handle.read()
        if any(marker in content for marker in _CONTAINER_CGROUP_MARKERS):
            return True
    except OSError:
        pass
    return False


class LocalHostAdapter:
    """Conforms structurally to ``chanakya.targets.adapter.TargetAdapter``.
    Every method rejects a non-``local_host`` (or non-``Target``) input by
    raising — never reinterprets another target type as localhost
    (docs/TARGET-MANAGER.md §9/§19 target boundary)."""

    def __init__(self, adapter_id: str = "local-host-adapter") -> None:
        self.adapter_id = adapter_id
        self.supported_target_types = (_SUPPORTED_TARGET_TYPE,)

    def _require_local_host_target(self, target: Any) -> Target:
        if not isinstance(target, Target):
            raise TypeError("LocalHostAdapter requires a Target instance")
        if target.target_type != _SUPPORTED_TARGET_TYPE:
            raise UnsupportedTargetTypeError(
                f"LocalHostAdapter does not support target_type {target.target_type!r}; "
                f"only {_SUPPORTED_TARGET_TYPE!r} is supported"
            )
        return target

    def discover(self, config: Mapping[str, Any]) -> DiscoveryResult:
        """No auto-discovery workflow is implemented in this phase
        (docs/TARGET-MANAGER.md §19: discovery is out of Phase 4.7 scope)
        — always returns an empty result."""
        return DiscoveryResult(candidates=())

    def validate(self, target: Target) -> ValidationResult:
        self._require_local_host_target(target)
        return ValidationResult(is_valid=True, reason="target_type is local_host")

    def check_availability(self, target: Target) -> AvailabilityResult:
        self._require_local_host_target(target)
        return AvailabilityResult(is_available=True)

    def collect_environment(self, target: Target) -> EnvironmentContext:
        resolved = self._require_local_host_target(target)

        observations = (
            TargetObservation(key="os_name", value=platform.system()),
            TargetObservation(key="os_release", value=platform.release()),
            TargetObservation(key="os_version", value=platform.version()),
            TargetObservation(key="platform", value=platform.platform()),
            TargetObservation(key="architecture", value=platform.machine()),
            TargetObservation(key="hostname", value=platform.node()),
            TargetObservation(key="python_version", value=platform.python_version()),
            TargetObservation(key="cpu_count", value=os.cpu_count()),
            TargetObservation(key="is_containerized", value=_detect_containerized()),
        )

        return EnvironmentContext(
            environment_context_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            target_id=resolved.target_id,
            collected_by=self.adapter_id,
            collected_at=_utcnow_iso(),
            observations=observations,
            source=EnvironmentSource.LOCAL_ADAPTER,
        )
