"""Durable workdir placement confinement — Phase 20 (T-65, T-22).

Every durable store (Audit Log, Evidence, Findings, RiskAssessments) lives
under one workdir. This module is the single, Runtime-owned control that
makes that workdir safe to write before any store exists:

    resolve the workdir (canonical path; symlinks, junctions, ``..``)
        -> determine the enclosing Git working-tree boundary (filesystem
           inspection only: a ``.git`` directory or ``.git`` file)
        -> establish (exclusively, atomically) or verify (exactly) the
           Runtime-owned ``.gitignore`` at the workdir root
        -> verify the store roots are plain directories inside the workdir
        -> ONLY THEN return the resolved root to the composition root

The exclusion is unconditional: the workdir is always self-excluding,
whether or not it is inside a working tree today (a directory can later
become part of one). A pre-existing exclusion file that is not byte-for-
byte the canonical content, or is not a plain regular file, is refused;
it is never overwritten, appended to, or repaired.

Placement is a filesystem/data-egress control only. It has no authority:
it decides nothing about policy, approval, risk, targets or capabilities,
and imports nothing from those layers. It either returns a safe root or
raises ``WorkdirPlacementError`` carrying a fixed code; the error never
carries a path, an OS error message, or any other value.
"""
from __future__ import annotations

import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

#: The file name Git reads for per-directory exclusion rules.
EXCLUSION_FILE_NAME = ".gitignore"

#: The one canonical, Runtime-owned exclusion policy. ``*`` matches every
#: entry directly under the workdir, including this file and every store
#: directory; Git never descends into an excluded directory, so nothing
#: beneath the workdir can be re-included by a deeper file. Deeper
#: ``.gitignore`` files take precedence over shallower ones, so no rule in
#: an enclosing repository's own ``.gitignore`` can re-include it either.
#: Exact bytes, LF line endings; compared byte-for-byte.
CANONICAL_EXCLUSION = (
    b"# Chanakya AI runtime-owned exclusion (Phase 20). Do not edit.\n"
    b"# Everything beneath this directory is durable investigation data\n"
    b"# and must never be staged by version control.\n"
    b"*\n"
)

#: The store directories created under the workdir by the composition root.
STORE_NAMES: Tuple[str, ...] = ("audit", "evidence", "findings", "risk")

_VCS_MARKER = ".git"
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

# Fixed, closed error-code vocabulary. Nothing else is ever reported.
WORKDIR_UNRESOLVABLE = "WORKDIR_UNRESOLVABLE"
WORKDIR_NOT_DIRECTORY = "WORKDIR_NOT_DIRECTORY"
WORKDIR_INSIDE_VCS_METADATA = "WORKDIR_INSIDE_VCS_METADATA"
WORKDIR_UNSTABLE = "WORKDIR_UNSTABLE"
WORKDIR_EXCLUSION_MISMATCH = "WORKDIR_EXCLUSION_MISMATCH"
WORKDIR_EXCLUSION_UNAVAILABLE = "WORKDIR_EXCLUSION_UNAVAILABLE"
WORKDIR_STORE_ROOT_UNSAFE = "WORKDIR_STORE_ROOT_UNSAFE"

PLACEMENT_ERROR_CODES = frozenset({
    WORKDIR_UNRESOLVABLE,
    WORKDIR_NOT_DIRECTORY,
    WORKDIR_INSIDE_VCS_METADATA,
    WORKDIR_UNSTABLE,
    WORKDIR_EXCLUSION_MISMATCH,
    WORKDIR_EXCLUSION_UNAVAILABLE,
    WORKDIR_STORE_ROOT_UNSAFE,
})


class WorkdirPlacementError(Exception):
    """Placement refused. Carries only a fixed code from
    ``PLACEMENT_ERROR_CODES``: never a path, an OS message, or a value."""

    def __init__(self, code: str) -> None:
        if code not in PLACEMENT_ERROR_CODES:  # pragma: no cover - programming error
            code = WORKDIR_UNRESOLVABLE
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class DurableWorkdir:
    """A workdir that has passed placement: ``root`` is canonical, carries
    the verified canonical exclusion, and its store roots are safe.
    ``vcs_boundary`` is the enclosing working-tree root, if any (for
    reporting; the exclusion is established either way)."""

    root: Path
    vcs_boundary: Optional[Path]

    def store_root(self, name: str) -> Path:
        if name not in STORE_NAMES:
            raise WorkdirPlacementError(WORKDIR_STORE_ROOT_UNSAFE)
        return self.root / name


# -- path resolution and VCS detection ---------------------------------------


def resolve_workdir(workdir: Union[str, Path]) -> Path:
    """The canonical absolute path of ``workdir``: relative spellings,
    ``..``, symlinks and junctions are resolved for every component that
    exists. Raw strings are never compared."""
    try:
        return Path(os.path.abspath(Path(workdir))).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        raise WorkdirPlacementError(WORKDIR_UNRESOLVABLE) from None


def _lexists(path: Path) -> bool:
    try:
        os.lstat(path)
    except (OSError, ValueError):
        return False
    return True


def _is_vcs_metadata_name(name: str) -> bool:
    return name.casefold() == _VCS_MARKER


def detect_vcs_boundary(resolved: Path) -> Optional[Path]:
    """The nearest directory at or above ``resolved`` that holds a ``.git``
    entry — a directory (ordinary repository), a file (worktree or
    submodule), or a link — or ``None``. Deterministic filesystem
    inspection only; no Git command is run. Nested repositories are found
    because the walk stops at the nearest marker."""
    for candidate in (resolved, *resolved.parents):
        if _lexists(candidate / _VCS_MARKER):
            return candidate
    return None


def _inside_vcs_metadata(resolved: Path) -> bool:
    return any(_is_vcs_metadata_name(part) for part in resolved.parts)


# -- exclusion ----------------------------------------------------------------


def _is_plain(st: os.stat_result) -> bool:
    return not (getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def verify_exclusion(root: Path) -> None:
    """The exclusion file at ``root`` must be a plain regular file (not a
    link, junction or hard link) whose bytes are exactly
    ``CANONICAL_EXCLUSION``. Reads at most one byte more than the canonical
    length. Anything else is refused."""
    path = root / EXCLUSION_FILE_NAME
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or not _is_plain(st) or st.st_nlink != 1:
            raise WorkdirPlacementError(WORKDIR_EXCLUSION_MISMATCH)
        if st.st_size != len(CANONICAL_EXCLUSION):
            raise WorkdirPlacementError(WORKDIR_EXCLUSION_MISMATCH)
        with open(path, "rb") as handle:
            content = handle.read(len(CANONICAL_EXCLUSION) + 1)
    except WorkdirPlacementError:
        raise
    except (OSError, ValueError):
        raise WorkdirPlacementError(WORKDIR_EXCLUSION_MISMATCH) from None
    if content != CANONICAL_EXCLUSION:
        raise WorkdirPlacementError(WORKDIR_EXCLUSION_MISMATCH)


def _establish_exclusion(root: Path) -> None:
    """Creates the exclusion file atomically and exclusively: the content
    is written and flushed to a uniquely named temporary file, which is
    then hard-linked to the final name. ``os.link`` fails if the name
    already exists, so an existing file is never overwritten, and the
    final name never holds partial content."""
    final = root / EXCLUSION_FILE_NAME
    temporary = root / f".chanakya-exclusion-{uuid.uuid4().hex}.tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(CANONICAL_EXCLUSION)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, final)
        except FileExistsError:
            # Someone else created it first: never overwrite; verify below.
            pass
    except OSError:
        raise WorkdirPlacementError(WORKDIR_EXCLUSION_UNAVAILABLE) from None
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass


# -- store roots ---------------------------------------------------------------


def _verify_store_roots(root: Path) -> None:
    """An existing store root must be a plain directory directly under the
    workdir (not a link or junction that would carry data elsewhere)."""
    for name in STORE_NAMES:
        path = root / name
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            raise WorkdirPlacementError(WORKDIR_STORE_ROOT_UNSAFE) from None
        if not stat.S_ISDIR(st.st_mode) or not _is_plain(st):
            raise WorkdirPlacementError(WORKDIR_STORE_ROOT_UNSAFE)
        try:
            if path.resolve(strict=True) != path:
                raise WorkdirPlacementError(WORKDIR_STORE_ROOT_UNSAFE)
        except (OSError, RuntimeError):
            raise WorkdirPlacementError(WORKDIR_STORE_ROOT_UNSAFE) from None


# -- the control ----------------------------------------------------------------


def establish_durable_workdir(workdir: Union[str, Path]) -> DurableWorkdir:
    """Phase 20 placement control, run by the composition root before any
    durable store is constructed. Returns the safe, canonical root or
    raises ``WorkdirPlacementError`` having written nothing but (at most)
    empty directories and the canonical exclusion file."""
    resolved = resolve_workdir(workdir)
    if _inside_vcs_metadata(resolved):
        raise WorkdirPlacementError(WORKDIR_INSIDE_VCS_METADATA)
    boundary = detect_vcs_boundary(resolved)

    if _lexists(resolved) and not resolved.is_dir():
        raise WorkdirPlacementError(WORKDIR_NOT_DIRECTORY)
    try:
        resolved.mkdir(parents=True, exist_ok=True)
    except (OSError, ValueError):
        raise WorkdirPlacementError(WORKDIR_UNRESOLVABLE) from None
    # The location must not have changed while it was being created (a
    # link or junction appearing in between would redirect the stores).
    if resolve_workdir(resolved) != resolved:
        raise WorkdirPlacementError(WORKDIR_UNSTABLE)

    if not _lexists(resolved / EXCLUSION_FILE_NAME):
        _establish_exclusion(resolved)
    verify_exclusion(resolved)
    _verify_store_roots(resolved)
    return DurableWorkdir(root=resolved, vcs_boundary=boundary)


__all__ = [
    "CANONICAL_EXCLUSION",
    "EXCLUSION_FILE_NAME",
    "PLACEMENT_ERROR_CODES",
    "STORE_NAMES",
    "DurableWorkdir",
    "WorkdirPlacementError",
    "detect_vcs_boundary",
    "establish_durable_workdir",
    "resolve_workdir",
    "verify_exclusion",
]
