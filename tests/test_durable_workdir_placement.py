"""Phase 20 — durable investigation data placement confinement (T-65, T-22).

P20-INV-1  Stores -> VCS: no durable file under the workdir is stageable by Git
           (real temporary repositories; ``git status`` / ``git add -A``).
P20-INV-2  CLI -> filesystem: an unverifiable workdir is refused before any
           durable file is created.
P20-INV-3  A deleted or altered Runtime-owned exclusion is re-established
           safely or refused before any durable write.
P20-INV-4  A pre-created weaker exclusion is refused.
P20-INV-5  ``--review`` creates and modifies nothing.
P20-INV-6  Placement has no authorization authority (AST + behavior).

Git is never mocked for the primary invariant: the tests run the real
``git`` binary against throwaway repositories under ``tmp_path`` with an
isolated (empty) Git configuration and no network.
"""
from __future__ import annotations

import ast
import hashlib
import io
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

import chanakya.cli.main as cli_main
import chanakya.runtime.workdir_placement as placement
from chanakya.audit import FilesystemAuditLog
from chanakya.contracts.audit_event import AuditEventType
from chanakya.evidence import EvidenceStore
from chanakya.findings import FindingStore
from chanakya.risk import RiskAssessmentStore
from chanakya.runtime.workdir_placement import (
    CANONICAL_EXCLUSION,
    EXCLUSION_FILE_NAME,
    PLACEMENT_ERROR_CODES,
    WorkdirPlacementError,
    detect_vcs_boundary,
    establish_durable_workdir,
    resolve_workdir,
)

from runtime_factories import make_agent_turn_conclude, make_agent_turn_propose

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHANAKYA = _REPO_ROOT / "chanakya"
ENV_CAP = "observe_local_host_environment"
TARGET = cli_main.LOCAL_TARGET_ID
KEY = "sk-ant-PHASE20-SENTINEL-KEY"
OBJECTIVE = "OBJECTIVE-SENTINEL-p20 assess exposed services"
STORES = ("audit", "evidence", "findings", "risk")


# ===========================================================================
# Helpers: real Git, a scripted model, the real CLI
# ===========================================================================


def _git_env(tmp_path: Path) -> Dict[str, str]:
    config = tmp_path / "isolated-gitconfig"
    if not config.exists():
        config.write_text("", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": str(config), "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"})
    return env


def git(tmp_path: Path, cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-c", "user.name=p20", "-c", "user.email=p20@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "core.autocrlf=false", *args],
        cwd=str(cwd), env=_git_env(tmp_path), capture_output=True, text=True, check=check,
    )


def git_init(tmp_path: Path, path: Path, *, commit: bool = False) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git(tmp_path, path, "init", "-q")
    if commit:
        (path / "README.md").write_text("tracked\n", encoding="utf-8")
        git(tmp_path, path, "add", "README.md")
        git(tmp_path, path, "commit", "-q", "-m", "init")
    return path


def porcelain(tmp_path: Path, repo: Path) -> List[str]:
    out = git(tmp_path, repo, "status", "--porcelain", "--untracked-files=all").stdout
    return [line for line in out.splitlines() if line.strip()]


def stage_all(tmp_path: Path, repo: Path) -> List[str]:
    git(tmp_path, repo, "add", "-A")
    return git(tmp_path, repo, "diff", "--cached", "--name-only").stdout.split()


class ScriptedModel:
    """Proposes one observation, then concludes with a finding grounded in
    it, so every store (audit, evidence, findings, risk) receives data."""

    def __init__(self, config=None, api_key=None) -> None:
        self.turns = 0

    def next_turn(self, assembled_context):
        iid = assembled_context.investigation_id
        self.turns += 1
        if self.turns == 1:
            return make_agent_turn_propose(iid, ENV_CAP, TARGET, {})
        ids = [d.source.split(":", 1)[1] for d in assembled_context.data if d.source.startswith("tool_result:")]
        turn = make_agent_turn_conclude(iid)
        turn["findings"] = [{"title": "Service exposure", "description": "Observed on this host.",
                             "evidence_refs": ids, "category": "platform_configuration", "confidence": "medium"}]
        return turn


def run_cli(monkeypatch, cwd: Path, *args: str, objective: str = OBJECTIVE, environ=None,
            answer: str = "approve") -> Tuple[int, str]:
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(cli_main, "AnthropicProvider", ScriptedModel)
    out = io.StringIO()
    code = cli_main.main([objective, *args, "--approver", "alice"],
                         environ=environ if environ is not None else {cli_main.API_KEY_ENV_VAR: KEY},
                         input_fn=lambda _p: answer, output=out)
    return code, out.getvalue()


def investigation_id(output: str) -> str:
    return next(line.split(": ", 1)[1] for line in output.splitlines() if line.startswith("investigation: "))


def durable_files(workdir: Path) -> List[Path]:
    return sorted(p for p in workdir.rglob("*") if p.is_file() and p.name != EXCLUSION_FILE_NAME)


def canonical(workdir: Path) -> bool:
    path = workdir / EXCLUSION_FILE_NAME
    return path.is_file() and path.read_bytes() == CANONICAL_EXCLUSION


def assert_populated(workdir: Path) -> None:
    for store in ("audit", "evidence", "findings", "risk"):
        assert any(p.is_file() for p in (workdir / store).rglob("*")), store


def make_dir_link(link: Path, target: Path) -> None:
    """A directory junction on Windows (no privilege needed), a symlink
    elsewhere."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def snapshot(root: Path) -> Dict[str, Tuple]:
    state: Dict[str, Tuple] = {}
    if not root.exists():
        return state
    state["."] = ("dir", root.stat().st_mtime_ns)
    for directory, dirs, files in os.walk(root):
        for name in dirs:
            p = Path(directory, name)
            state[str(p.relative_to(root))] = ("dir", p.stat().st_mtime_ns)
        for name in files:
            p = Path(directory, name)
            st = p.stat()
            state[str(p.relative_to(root))] = ("file", st.st_size, st.st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
    return state


def refused(output: str, code: str) -> bool:
    return f"error: durable workdir placement refused ({code})" in output


# ===========================================================================
# Canonical content (exact, bounded, documented)
# ===========================================================================


def test_canonical_exclusion_is_exact():
    assert CANONICAL_EXCLUSION == (
        b"# Chanakya AI runtime-owned exclusion (Phase 20). Do not edit.\n"
        b"# Everything beneath this directory is durable investigation data\n"
        b"# and must never be staged by version control.\n"
        b"*\n"
    )
    assert EXCLUSION_FILE_NAME == ".gitignore"
    lines = CANONICAL_EXCLUSION.decode("ascii").splitlines()
    rules = [line for line in lines if line and not line.startswith("#")]
    assert rules == ["*"]  # one rule; no negation, no directory-only form
    assert b"\r" not in CANONICAL_EXCLUSION and len(CANONICAL_EXCLUSION) < 512


def test_canonical_rule_really_excludes_everything_per_git(tmp_path):
    repo = git_init(tmp_path, tmp_path / "repo")
    wd = repo / "wd"
    establish_durable_workdir(wd)
    for rel in ("audit/inv/00000001.json", "evidence/inv/x.json", "findings/inv/f.json", "risk/inv/r.json",
                "deep/a/b/c.txt", ".hidden", EXCLUSION_FILE_NAME):
        path = wd / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text("data", encoding="utf-8")
        assert git(tmp_path, repo, "check-ignore", "-q", f"wd/{rel}", check=False).returncode == 0, rel
    # A deeper negation file cannot re-include: Git never descends into an
    # excluded directory.
    (wd / "evidence" / EXCLUSION_FILE_NAME).write_text("!*\n", encoding="utf-8")
    # Nor can the enclosing repository's own rules.
    (repo / EXCLUSION_FILE_NAME).write_text("!wd/\n!wd/**\n", encoding="utf-8")
    assert porcelain(tmp_path, repo) == ["?? .gitignore"]
    assert stage_all(tmp_path, repo) == [".gitignore"]


# ===========================================================================
# P20-INV-1 — TEST 1, TEST 2: real Git repository, default workdir
# ===========================================================================


def test_default_workdir_in_a_git_repository_is_not_stageable(tmp_path, monkeypatch):
    """TEST 1 + TEST 2 (P20-INV-1). The temporary repository has NO root
    .gitignore, so only the Runtime-owned exclusion protects the data."""
    repo = git_init(tmp_path, tmp_path / "repo")
    (repo / "project.txt").write_text("real project file\n", encoding="utf-8")

    code, out = run_cli(monkeypatch, repo)  # default --workdir .chanakya
    assert code == cli_main.EXIT_COMPLETED, out
    wd = repo / ".chanakya"
    assert canonical(wd)
    assert_populated(wd)
    assert durable_files(wd)

    assert porcelain(tmp_path, repo) == ["?? project.txt"]
    ignored = git(tmp_path, repo, "status", "--porcelain", "--ignored").stdout.splitlines()
    assert "!! .chanakya/" in ignored
    assert git(tmp_path, repo, "ls-files", "--others", "--exclude-standard").stdout.split() == ["project.txt"]

    staged = stage_all(tmp_path, repo)
    assert staged == ["project.txt"]  # git add -A works, and stages no Chanakya data
    assert not any(name.startswith(".chanakya") for name in staged)
    for path in durable_files(wd):  # belt and braces: Git itself says each file is ignored
        rel = path.relative_to(repo).as_posix()
        assert git(tmp_path, repo, "check-ignore", "-q", rel, check=False).returncode == 0, rel


def test_second_investigation_in_the_same_repository_stays_excluded(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")
    assert run_cli(monkeypatch, repo)[0] == cli_main.EXIT_COMPLETED
    assert run_cli(monkeypatch, repo)[0] == cli_main.EXIT_COMPLETED
    assert canonical(repo / ".chanakya")
    assert porcelain(tmp_path, repo) == [] and stage_all(tmp_path, repo) == []


# ===========================================================================
# TEST 3 — nested repositories
# ===========================================================================


@pytest.mark.parametrize("relative", ["nested", "nested/deep/wd"], ids=["nested-root", "inside-nested"])
def test_workdir_in_a_nested_repository(tmp_path, monkeypatch, relative):
    outer = git_init(tmp_path, tmp_path / "outer")
    inner = git_init(tmp_path, outer / "nested", commit=True)
    wd = outer / relative
    assert detect_vcs_boundary(resolve_workdir(wd)) == inner.resolve()

    code, out = run_cli(monkeypatch, outer, "--workdir", relative)
    assert code == cli_main.EXIT_COMPLETED, out
    assert canonical(wd) and durable_files(wd)
    assert porcelain(tmp_path, inner) == [] and stage_all(tmp_path, inner) == []
    # The outer repository can only record the nested repository as a
    # gitlink (mode 160000), never a blob from inside it.
    stage_all(tmp_path, outer)
    entries = git(tmp_path, outer, "ls-files", "-s").stdout.splitlines()
    assert all(line.startswith("160000 ") for line in entries), entries


# ===========================================================================
# TEST 4 — deleted exclusion (P20-INV-3)
# ===========================================================================


def test_deleted_exclusion_is_re_established_before_any_write(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")
    assert run_cli(monkeypatch, repo)[0] == cli_main.EXIT_COMPLETED
    wd = repo / ".chanakya"
    (wd / EXCLUSION_FILE_NAME).unlink()

    writes = _spy_writes(monkeypatch)
    code, out = run_cli(monkeypatch, repo)
    assert code == cli_main.EXIT_COMPLETED, out
    assert canonical(wd)
    assert writes and all(protected for _, protected in writes), writes
    assert porcelain(tmp_path, repo) == [] and stage_all(tmp_path, repo) == []
    assert not list(wd.glob(".chanakya-exclusion-*"))  # the temporary file is gone


# ===========================================================================
# TEST 5, 6, 16 — tampered exclusion after a successful run (P20-INV-3)
# ===========================================================================

_TAMPERS = {
    "negate-all": b"!*\n",
    "empty": b"",
    "truncated": CANONICAL_EXCLUSION[:-2],
    "rule-removed": CANONICAL_EXCLUSION.replace(b"*\n", b""),
    "conflicting-rule-appended": CANONICAL_EXCLUSION + b"!evidence/\n",
    "replaced": b"*.tmp\n",
    "crlf": CANONICAL_EXCLUSION.replace(b"\n", b"\r\n"),
    "bom": b"\xef\xbb\xbf" + CANONICAL_EXCLUSION,
    "trailing-space": CANONICAL_EXCLUSION[:-1] + b" \n",
    "equivalent-looking-star-only": b"*\n",
}


@pytest.mark.parametrize("content", list(_TAMPERS.values()), ids=list(_TAMPERS))
def test_tampered_exclusion_is_refused_before_any_write(tmp_path, monkeypatch, content):
    repo = git_init(tmp_path, tmp_path / "repo")
    assert run_cli(monkeypatch, repo)[0] == cli_main.EXIT_COMPLETED
    wd = repo / ".chanakya"
    (wd / EXCLUSION_FILE_NAME).write_bytes(content)
    before = snapshot(wd)

    code, out = run_cli(monkeypatch, repo)
    assert code == cli_main.EXIT_CONFIG_ERROR
    assert refused(out, "WORKDIR_EXCLUSION_MISMATCH"), out
    assert "investigation:" not in out
    assert snapshot(wd) == before  # nothing written, nothing repaired
    assert (wd / EXCLUSION_FILE_NAME).read_bytes() == content


# ===========================================================================
# TEST 6, 7, 15 — pre-created weak exclusion before the first run (P20-INV-4)
# ===========================================================================

_WEAK = {
    "empty": b"",
    "negate-all": b"!*\n",
    "partial": b"evidence/\naudit/\n",
    "unrelated": b"*.pyc\n__pycache__/\n",
    "star-only": b"*\n",
    "canonical-plus-negation": CANONICAL_EXCLUSION + b"!findings/**\n",
}


@pytest.mark.parametrize("content", list(_WEAK.values()), ids=list(_WEAK))
def test_pre_created_weak_exclusion_is_refused(tmp_path, monkeypatch, content):
    repo = git_init(tmp_path, tmp_path / "repo")
    wd = repo / ".chanakya"
    wd.mkdir()
    (wd / EXCLUSION_FILE_NAME).write_bytes(content)

    code, out = run_cli(monkeypatch, repo)
    assert code == cli_main.EXIT_CONFIG_ERROR and refused(out, "WORKDIR_EXCLUSION_MISMATCH"), out
    assert sorted(p.name for p in wd.iterdir()) == [EXCLUSION_FILE_NAME]  # no store created
    assert (wd / EXCLUSION_FILE_NAME).read_bytes() == content


def test_exclusion_that_is_not_a_plain_file_is_refused(tmp_path):
    as_directory = tmp_path / "dir-case"
    (as_directory / EXCLUSION_FILE_NAME).mkdir(parents=True)
    with pytest.raises(WorkdirPlacementError) as exc:
        establish_durable_workdir(as_directory)
    assert exc.value.code == "WORKDIR_EXCLUSION_MISMATCH"

    # A hard link whose content is canonical can be changed through its
    # other name at any time: refused.
    hard = tmp_path / "hard-case"
    hard.mkdir()
    other = tmp_path / "elsewhere.txt"
    other.write_bytes(CANONICAL_EXCLUSION)
    os.link(other, hard / EXCLUSION_FILE_NAME)
    with pytest.raises(WorkdirPlacementError) as exc:
        establish_durable_workdir(hard)
    assert exc.value.code == "WORKDIR_EXCLUSION_MISMATCH"
    assert sorted(p.name for p in hard.iterdir()) == [EXCLUSION_FILE_NAME]


def test_exclusion_symlink_is_refused(tmp_path):
    """Git ignores a symlinked .gitignore, so one must never be accepted.
    (Junctions only apply to directories; the directory case is above.)"""
    wd = tmp_path / "wd"
    wd.mkdir()
    real = tmp_path / "real-ignore"
    real.write_bytes(CANONICAL_EXCLUSION)
    try:
        os.symlink(real, wd / EXCLUSION_FILE_NAME)
    except OSError:
        # No symlink privilege on this host: an unprivileged attacker
        # cannot create one either; the placement verdict is still checked
        # through a directory junction named .gitignore.
        make_dir_link(wd / EXCLUSION_FILE_NAME, tmp_path)
    with pytest.raises(WorkdirPlacementError) as exc:
        establish_durable_workdir(wd)
    assert exc.value.code == "WORKDIR_EXCLUSION_MISMATCH"


# ===========================================================================
# TEST 8 — outside any repository
# ===========================================================================


def test_workdir_outside_any_repository_still_self_excludes(tmp_path, monkeypatch):
    data = tmp_path / "Chanakya-Data"
    assert detect_vcs_boundary(resolve_workdir(data)) is None
    code, out = run_cli(monkeypatch, tmp_path, "--workdir", str(data))
    assert code == cli_main.EXIT_COMPLETED, out
    assert canonical(data)
    assert_populated(data)
    # If the directory later becomes part of a working tree, it is
    # already excluded.
    later = git_init(tmp_path, tmp_path / "later-repo")
    moved = later / "Chanakya-Data"
    os.replace(data, moved)
    assert porcelain(tmp_path, later) == [] and stage_all(tmp_path, later) == []


# ===========================================================================
# TEST 9, §29 — path resolution
# ===========================================================================


def test_parent_traversal_is_resolved_before_the_guard(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")
    cwd = repo / "a" / "b"
    cwd.mkdir(parents=True)
    monkeypatch.chdir(cwd)
    runtime = cli_main.build_runtime(os.path.join("..", "..", "target"), approver="alice", output=io.StringIO())
    assert runtime.workdir.root == (repo / "target").resolve()
    assert runtime.workdir.vcs_boundary == repo.resolve()
    assert canonical(repo / "target")

    code, out = run_cli(monkeypatch, cwd, "--workdir", os.path.join("..", "..", "target"))
    assert code == cli_main.EXIT_COMPLETED, out
    assert durable_files(repo / "target")
    assert porcelain(tmp_path, repo) == [] and stage_all(tmp_path, repo) == []


def test_all_spellings_of_one_location_resolve_identically(tmp_path, monkeypatch):
    home = tmp_path / "Chanakya-AI"
    home.mkdir()
    monkeypatch.chdir(home)
    spellings = [".", "." + os.sep, os.path.join("..", "Chanakya-AI"), str(home),
                 os.path.join(str(home), "x", "..")]
    link = tmp_path / "alias"
    make_dir_link(link, home)
    spellings.append(str(link))
    resolved = {resolve_workdir(s) for s in spellings}
    assert resolved == {home.resolve()}


# ===========================================================================
# TEST 10 — symlink / junction into a repository
# ===========================================================================


def test_link_into_a_repository_is_resolved_and_detected(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")
    inside = repo / "hidden-target"
    inside.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = outside / "innocent"
    make_dir_link(link, inside)
    # The raw spelling is outside the repository; the location is not.
    assert detect_vcs_boundary(Path(os.path.abspath(link))) is None
    runtime = cli_main.build_runtime(link, approver="alice", output=io.StringIO())
    assert runtime.workdir.root == inside.resolve()
    assert runtime.workdir.vcs_boundary == repo.resolve()

    code, out = run_cli(monkeypatch, outside, "--workdir", str(link / "sub"))
    assert code == cli_main.EXIT_COMPLETED, out
    assert canonical(inside / "sub") and durable_files(inside / "sub")
    assert porcelain(tmp_path, repo) == [] and stage_all(tmp_path, repo) == []


def test_store_root_link_that_escapes_the_workdir_is_refused(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")
    escape = repo / "not-excluded"
    escape.mkdir()
    wd = tmp_path / "wd"
    wd.mkdir()
    make_dir_link(wd / "evidence", escape)

    code, out = run_cli(monkeypatch, tmp_path, "--workdir", str(wd))
    assert code == cli_main.EXIT_CONFIG_ERROR and refused(out, "WORKDIR_STORE_ROOT_UNSAFE"), out
    assert list(escape.iterdir()) == []
    assert not any((wd / s).exists() for s in ("audit", "findings", "risk"))
    assert porcelain(tmp_path, repo) == []


def test_store_root_that_is_a_file_is_refused(tmp_path):
    wd = tmp_path / "wd"
    wd.mkdir()
    (wd / "audit").write_text("x", encoding="utf-8")
    with pytest.raises(WorkdirPlacementError) as exc:
        establish_durable_workdir(wd)
    assert exc.value.code == "WORKDIR_STORE_ROOT_UNSAFE"


def test_workdir_that_is_a_file_is_refused(tmp_path, monkeypatch):
    target = tmp_path / "file"
    target.write_text("x", encoding="utf-8")
    code, out = run_cli(monkeypatch, tmp_path, "--workdir", str(target))
    assert code == cli_main.EXIT_CONFIG_ERROR and refused(out, "WORKDIR_NOT_DIRECTORY"), out
    assert target.read_text(encoding="utf-8") == "x"


# ===========================================================================
# TEST 11, §28 — .git file (worktree, submodule-like) and .git directory
# ===========================================================================


def test_git_worktree_with_a_git_file_is_recognized(tmp_path, monkeypatch):
    main_repo = git_init(tmp_path, tmp_path / "main", commit=True)
    worktree = tmp_path / "wt"
    git(tmp_path, main_repo, "worktree", "add", "-q", str(worktree))
    assert (worktree / ".git").is_file() and not (worktree / ".git").is_dir()
    assert detect_vcs_boundary(resolve_workdir(worktree / ".chanakya")) == worktree.resolve()

    code, out = run_cli(monkeypatch, worktree)
    assert code == cli_main.EXIT_COMPLETED, out
    assert canonical(worktree / ".chanakya") and durable_files(worktree / ".chanakya")
    assert porcelain(tmp_path, worktree) == [] and stage_all(tmp_path, worktree) == []


def test_submodule_like_git_file_is_recognized(tmp_path):
    module = tmp_path / "super" / "module"
    module.mkdir(parents=True)
    (tmp_path / "super" / ".git").mkdir()
    (module / ".git").write_text("gitdir: ../.git/modules/module\n", encoding="utf-8")
    assert detect_vcs_boundary(resolve_workdir(module / "a" / "wd")) == module.resolve()
    assert detect_vcs_boundary(resolve_workdir(tmp_path / "super" / "other")) == (tmp_path / "super").resolve()


def test_git_directory_is_recognized(tmp_path):
    repo = git_init(tmp_path, tmp_path / "repo")
    assert (repo / ".git").is_dir()
    assert detect_vcs_boundary(resolve_workdir(repo / ".chanakya")) == repo.resolve()
    assert detect_vcs_boundary(resolve_workdir(repo)) == repo.resolve()


@pytest.mark.parametrize("inside", [".git/chanakya", ".git", ".GIT/x"] if sys.platform == "win32" else [".git/chanakya", ".git"])
def test_workdir_inside_git_metadata_is_refused(tmp_path, inside):
    repo = git_init(tmp_path, tmp_path / "repo")
    before = snapshot(repo / ".git")
    with pytest.raises(WorkdirPlacementError) as exc:
        establish_durable_workdir(repo / inside)
    assert exc.value.code == "WORKDIR_INSIDE_VCS_METADATA"
    assert snapshot(repo / ".git") == before


# ===========================================================================
# §13 — first-write ordering (M2)
# ===========================================================================


def _spy_writes(monkeypatch) -> List[Tuple[str, bool]]:
    """Records, at every store construction and every durable write,
    whether the canonical exclusion was already in place at that store's
    workdir."""
    writes: List[Tuple[str, bool]] = []

    def protected(store_root: Path) -> bool:
        return canonical(Path(store_root).resolve().parent)

    def wrap_init(cls, name):
        original = cls.__init__

        def __init__(self, root, *a, **k):
            writes.append((f"{name}.__init__", protected(Path(root))))
            original(self, root, *a, **k)

        monkeypatch.setattr(cls, "__init__", __init__)

    def wrap_write(cls, method, name):
        original = getattr(cls, method)

        def write(self, *a, **k):
            writes.append((f"{name}.{method}", protected(self.root)))
            return original(self, *a, **k)

        monkeypatch.setattr(cls, method, write)

    for cls, name in ((EvidenceStore, "evidence"), (FindingStore, "findings"),
                      (RiskAssessmentStore, "risk"), (FilesystemAuditLog, "audit")):
        wrap_init(cls, name)
    wrap_write(EvidenceStore, "append", "evidence")
    wrap_write(FindingStore, "append", "findings")
    wrap_write(RiskAssessmentStore, "append", "risk")
    wrap_write(FilesystemAuditLog, "emit", "audit")
    return writes


def test_exclusion_is_established_before_any_store_is_built_or_written(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")
    writes = _spy_writes(monkeypatch)
    code, out = run_cli(monkeypatch, repo)
    assert code == cli_main.EXIT_COMPLETED, out
    kinds = {name for name, _ in writes}
    assert {"evidence.__init__", "findings.__init__", "risk.__init__", "audit.__init__",
            "evidence.append", "findings.append", "risk.append", "audit.emit"} <= kinds
    assert all(ok for _, ok in writes), [w for w in writes if not w[1]]
    assert writes[0][0].endswith("__init__")


def test_build_runtime_runs_placement_before_any_store(tmp_path, monkeypatch):
    order: List[str] = []
    real = cli_main.establish_durable_workdir

    def spy(workdir):
        order.append("placement")
        return real(workdir)

    monkeypatch.setattr(cli_main, "establish_durable_workdir", spy)
    for name in ("EvidenceStore", "FindingStore", "RiskAssessmentStore", "FilesystemAuditLog"):
        original = getattr(cli_main, name)
        monkeypatch.setattr(cli_main, name, lambda root, _o=original, _n=name: (order.append(_n), _o(root))[1])
    runtime = cli_main.build_runtime(tmp_path / "wd", approver="alice", output=io.StringIO())
    assert order[0] == "placement" and order.count("placement") == 1 and len(order) == 5
    # M7: every durable store is rooted in the verified root, nowhere else.
    root = runtime.workdir.root
    for store, name in ((runtime.evidence_store, "evidence"), (runtime.finding_store, "findings"),
                        (runtime.risk_store, "risk"), (runtime.audit_log, "audit")):
        assert Path(store.root).resolve() == root / name


# ===========================================================================
# TEST 13 — failure between placement and execution
# ===========================================================================


def test_failure_after_placement_leaves_no_unprotected_data(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")

    def boom(*a, **k):
        raise RuntimeError("simulated failure after placement")

    monkeypatch.setattr(cli_main, "AuditEmitter", boom)  # built after every store root
    monkeypatch.chdir(repo)
    with pytest.raises(RuntimeError):
        cli_main.build_runtime(".chanakya", approver="alice", output=io.StringIO())
    wd = repo / ".chanakya"
    assert canonical(wd) and durable_files(wd) == []
    assert porcelain(tmp_path, repo) == [] and stage_all(tmp_path, repo) == []


def test_failure_while_establishing_the_exclusion_creates_no_store(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")

    def no_link(*a, **k):
        raise OSError(5, "SECRET-OS-TEXT C:\\very\\private\\path")

    monkeypatch.setattr(placement.os, "link", no_link)
    code, out = run_cli(monkeypatch, repo)
    assert code == cli_main.EXIT_CONFIG_ERROR and refused(out, "WORKDIR_EXCLUSION_UNAVAILABLE"), out
    assert "SECRET-OS-TEXT" not in out and "private" not in out
    wd = repo / ".chanakya"
    assert list(wd.iterdir()) == []  # no exclusion, no temporary file, no store
    assert porcelain(tmp_path, repo) == []


def test_agent_failure_mid_investigation_leaves_data_excluded(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")

    class Crashing(ScriptedModel):
        def next_turn(self, assembled_context):
            if self.turns >= 1:
                raise RuntimeError("provider crashed")
            return super().next_turn(assembled_context)

    monkeypatch.chdir(repo)
    monkeypatch.setattr(cli_main, "AnthropicProvider", Crashing)
    out = io.StringIO()
    cli_main.main([OBJECTIVE, "--approver", "alice"], environ={cli_main.API_KEY_ENV_VAR: KEY}, output=out)
    assert durable_files(repo / ".chanakya") and canonical(repo / ".chanakya")
    assert porcelain(tmp_path, repo) == [] and stage_all(tmp_path, repo) == []


# ===========================================================================
# TEST 14 — refusal messages carry the fixed code only
# ===========================================================================


def test_refusal_output_is_the_fixed_code_only(tmp_path, monkeypatch):
    secret_dir = tmp_path / "SECRET-DIRNAME-p20"
    wd = secret_dir / "wd"
    wd.mkdir(parents=True)
    (wd / EXCLUSION_FILE_NAME).write_bytes(b"!*\n")
    environ = {cli_main.API_KEY_ENV_VAR: KEY, "P20_ENV_SENTINEL": "ENV-VALUE-SENTINEL"}
    code, out = run_cli(monkeypatch, tmp_path, "--workdir", str(wd), environ=environ)
    assert code == cli_main.EXIT_CONFIG_ERROR
    assert out == "error: durable workdir placement refused (WORKDIR_EXCLUSION_MISMATCH)\n"
    for leaked in ("SECRET-DIRNAME", str(tmp_path), "OBJECTIVE-SENTINEL", KEY, "ENV-VALUE-SENTINEL",
                   "Errno", "Traceback", "gitignore"):
        assert leaked not in out, leaked


def test_placement_error_carries_no_value():
    for code in PLACEMENT_ERROR_CODES:
        error = WorkdirPlacementError(code)
        assert str(error) == code and error.args == (code,) and error.code == code
        assert error.__cause__ is None
    assert not issubclass(WorkdirPlacementError, (ValueError, OSError))
    assert all(code.isupper() and code.startswith("WORKDIR_") for code in PLACEMENT_ERROR_CODES)


def test_os_errors_never_chain_into_the_placement_error(tmp_path, monkeypatch):
    monkeypatch.setattr(placement.os, "link", lambda *a, **k: (_ for _ in ()).throw(OSError("PRIVATE")))
    with pytest.raises(WorkdirPlacementError) as exc:
        establish_durable_workdir(tmp_path / "wd")
    assert exc.value.__cause__ is None and exc.value.__suppress_context__
    assert "PRIVATE" not in str(exc.value)


# ===========================================================================
# TEST 12 — Review stays read-only (P20-INV-5)
# ===========================================================================


def test_review_creates_and_modifies_nothing(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")
    code, out = run_cli(monkeypatch, repo)
    assert code == cli_main.EXIT_COMPLETED
    iid = investigation_id(out)
    wd = repo / ".chanakya"
    before = snapshot(wd)
    review_out = io.StringIO()
    assert cli_main.main(["--review", iid], environ={}, output=review_out) == cli_main.EXIT_COMPLETED
    assert "consistency: consistent" in review_out.getvalue()
    assert snapshot(wd) == before


def test_review_does_not_repair_a_missing_exclusion(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")
    code, out = run_cli(monkeypatch, repo)
    iid = investigation_id(out)
    wd = repo / ".chanakya"
    (wd / EXCLUSION_FILE_NAME).unlink()
    before = snapshot(wd)
    assert cli_main.main(["--review", iid, "--workdir", str(wd)], environ={}, output=io.StringIO()) == 0
    assert snapshot(wd) == before and not (wd / EXCLUSION_FILE_NAME).exists()


def test_review_does_not_touch_a_tampered_exclusion(tmp_path, monkeypatch):
    repo = git_init(tmp_path, tmp_path / "repo")
    code, out = run_cli(monkeypatch, repo)
    iid = investigation_id(out)
    wd = repo / ".chanakya"
    (wd / EXCLUSION_FILE_NAME).write_bytes(b"!*\n")
    before = snapshot(wd)
    cli_main.main(["--review", iid, "--workdir", str(wd)], environ={}, output=io.StringIO())
    assert snapshot(wd) == before


def test_review_of_a_missing_workdir_creates_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli_main.main(["--review", "inv-x"], environ={}, output=io.StringIO()) == cli_main.EXIT_NOT_COMPLETED
    assert list(tmp_path.iterdir()) == []


def test_review_path_never_calls_placement():
    tree = ast.parse((_CHANAKYA / "cli" / "main.py").read_text(encoding="utf-8"))
    review = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "review_investigation")
    names = {n.id for n in ast.walk(review) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(review) if isinstance(n, ast.Attribute)}
    assert not names & {"establish_durable_workdir", "build_runtime", "mkdir", "EvidenceStore", "write_bytes",
                        "write_text", "open"}


# ===========================================================================
# §12 — repository-level .gitignore defense in depth (M5)
# ===========================================================================


def test_repository_gitignore_excludes_the_default_workdir(tmp_path):
    lines = (_REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".chanakya/" in lines
    probe = git(tmp_path, _REPO_ROOT, "check-ignore", "--no-index", "-q", ".chanakya/audit/probe.json", check=False)
    assert probe.returncode == 0


def test_default_workdir_is_dot_chanakya():
    assert cli_main._parser().parse_args(["x"]).workdir == ".chanakya"


# ===========================================================================
# P20-INV-6 — placement has no authority
# ===========================================================================


_AUTHORITY_MODULES = ("policy", "approval", "risk", "targets", "registry", "capability", "tools", "providers",
                      "contracts", "review", "evidence", "findings", "audit")


def test_placement_module_imports_nothing_with_authority():
    tree = ast.parse((_CHANAKYA / "runtime" / "workdir_placement.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "os", "stat", "uuid", "dataclasses", "pathlib", "typing"}, imported
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {
        n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"Verdict", "PolicyGateway", "ApprovalDecision", "RiskAssessment", "TargetStatus",
                        "PermissionLevel", "authorize", "approve", "evaluate"}


def test_no_authority_module_imports_placement():
    for path in _CHANAKYA.rglob("*.py"):
        if path.name == "workdir_placement.py" or path.parent.name == "cli":
            continue
        assert "workdir_placement" not in path.read_text(encoding="utf-8"), path


def test_composition_root_uses_placement_only_for_store_roots():
    tree = ast.parse((_CHANAKYA / "cli" / "main.py").read_text(encoding="utf-8"))
    build = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "build_runtime")
    uses = []
    for node in ast.walk(build):
        if isinstance(node, ast.Call):
            for arg in [*node.args, *[k.value for k in node.keywords]]:
                if any(isinstance(n, ast.Name) and n.id == "placement" for n in ast.walk(arg)):
                    func = node.func
                    uses.append(func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "?"))
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "placement":
            assert node.attr == "store_root", node.attr
    # Only the four durable stores (via store_root) and the returned
    # CliRuntime record receive it: never the Gateway, the approval
    # provider, the Risk Engine, the target registry or the controller.
    assert sorted(uses) == sorted(["EvidenceStore", "FindingStore", "RiskAssessmentStore", "FilesystemAuditLog",
                                   "CliRuntime"]), uses


def test_placement_does_not_change_security_decisions(tmp_path, monkeypatch):
    """The same investigation inside and outside a repository yields the
    same policy verdicts, approvals and risk ratings."""
    repo = git_init(tmp_path, tmp_path / "repo")
    outside = tmp_path / "outside"

    def decisions(cwd: Path, workdir: Path):
        code, out = run_cli(monkeypatch, cwd, "--workdir", str(workdir), "--require-approval")
        iid = investigation_id(out)
        log = FilesystemAuditLog(workdir / "audit")
        facts = []
        for record in log.list_by_investigation(iid):
            event = record.event
            if event.event_type in (AuditEventType.POLICY_EVALUATED, AuditEventType.APPROVAL_DECIDED):
                facts.append((event.event_type.value, event.details.get("verdict"), event.details.get("outcome")))
        risk = sorted((a.severity.value, a.confidence) for a in RiskAssessmentStore(workdir / "risk").list_by_investigation(iid))
        return code, facts, risk

    inside = decisions(repo, repo / ".chanakya")
    away = decisions(tmp_path, outside)
    assert inside == away and inside[0] == cli_main.EXIT_COMPLETED and inside[1] and inside[2]
