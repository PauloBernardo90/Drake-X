"""Workspace management.

A Drake-X workspace is a self-contained directory holding everything for one
engagement: the workspace config, the engagement scope file, the SQLite
database of sessions, the per-session run directories, and the append-only
audit log.

Default location is ``~/.drake-x/workspaces/<name>/``. Operators may also
init a workspace inside their current working directory with ``--here``.

The workspace is the unit of reproducibility: copy a workspace directory and
you can re-render every report and re-run any analysis on the same evidence.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..exceptions import WorkspaceError
from ..safety.scope_file import write_scope_template
from ..utils.pathing import expand_user_path

WORKSPACE_FILE = "workspace.toml"
SCOPE_FILE = "scope.yaml"
DB_FILE = "drake.db"
RUNS_DIR = "runs"
AUDIT_FILE = "audit.log"

DEFAULT_WORKSPACES_ROOT = expand_user_path("~/.drake-x/workspaces")


@dataclass
class WorkspaceConfig:
    """Per-workspace configuration loaded from ``workspace.toml``."""

    name: str
    created_at: str | None = None
    operator: str | None = None
    notes: str | None = None
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:1b"
    default_timeout: int = 180
    default_module: str = "recon_passive"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_toml(self) -> str:
        """Serialize back to TOML.

        We hand-write TOML because the standard library only ships
        ``tomllib`` (read-only). The output stays trivially readable.
        """
        lines: list[str] = []
        lines.append("# Drake-X workspace configuration")
        lines.append(f'name = "{self.name}"')
        if self.created_at:
            lines.append(f'created_at = "{self.created_at}"')
        if self.operator:
            lines.append(f'operator = "{self.operator}"')
        if self.notes:
            lines.append(f'notes = "{self.notes}"')
        lines.append("")
        lines.append("[ai]")
        lines.append(f'ollama_url = "{self.ollama_url}"')
        lines.append(f'ollama_model = "{self.ollama_model}"')
        lines.append("")
        lines.append("[engine]")
        lines.append(f"default_timeout = {self.default_timeout}")
        lines.append(f'default_module = "{self.default_module}"')
        lines.append("")
        return "\n".join(lines) + "\n"


@dataclass
class Workspace:
    """A loaded Drake-X workspace."""

    name: str
    root: Path
    config: WorkspaceConfig

    # ----- canonical paths -------------------------------------------------

    @property
    def config_path(self) -> Path:
        return self.root / WORKSPACE_FILE

    @property
    def scope_path(self) -> Path:
        return self.root / SCOPE_FILE

    @property
    def db_path(self) -> Path:
        return self.root / DB_FILE

    @property
    def runs_dir(self) -> Path:
        return self.root / RUNS_DIR

    @property
    def audit_log_path(self) -> Path:
        return self.root / AUDIT_FILE

    def session_dir(self, session_id: str) -> Path:
        return self.runs_dir / session_id

    def ensure_directories(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)

    # ----- factory methods -------------------------------------------------

    @classmethod
    def init(
        cls,
        name: str,
        *,
        root: Path | None = None,
        operator: str | None = None,
        force: bool = False,
    ) -> "Workspace":
        """Scaffold a new workspace on disk.

        ``root`` is the parent directory the workspace lives under. When not
        given we use ``~/.drake-x/workspaces``. The workspace itself is
        ``root/name/``.
        """
        from ..utils.timefmt import isoformat_utc, utcnow

        parent = (root or DEFAULT_WORKSPACES_ROOT).expanduser().resolve()
        ws_root = parent / name

        if ws_root.exists() and not force:
            if any(ws_root.iterdir()):
                raise WorkspaceError(
                    f"workspace directory {ws_root} already exists and is not empty; "
                    "pass --force to reuse it"
                )

        ws_root.mkdir(parents=True, exist_ok=True)
        (ws_root / RUNS_DIR).mkdir(parents=True, exist_ok=True)

        cfg = WorkspaceConfig(
            name=name,
            operator=operator,
            created_at=isoformat_utc(utcnow()),
        )
        (ws_root / WORKSPACE_FILE).write_text(cfg.to_toml(), encoding="utf-8")

        scope_path = ws_root / SCOPE_FILE
        if not scope_path.exists():
            write_scope_template(scope_path)

        # Initialize an empty audit log so callers can rely on the file
        # existing without an extra branch in the writer.
        audit_path = ws_root / AUDIT_FILE
        if not audit_path.exists():
            audit_path.write_text("", encoding="utf-8")

        return cls(name=name, root=ws_root, config=cfg)

    @classmethod
    def load(cls, name_or_path: str, *, root: Path | None = None) -> "Workspace":
        """Load an existing workspace by name or absolute path."""
        candidate = Path(name_or_path).expanduser()
        if candidate.is_absolute() or candidate.exists():
            ws_root = candidate.resolve()
        else:
            parent = (root or DEFAULT_WORKSPACES_ROOT).expanduser().resolve()
            ws_root = parent / name_or_path

        if not ws_root.exists() or not (ws_root / WORKSPACE_FILE).exists():
            raise WorkspaceError(
                f"no workspace found at {ws_root}. Run `drake init {name_or_path}` first."
            )

        cfg = _load_workspace_config(ws_root / WORKSPACE_FILE)
        ws = cls(name=cfg.name, root=ws_root, config=cfg)
        ws.ensure_directories()
        return ws

    # ----- introspection ---------------------------------------------------

    def manifest(self) -> dict[str, Any]:
        """Return a JSON-serializable summary of the workspace state."""
        return {
            "name": self.name,
            "root": str(self.root),
            "config": {
                "name": self.config.name,
                "operator": self.config.operator,
                "created_at": self.config.created_at,
                "ollama_url": self.config.ollama_url,
                "ollama_model": self.config.ollama_model,
                "default_timeout": self.config.default_timeout,
                "default_module": self.config.default_module,
            },
            "scope_path": str(self.scope_path),
            "db_path": str(self.db_path),
            "runs_dir": str(self.runs_dir),
            "audit_log_path": str(self.audit_log_path),
            "scope_present": self.scope_path.exists(),
        }


# ----- internals -------------------------------------------------------------


def _load_workspace_config(path: Path) -> WorkspaceConfig:
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except Exception as exc:  # noqa: BLE001
        raise WorkspaceError(f"invalid TOML in {path}: {exc}") from exc

    ai = data.get("ai", {}) or {}
    engine = data.get("engine", {}) or {}
    return WorkspaceConfig(
        name=str(data.get("name") or path.parent.name),
        created_at=data.get("created_at"),
        operator=data.get("operator"),
        notes=data.get("notes"),
        ollama_url=str(ai.get("ollama_url", "http://127.0.0.1:11434")),
        ollama_model=str(ai.get("ollama_model", "llama3.2:1b")),
        default_timeout=int(engine.get("default_timeout", 180)),
        default_module=str(engine.get("default_module", "recon_passive")),
        extra={k: v for k, v in data.items() if k not in {"name", "ai", "engine", "created_at", "operator", "notes"}},
    )


# Convenience for places that just need to know the default location.
def default_workspaces_root() -> Path:
    return DEFAULT_WORKSPACES_ROOT


# Used by the CLI to print "machine-readable" workspace info.
def workspace_to_json(workspace: Workspace) -> str:
    return json.dumps(workspace.manifest(), indent=2)
