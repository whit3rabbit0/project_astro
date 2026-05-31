"""Shell session management for tracking reverse/bind/web shells and other connections."""
import os
import signal
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum

import structlog

logger = structlog.get_logger()


class ShellType(str, Enum):
    REVERSE = "reverse"
    BIND = "bind"
    WEB = "web"
    WINRM = "winrm"
    SSH = "ssh"
    PSEXEC = "psexec"
    WMIEXEC = "wmiexec"


class PrivilegeLevel(str, Enum):
    USER = "user"
    ROOT = "root"
    SYSTEM = "SYSTEM"
    ADMIN = "admin"
    UNKNOWN = "unknown"


@dataclass
class ShellSession:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    port: int = 0
    user: str = ""
    privilege: PrivilegeLevel = PrivilegeLevel.UNKNOWN
    shell_type: ShellType = ShellType.REVERSE
    status: str = "active"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    notes: str = ""
    pid: int | None = None


class ShellManager:
    def __init__(self) -> None:
        self._sessions: dict[str, ShellSession] = {}

    def create_session(
        self,
        target: str,
        port: int = 0,
        user: str = "",
        shell_type: ShellType = ShellType.REVERSE,
        privilege: PrivilegeLevel = PrivilegeLevel.UNKNOWN,
        pid: int | None = None,
        notes: str = "",
    ) -> ShellSession:
        session = ShellSession(
            target=target,
            port=port,
            user=user,
            shell_type=shell_type,
            privilege=privilege,
            pid=pid,
            notes=notes,
        )
        self._sessions[session.id] = session
        logger.info("shell_session_created", id=session.id, target=target, type=shell_type.value)
        return session

    def get_session(self, session_id: str) -> ShellSession | None:
        return self._sessions.get(session_id)

    def list_sessions(self, status: str | None = None) -> list[ShellSession]:
        sessions = list(self._sessions.values())
        if status:
            sessions = [s for s in sessions if s.status == status]
        return sessions

    def update_session(self, session_id: str, **kwargs: object) -> ShellSession | None:
        session = self._sessions.get(session_id)
        if not session:
            return None
        for key, value in kwargs.items():
            if hasattr(session, key):
                setattr(session, key, value)
        return session

    def kill_session(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if not session:
            return False
        session.status = "dead"
        if session.pid:
            try:
                os.kill(session.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        return True

    def to_dict(self) -> list[dict]:  # type: ignore[type-arg]
        return [asdict(s) for s in self._sessions.values()]

    def get_summary(self) -> dict:  # type: ignore[type-arg]
        active = sum(1 for s in self._sessions.values() if s.status == "active")
        return {
            "total": len(self._sessions),
            "active": active,
            "dead": len(self._sessions) - active,
            "sessions": self.to_dict(),
        }
