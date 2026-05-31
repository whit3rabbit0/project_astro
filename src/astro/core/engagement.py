import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite

DEFAULT_DB_PATH = str(Path.home() / ".astro" / "engagements.db")

_CREATE_ENGAGEMENTS = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scope_config TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    params_json TEXT NOT NULL,
    raw_output TEXT NOT NULL,
    parsed_output TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
)
"""

_CREATE_TEMPLATES = """
CREATE TABLE IF NOT EXISTS engagement_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    scope_config TEXT,
    created_at TEXT NOT NULL
)
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EngagementManager:
    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self._db_path = str(Path(db_path).expanduser())
        self._db: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute(_CREATE_ENGAGEMENTS)
        await self._db.execute(_CREATE_FINDINGS)
        await self._db.execute(_CREATE_TEMPLATES)
        await self._db.commit()

    async def create_engagement(
        self,
        name: str,
        scope_config: Optional[Dict[str, Any]] = None,
    ) -> str:
        eng_id = str(uuid.uuid4())
        now = _now()
        await self._db.execute(  # type: ignore[union-attr]
            "INSERT INTO engagements (id, name, scope_config, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (eng_id, name, json.dumps(scope_config) if scope_config else None, now, now),
        )
        await self._db.commit()  # type: ignore[union-attr]
        return eng_id

    async def record_finding(
        self,
        engagement_id: str,
        tool: str,
        target: str,
        params: Dict[str, Any],
        raw_output: Dict[str, Any],
        parsed_output: Optional[Dict[str, Any]] = None,
    ) -> str:
        finding_id = str(uuid.uuid4())
        await self._db.execute(  # type: ignore[union-attr]
            "INSERT INTO findings (id, engagement_id, tool, target, params_json, raw_output, parsed_output, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding_id,
                engagement_id,
                tool,
                target,
                json.dumps(params),
                json.dumps(raw_output),
                json.dumps(parsed_output) if parsed_output is not None else None,
                _now(),
            ),
        )
        await self._db.commit()  # type: ignore[union-attr]
        return finding_id

    async def get_findings(
        self,
        engagement_id: str,
        tool: Optional[str] = None,
        target: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM findings WHERE engagement_id = ?"
        args: list[Any] = [engagement_id]
        if tool:
            query += " AND tool = ?"
            args.append(tool)
        if target:
            query += " AND target = ?"
            args.append(target)
        async with self._db.execute(query, args) as cursor:  # type: ignore[union-attr]
            rows = await cursor.fetchall()
        results = []
        for row in rows:
            record = dict(row)
            record["params_json"] = json.loads(record["params_json"])
            record["raw_output"] = json.loads(record["raw_output"])
            if record["parsed_output"] is not None:
                record["parsed_output"] = json.loads(record["parsed_output"])
            results.append(record)
        return results

    async def list_engagements(self) -> List[Dict[str, Any]]:
        async with self._db.execute("SELECT * FROM engagements ORDER BY created_at DESC") as cursor:  # type: ignore[union-attr]
            rows = await cursor.fetchall()
        results = []
        for row in rows:
            record = dict(row)
            if record["scope_config"] is not None:
                record["scope_config"] = json.loads(record["scope_config"])
            results.append(record)
        return results

    async def get_engagement(self, engagement_id: str) -> Optional[Dict[str, Any]]:
        async with self._db.execute(  # type: ignore[union-attr]
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        record = dict(row)
        if record["scope_config"] is not None:
            record["scope_config"] = json.loads(record["scope_config"])
        return record

    async def clone_engagement(
        self,
        source_id: str,
        new_name: str,
        clone_findings: bool = False,
    ) -> str:
        source = await self.get_engagement(source_id)
        if source is None:
            raise ValueError(f"Engagement {source_id!r} not found")

        new_id = await self.create_engagement(
            name=new_name,
            scope_config=source.get("scope_config"),
        )

        if clone_findings:
            findings = await self.get_findings(source_id)
            for f in findings:
                await self.record_finding(
                    engagement_id=new_id,
                    tool=f["tool"],
                    target=f["target"],
                    params=f["params_json"],
                    raw_output=f["raw_output"],
                    parsed_output=f.get("parsed_output"),
                )

        return new_id

    async def save_as_template(
        self,
        engagement_id: str,
        template_name: str,
    ) -> str:
        source = await self.get_engagement(engagement_id)
        if source is None:
            raise ValueError(f"Engagement {engagement_id!r} not found")

        template_id = str(uuid.uuid4())
        scope_json = json.dumps(source.get("scope_config")) if source.get("scope_config") else None
        await self._db.execute(  # type: ignore[union-attr]
            "INSERT INTO engagement_templates (id, name, scope_config, created_at) VALUES (?, ?, ?, ?)",
            (template_id, template_name, scope_json, _now()),
        )
        await self._db.commit()  # type: ignore[union-attr]
        return template_id

    async def create_from_template(
        self,
        template_name_or_id: str,
        engagement_name: str,
    ) -> str:
        async with self._db.execute(  # type: ignore[union-attr]
            "SELECT * FROM engagement_templates WHERE id = ? OR name = ?",
            (template_name_or_id, template_name_or_id),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            raise ValueError(f"Template {template_name_or_id!r} not found")

        record = dict(row)
        scope_config = json.loads(record["scope_config"]) if record["scope_config"] else None
        return await self.create_engagement(
            name=engagement_name,
            scope_config=scope_config,
        )

    async def list_templates(self) -> List[Dict[str, Any]]:
        async with self._db.execute(  # type: ignore[union-attr]
            "SELECT * FROM engagement_templates ORDER BY created_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
        results = []
        for row in rows:
            record = dict(row)
            if record["scope_config"] is not None:
                record["scope_config"] = json.loads(record["scope_config"])
            results.append(record)
        return results

    async def delete_template(self, template_id: str) -> bool:
        cursor = await self._db.execute(  # type: ignore[union-attr]
            "DELETE FROM engagement_templates WHERE id = ?", (template_id,)
        )
        await self._db.commit()  # type: ignore[union-attr]
        return cursor.rowcount > 0
