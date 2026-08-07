import json
import logging
import sqlite3
from datetime import datetime

from config.settings import DB_PATH

logger = logging.getLogger(__name__)


class Database:
    _conn: sqlite3.Connection | None = None

    @classmethod
    def init_db(cls) -> None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        cls._conn = sqlite3.connect(str(DB_PATH))
        cls._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                hostname TEXT,
                profile TEXT,
                use_tor INTEGER DEFAULT 0,
                command TEXT,
                open_ports INTEGER DEFAULT 0,
                services TEXT,
                total_vulns INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                summary TEXT,
                xml_path TEXT
            )
            """
        )
        cls._conn.commit()
        logger.info("Database initialised at %s", DB_PATH)

    @classmethod
    def _ensure(cls) -> None:
        if cls._conn is None:
            cls.init_db()

    @classmethod
    def log_scan(cls, report) -> None:
        try:
            cls._ensure()
            services = ", ".join(
                f"{p.port_id}/{p.service or p.product}" for p in report.open_ports
            )
            cls._conn.execute(
                """
                INSERT INTO scans (
                    timestamp, target, hostname, profile, use_tor, command,
                    open_ports, services, total_vulns, critical_count, summary, xml_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now().isoformat(timespec="seconds"),
                    report.target,
                    report.hostname,
                    report.profile,
                    int(report.use_tor),
                    report.command,
                    len(report.open_ports),
                    services,
                    len(report.vulnerabilities),
                    report.critical_count,
                    report.summary,
                    report.xml_path,
                ),
            )
            cls._conn.commit()
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to log scan to database: %s", exc)

    @classmethod
    def list_scans(cls) -> list[dict]:
        try:
            cls._ensure()
            cls._conn.row_factory = sqlite3.Row
            rows = cls._conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT 200"
            ).fetchall()
            return [dict(row) for row in rows]
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to list scans: %s", exc)
            return []

    @classmethod
    def json_export(cls) -> str:
        return json.dumps(cls.list_scans(), indent=2)

    @classmethod
    def close(cls) -> None:
        if cls._conn is not None:
            cls._conn.close()
            cls._conn = None
