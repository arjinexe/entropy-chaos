"""SQLite-backed run history for regression detection across scans."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from entropy.core.models import EntropyReport, Finding, Severity


# ---------------------------------------------------------------------------
# DB path
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = Path.home() / ".entropy" / "history.db"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RunRecord:
    id:           str
    target:       str
    started_at:   str
    finished_at:  str
    status:       str
    findings_count: int
    critical:     int
    high:         int
    medium:       int
    low:          int
    stats:        Dict

@dataclass
class DiffResult:
    baseline_run_id:   Optional[str]
    new_findings:      List[Finding] = field(default_factory=list)
    fixed_findings:    List[Finding] = field(default_factory=list)   # in baseline, not in current
    unchanged_findings: List[Finding] = field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        return len(self.new_findings) > 0

    @property
    def summary(self) -> str:
        return (
            f"Diff vs {self.baseline_run_id or 'no baseline'}: "
            f"+{len(self.new_findings)} new, "
            f"-{len(self.fixed_findings)} fixed, "
            f"={len(self.unchanged_findings)} unchanged"
        )


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class FindingHistory:
    """
    Persists Entropy runs to a local SQLite database.
    Enables regression detection, trend tracking, and CI diffing.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path or DEFAULT_DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_run(self, report: EntropyReport) -> str:
        """Persist a completed run. Returns the run ID."""
        with self._connect() as conn:
            summary = report.summary()
            conn.execute("""
                INSERT OR REPLACE INTO runs
                    (id, target, started_at, finished_at, status,
                     findings_count, critical, high, medium, low, stats_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.id,
                report.target,
                report.started_at.isoformat(),
                report.finished_at.isoformat() if report.finished_at else None,
                report.status.value,
                len(report.findings),
                summary.get("critical", 0),
                summary.get("high", 0),
                summary.get("medium", 0),
                summary.get("low", 0),
                json.dumps(report.stats),
            ))

            for f in report.findings:
                conn.execute("""
                    INSERT OR IGNORE INTO findings
                        (id, run_id, fingerprint, type, severity, title,
                         description, endpoint, persona, remediation,
                         discovered_at, evidence_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.id,
                    report.id,
                    self._fingerprint(f),
                    f.type.value,
                    f.severity.value,
                    f.title,
                    f.description,
                    f.endpoint,
                    f.persona,
                    f.remediation,
                    f.discovered_at.isoformat(),
                    json.dumps(f.evidence),
                ))

        return report.id

    def diff_with_last(
        self,
        report: EntropyReport,
        target: Optional[str] = None,
    ) -> DiffResult:
        """
        Compare `report` findings against the most recent previous run for
        the same target. Returns new/fixed/unchanged findings.
        """
        tgt = target or report.target
        last_run = self._last_run_for(tgt, exclude_id=report.id)

        if not last_run:
            return DiffResult(baseline_run_id=None, new_findings=report.findings)

        # Fingerprints from baseline
        baseline_fps: Dict[str, Finding] = {}
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint, type, severity, title, description, endpoint "
                "FROM findings WHERE run_id = ?",
                (last_run,),
            ).fetchall()
            for row in rows:
                baseline_fps[row[0]] = row

        current_fps = {self._fingerprint(f): f for f in report.findings}

        new_findings     = [f for fp, f in current_fps.items() if fp not in baseline_fps]
        fixed_fps        = set(baseline_fps.keys()) - set(current_fps.keys())
        unchanged        = [f for fp, f in current_fps.items() if fp in baseline_fps]

        # Reconstruct "fixed" as minimal Finding objects
        fixed: List[Finding] = []
        with self._connect() as conn:
            for fp in fixed_fps:
                row = conn.execute(
                    "SELECT id, type, severity, title, description, endpoint "
                    "FROM findings WHERE fingerprint = ? AND run_id = ?",
                    (fp, last_run),
                ).fetchone()
                if row:
                    from entropy.core.models import FindingType
                    fixed.append(Finding(
                        id=row[0],
                        type=FindingType(row[1]),
                        severity=Severity(row[2]),
                        title=row[3],
                        description=row[4],
                        endpoint=row[5],
                    ))

        return DiffResult(
            baseline_run_id=last_run,
            new_findings=new_findings,
            fixed_findings=fixed,
            unchanged_findings=unchanged,
        )

    def list_runs(
        self,
        target: Optional[str] = None,
        limit: int = 20,
    ) -> List[RunRecord]:
        """Return recent runs, optionally filtered by target."""
        with self._connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT * FROM runs WHERE target = ? ORDER BY started_at DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()

        return [self._row_to_run(r) for r in rows]

    def get_findings(self, run_id: str) -> List[Dict]:
        """Return all raw finding dicts for a run."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE run_id = ? ORDER BY severity",
                (run_id,),
            ).fetchall()
        cols = [
            "id", "run_id", "fingerprint", "type", "severity",
            "title", "description", "endpoint", "persona",
            "remediation", "discovered_at", "evidence_json",
        ]
        return [dict(zip(cols, row)) for row in rows]

    def trend(self, target: str, last_n: int = 10) -> List[Dict]:
        """Return severity counts per run for trend charts."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT id, started_at, critical, high, medium, low
                   FROM runs WHERE target = ?
                   ORDER BY started_at DESC LIMIT ?""",
                (target, last_n),
            ).fetchall()
        return [
            {"run_id": r[0], "started_at": r[1], "critical": r[2],
             "high": r[3], "medium": r[4], "low": r[5]}
            for r in reversed(rows)
        ]

    def compare_runs(self, run_a: str, run_b: str) -> Dict:
        """Compare two specific runs by ID."""
        fps_a = self._fps_for_run(run_a)
        fps_b = self._fps_for_run(run_b)
        return {
            "only_in_a": list(fps_a - fps_b),
            "only_in_b": list(fps_b - fps_a),
            "in_both":   list(fps_a & fps_b),
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    id             TEXT PRIMARY KEY,
                    target         TEXT NOT NULL,
                    started_at     TEXT,
                    finished_at    TEXT,
                    status         TEXT,
                    findings_count INTEGER,
                    critical       INTEGER DEFAULT 0,
                    high           INTEGER DEFAULT 0,
                    medium         INTEGER DEFAULT 0,
                    low            INTEGER DEFAULT 0,
                    stats_json     TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id            TEXT PRIMARY KEY,
                    run_id        TEXT NOT NULL,
                    fingerprint   TEXT NOT NULL,
                    type          TEXT,
                    severity      TEXT,
                    title         TEXT,
                    description   TEXT,
                    endpoint      TEXT,
                    persona       TEXT,
                    remediation   TEXT,
                    discovered_at TEXT,
                    evidence_json TEXT,
                    FOREIGN KEY (run_id) REFERENCES runs(id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_fp  ON findings(fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_target  ON runs(target)")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    @staticmethod
    def _fingerprint(f: Finding) -> str:
        """Stable hash of (type, title, endpoint) — ignores ID / timestamps."""
        key = f"{f.type.value}|{f.title}|{f.endpoint}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _last_run_for(self, target: str, exclude_id: Optional[str] = None) -> Optional[str]:
        with self._connect() as conn:
            if exclude_id:
                row = conn.execute(
                    "SELECT id FROM runs WHERE target = ? AND id != ? "
                    "AND status = 'completed' ORDER BY started_at DESC LIMIT 1",
                    (target, exclude_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT id FROM runs WHERE target = ? AND status = 'completed' "
                    "ORDER BY started_at DESC LIMIT 1",
                    (target,),
                ).fetchone()
        return row[0] if row else None

    def _fps_for_run(self, run_id: str) -> set:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint FROM findings WHERE run_id = ?", (run_id,)
            ).fetchall()
        return {r[0] for r in rows}

    @staticmethod
    def _row_to_run(row) -> RunRecord:
        return RunRecord(
            id=row[0], target=row[1], started_at=row[2], finished_at=row[3],
            status=row[4], findings_count=row[5], critical=row[6],
            high=row[7], medium=row[8], low=row[9],
            stats=json.loads(row[10] or "{}"),
        )
