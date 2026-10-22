"""Local SQLite scan history."""

import json
from pathlib import Path

from sqlalchemy import String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)

engine = create_engine(
    f"sqlite:///{DATA_DIR / 'vulnsight.db'}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    """Base class for local database models."""


class ScanRecord(Base):
    """Persist one serialized scan result for the local history view."""

    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp_utc: Mapped[str] = mapped_column(String)
    hostname: Mapped[str] = mapped_column(String)
    result_json: Mapped[str] = mapped_column(Text)


Base.metadata.create_all(engine)


def save_scan(result: dict) -> None:
    """Insert or replace a scan result in local history."""
    with SessionLocal() as database:
        database.merge(
            ScanRecord(
                scan_id=result["scan_id"],
                timestamp_utc=result["timestamp_utc"],
                hostname=result["hostname"],
                result_json=json.dumps(result),
            )
        )
        database.commit()


def get_scan(scan_id: str) -> dict | None:
    """Load a scan result by ID, or return ``None`` when it is missing."""
    with SessionLocal() as database:
        record = database.get(ScanRecord, scan_id)
        return json.loads(record.result_json) if record else None


def list_scans(limit: int = 25) -> list[dict]:
    """Return the latest scan results, newest first."""
    with SessionLocal() as database:
        records = (
            database.query(ScanRecord)
            .order_by(ScanRecord.timestamp_utc.desc())
            .limit(limit)
            .all()
        )
        return [json.loads(record.result_json) for record in records]
