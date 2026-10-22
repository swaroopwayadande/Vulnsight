"""Local SQLite scan history."""
from pathlib import Path
from sqlalchemy import create_engine, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
engine = create_engine(f"sqlite:///{DATA_DIR / 'vulnsight.db'}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
class Base(DeclarativeBase): pass
class ScanRecord(Base):
    __tablename__ = "scans"
    scan_id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp_utc: Mapped[str] = mapped_column(String)
    hostname: Mapped[str] = mapped_column(String)
    result_json: Mapped[str] = mapped_column(Text)
Base.metadata.create_all(engine)

def save_scan(result: dict) -> None:
    import json
    with SessionLocal() as db:
        db.merge(ScanRecord(scan_id=result["scan_id"], timestamp_utc=result["timestamp_utc"], hostname=result["hostname"], result_json=json.dumps(result)))
        db.commit()

def get_scan(scan_id: str) -> dict | None:
    import json
    with SessionLocal() as db:
        row = db.get(ScanRecord, scan_id)
        return json.loads(row.result_json) if row else None

def list_scans(limit: int = 25) -> list[dict]:
    import json
    with SessionLocal() as db:
        rows = db.query(ScanRecord).order_by(ScanRecord.timestamp_utc.desc()).limit(limit).all()
        return [json.loads(row.result_json) for row in rows]
