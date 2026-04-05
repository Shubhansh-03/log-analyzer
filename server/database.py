from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Text,
    Boolean,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime

DATABASE_URL = "sqlite:///./secure_logs.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="active")


class RawLog(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, ForeignKey("devices.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    raw_content = Column(Text)
    predicted_source = Column(String)
    source_confidence = Column(Float)


class ParsedLog(Base):
    __tablename__ = "parsed_logs"
    id = Column(Integer, primary_key=True, index=True)
    raw_log_id = Column(Integer, ForeignKey("logs.id"))
    template_id = Column(String, index=True)
    parsed_json = Column(Text)  # Storing JSON string representation


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    log_id = Column(
        Integer, ForeignKey("logs.id"), nullable=True
    )  # Nullable for aggregated alerts
    anomaly_score = Column(Float)
    severity = Column(String)  # LOW, MEDIUM, HIGH, CRITICAL
    reason = Column(Text)
    recommended_action = Column(Text)
    resolved = Column(Boolean, default=False)


class Template(Base):
    __tablename__ = "templates"
    id = Column(String, primary_key=True, index=True)  # MD5 hash of template string
    template_text = Column(Text)
    frequency = Column(Integer, default=1)


class CryptoEvent(Base):
    __tablename__ = "crypto_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    device_id = Column(String, ForeignKey("devices.id"))
    event_type = Column(String)  # e.g., "Decryption", "Signature Verification"
    status = Column(String)  # e.g., "Success", "Failure"
    details = Column(Text, nullable=True)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
