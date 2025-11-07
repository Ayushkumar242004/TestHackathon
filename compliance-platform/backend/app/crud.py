# app/crud.py

from typing import List, Optional
from time import time

from sqlmodel import SQLModel, Session, select, create_engine
from app.models import Inspection, Certificate, AgentAction
from app.settings import settings


# ---------- Database Setup ----------
engine = create_engine(settings.DATABASE_URL, echo=False)


def init_db():
    """Initialize all SQLModel tables."""
    SQLModel.metadata.create_all(engine)


# ---------- INSPECTION CRUD ----------
def create_inspection(obj: dict) -> Inspection:
    """Create and store a new inspection record."""
    with Session(engine) as s:
        ins = Inspection(**obj)
        s.add(ins)
        s.commit()
        s.refresh(ins)
        return ins


def get_inspection_by_content_hash(content_hash: str) -> Optional[Inspection]:
    """Retrieve an inspection by its content hash."""
    with Session(engine) as s:
        q = select(Inspection).where(Inspection.content_hash == content_hash)
        return s.exec(q).first()


def list_inspections(limit: int = 20) -> List[Inspection]:
    """List recent inspections."""
    with Session(engine) as s:
        q = select(Inspection).order_by(Inspection.timestamp.desc()).limit(limit)
        return s.exec(q).all()


# ---------- CERTIFICATE CRUD ----------
def create_certificate(obj: dict) -> Certificate:
    """Store a newly issued certificate."""
    with Session(engine) as s:
        cert = Certificate(**obj)
        s.add(cert)
        s.commit()
        s.refresh(cert)
        return cert


def get_certificate_by_hash(cert_hash: str) -> Optional[Certificate]:
    """Fetch a certificate using its hash."""
    with Session(engine) as s:
        q = select(Certificate).where(Certificate.cert_hash == cert_hash)
        return s.exec(q).first()


def get_valid_certificates() -> List[Certificate]:
    """Get all certificates that are currently valid."""
    with Session(engine) as s:
        q = select(Certificate).where(Certificate.revoked == False)
        return s.exec(q).all()


def mark_certificate_revoked(cert_hash: str) -> Optional[Certificate]:
    """Revoke a certificate by its hash."""
    with Session(engine) as s:
        q = select(Certificate).where(Certificate.cert_hash == cert_hash)
        cert = s.exec(q).first()
        if not cert:
            return None
        cert.revoked = True
        s.add(cert)
        s.commit()
        s.refresh(cert)
        return cert


# Compatibility alias for existing imports
def revoke_certificate(cert_hash: str) -> Optional[Certificate]:
    """Alias for mark_certificate_revoked() to maintain backward compatibility."""
    return mark_certificate_revoked(cert_hash)


# ---------- AGENT ACTIONS ----------
def create_agent_action(obj: dict) -> AgentAction:
    """Record an agent's action (for audit trail)."""
    with Session(engine) as s:
        act = AgentAction(**obj)
        s.add(act)
        s.commit()
        s.refresh(act)
        return act


def list_agent_actions(limit: int = 50) -> List[AgentAction]:
    """List recent agent actions."""
    with Session(engine) as s:
        q = select(AgentAction).order_by(AgentAction.timestamp.desc()).limit(limit)
        return s.exec(q).all()


# ---------- UTILITY ----------
def purge_expired_certificates():
    """Revoke all expired certificates automatically (for scheduler)."""
    now = int(time())
    with Session(engine) as s:
        q = select(Certificate).where(
            Certificate.expiry.is_not(None),
            Certificate.expiry < now,
            Certificate.revoked == False,
        )
        expired = s.exec(q).all()
        for c in expired:
            c.revoked = True
            s.add(c)
        s.commit()
        return len(expired)

# app/crud.py (append or integrate into your existing file)
from sqlmodel import Session, select
from app.models import Inspection, Certificate  # ensure these exist
from .settings import settings
from sqlmodel import SQLModel

# existing 'engine' creation should be present already
# engine = create_engine(settings.DATABASE_URL, echo=False)

def list_inspections(limit: int = 50, offset: int = 0):
    """
    Return a list of Inspection objects (limit/offset).
    """
    with Session(engine) as s:
        q = select(Inspection).offset(offset).limit(limit)
        rows = s.exec(q).all()
        return rows

def get_certificate_by_hash(cert_hash: str):
    with Session(engine) as s:
        # normalize cert_hash to '0x' prefixed if your DB uses that
        q = select(Certificate).where(Certificate.cert_hash == cert_hash)
        return s.exec(q).first()

def list_certificates(only_valid: bool = False, limit: int = 50, offset: int = 0):
    from time import time
    now = int(time())
    with Session(engine) as s:
        q = select(Certificate)
        if only_valid:
            # certificate row must not be revoked and not expired
            q = q.where(Certificate.revoked == False)
            q = q.where((Certificate.expiry == 0) | (Certificate.expiry > now))
        q = q.offset(offset).limit(limit)
        return s.exec(q).all()
    
# app/crud.py additions (append)

def get_inspection_by_id(inspection_id: int):
    with Session(engine) as s:
        q = select(Inspection).where(Inspection.id == inspection_id)
        return s.exec(q).first()

def list_inspections(limit: int = 50, offset: int = 0):
    with Session(engine) as s:
        q = select(Inspection).offset(offset).limit(limit)
        return s.exec(q).all()

def get_certificate_by_hash(cert_hash: str):
    with Session(engine) as s:
        q = select(Certificate).where(Certificate.cert_hash == cert_hash)
        return s.exec(q).first()

def list_certificates(only_valid: bool = False, limit: int = 100, offset: int = 0):
    from time import time
    now = int(time())
    with Session(engine) as s:
        q = select(Certificate)
        if only_valid:
            q = q.where(Certificate.revoked == False)
            q = q.where((Certificate.expiry == 0) | (Certificate.expiry > now))
        q = q.offset(offset).limit(limit)
        return s.exec(q).all()

