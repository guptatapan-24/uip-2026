# services/audit/audit_log.py
"""
Hash-chained append-only audit log.

Maintains cryptographic integrity of all validation decisions using SHA-256 hash chain:
  curr_hash = SHA256(prev_hash + record_data)

This prevents tampering and enables compliance auditing.

Database table: audit_log
  - id: auto-increment
  - decision_id: UUID
  - record_data: JSONB (full decision + validation chain)
  - prev_hash: VARCHAR(64) (SHA256 hex of previous entry)
  - curr_hash: VARCHAR(64) (SHA256 hex of this entry)
  - created_at: TIMESTAMP

TODO: Integrate Dhruv's database layer (db.orm)
"""

import hashlib
import json
from typing import Dict, Optional, List
from datetime import datetime
from pydantic import BaseModel


class AuditEntry(BaseModel):
    """Single audit log entry."""
    id: int
    decision_id: str
    record_data: Dict
    prev_hash: str
    curr_hash: str
    created_at: str


class AuditLog:
    """
    Append-only, hash-chained audit log.
    """
    
    def __init__(self, db_connection=None):
        """
        Initialize audit log.
        
        Args:
            db_connection: Async SQLAlchemy connection (TODO)
        """
        self.db = db_connection
        self.last_hash = None  # Track last hash for chaining
    
    async def initialize(self):
        """Load last hash from database on startup."""
        if not self.db:
            return
        
        # TODO: Query audit_log table for last entry
        # SELECT curr_hash FROM audit_log ORDER BY id DESC LIMIT 1
        # Set self.last_hash
        pass
    
    async def append(self, decision_id: str, record_data: Dict) -> Optional[AuditEntry]:
        """
        Append new record to audit log with hash chain.
        
        Args:
            decision_id: Unique decision identifier
            record_data: Full decision + validation data
            
        Returns:
            Created AuditEntry if successful, None on error
        """
        try:
            # Compute current hash
            curr_hash = self._compute_hash(self.last_hash or "", record_data)
            
            # Insert into database
            if self.db:
                # TODO: INSERT INTO audit_log (decision_id, record_data, prev_hash, curr_hash, created_at)
                # VALUES (?, ?, ?, ?, NOW())
                entry_id = await self._insert_entry(
                    decision_id,
                    record_data,
                    self.last_hash or "0" * 64,
                    curr_hash
                )
            else:
                entry_id = 1  # Stub
            
            # Update last hash
            self.last_hash = curr_hash
            
            return AuditEntry(
                id=entry_id,
                decision_id=decision_id,
                record_data=record_data,
                prev_hash=self.last_hash or "0" * 64,
                curr_hash=curr_hash,
                created_at=datetime.now().isoformat()
            )
        
        except Exception as e:
            print(f"Audit append failed: {e}")
            return None
    
    async def verify_chain(
        self,
        start_id: int = 1,
        end_id: Optional[int] = None
    ) -> Dict:
        """
        Verify hash chain integrity across audit log entries.
        
        Args:
            start_id: First entry ID to verify
            end_id: Last entry ID (default: latest)
            
        Returns:
            {
                "valid": bool,
                "total_entries": int,
                "verified_entries": int,
                "broken_links": [entry_id, ...],
                "message": str
            }
        """
        if not self.db:
            return {
                "valid": True,
                "total_entries": 0,
                "verified_entries": 0,
                "broken_links": [],
                "message": "No database connection"
            }
        
        try:
            # TODO: Query all entries in range
            # SELECT id, record_data, prev_hash, curr_hash FROM audit_log 
            # WHERE id >= start_id AND id <= end_id ORDER BY id
            
            entries = await self._fetch_entries(start_id, end_id)
            
            verified = 0
            broken_links = []
            
            prev_hash = "0" * 64  # Genesis hash
            
            for entry in entries:
                expected_hash = self._compute_hash(prev_hash, entry["record_data"])
                
                if expected_hash == entry["curr_hash"]:
                    verified += 1
                else:
                    broken_links.append(entry["id"])
                
                prev_hash = entry["curr_hash"]
            
            return {
                "valid": len(broken_links) == 0,
                "total_entries": len(entries),
                "verified_entries": verified,
                "broken_links": broken_links,
                "message": "Chain verified" if not broken_links else f"Tamper detected at entries: {broken_links}"
            }
        
        except Exception as e:
            print(f"Chain verification failed: {e}")
            return {
                "valid": False,
                "total_entries": 0,
                "verified_entries": 0,
                "broken_links": [],
                "message": f"Verification error: {str(e)}"
            }
    
    @staticmethod
    def _compute_hash(prev_hash: str, record_data: Dict) -> str:
        """
        Compute SHA-256 hash of hash chain.
        
        Args:
            prev_hash: Previous entry's hash (or genesis "0"*64)
            record_data: Current record
            
        Returns:
            SHA-256 hex digest
        """
        combined = prev_hash + json.dumps(record_data, sort_keys=True)
        return hashlib.sha256(combined.encode()).hexdigest()
    
    async def _insert_entry(
        self,
        decision_id: str,
        record_data: Dict,
        prev_hash: str,
        curr_hash: str
    ) -> int:
        """Insert entry into audit_log table. TODO: Implement."""
        return 1
    
    async def _fetch_entries(self, start_id: int, end_id: Optional[int]) -> List[Dict]:
        """Fetch entries from audit_log. TODO: Implement."""
        return []


# Singleton
_audit_log: Optional[AuditLog] = None


def get_audit_log(db_connection=None) -> AuditLog:
    """Get or create audit log singleton."""
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog(db_connection)
    return _audit_log
