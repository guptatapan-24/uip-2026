"""
Unit tests for AuditLog hash chain.
"""
import pytest
from audit.audit_log import AuditLog, AuditEntry
import asyncio

@pytest.mark.asyncio
def test_append_creates_correct_hash():
    log = AuditLog()
    entry = asyncio.run(log.append("dec1", {"foo": "bar"}))
    assert entry.curr_hash is not None
    assert len(entry.curr_hash) == 64

@pytest.mark.asyncio
def test_verify_chain_passes_on_clean_log():
    log = AuditLog()
    asyncio.run(log.append("dec1", {"foo": "bar"}))
    asyncio.run(log.append("dec2", {"baz": "qux"}))
    result = asyncio.run(log.verify_chain())
    assert result['valid']

@pytest.mark.asyncio
def test_verify_chain_fails_after_tampering():
    log = AuditLog()
    entry1 = asyncio.run(log.append("dec1", {"foo": "bar"}))
    entry2 = asyncio.run(log.append("dec2", {"baz": "qux"}))
    # Tamper with entry2's prev_hash
    entry2.prev_hash = "0" * 64
    # Simulate verify_chain
    result = asyncio.run(log.verify_chain())
    assert not result['valid']
