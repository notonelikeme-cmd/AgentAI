"""Tests for FindingsDB — SQLite findings registry."""
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from unittest.mock import patch

# Patch DB_PATH to a temp file before importing
with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
    _TEST_DB = Path(f.name)


@pytest.fixture
def db():
    from core.analysis.findingsdb import FindingsDB, DB_PATH
    import core.analysis.findingsdb as fdb_module
    # Redirect to temp DB
    orig = fdb_module.DB_PATH
    fdb_module.DB_PATH = _TEST_DB
    instance = FindingsDB()
    yield instance
    instance.close()
    fdb_module.DB_PATH = orig


class TestAdd:
    def test_add_returns_string_id(self, db):
        fid = db.add(title="Test finding", severity="High")
        assert isinstance(fid, str)
        assert len(fid) == 8

    def test_add_with_all_fields(self, db):
        fid = db.add(
            title="Reentrancy in withdraw()",
            severity="Critical",
            contract="src/Vault.sol",
            hypothesis="IF reentrancy THEN drain BECAUSE CEI violated",
            gate_status="6",
            net_profit=50_000.0,
            platform="Cantina",
            notes="Confirmed with Foundry PoC",
        )
        f = db.get(fid)
        assert f["title"] == "Reentrancy in withdraw()"
        assert f["severity"] == "Critical"
        assert f["contract"] == "src/Vault.sol"
        assert f["net_profit"] == 50_000.0
        assert f["status"] == "pending"

    def test_add_multiple_unique_ids(self, db):
        ids = {db.add(title=f"Finding {i}", severity="Low") for i in range(10)}
        assert len(ids) == 10


class TestGet:
    def test_get_existing(self, db):
        fid = db.add(title="Oracle manipulation", severity="High")
        f = db.get(fid)
        assert f is not None
        assert f["id"] == fid

    def test_get_nonexistent_returns_none(self, db):
        assert db.get("deadbeef") is None


class TestUpdateStatus:
    def test_update_to_verified(self, db):
        fid = db.add(title="Flash loan attack", severity="Critical")
        db.update_status(fid, "verified")
        f = db.get(fid)
        assert f["status"] == "verified"

    def test_update_to_rejected(self, db):
        fid = db.add(title="False positive", severity="Low")
        db.update_status(fid, "rejected")
        f = db.get(fid)
        assert f["status"] == "rejected"

    def test_update_increments_updated_at(self, db):
        import time
        fid = db.add(title="Test", severity="Medium")
        f_before = db.get(fid)
        time.sleep(0.01)
        db.update_status(fid, "verified")
        f_after = db.get(fid)
        assert f_after["updated_at"] >= f_before["updated_at"]


class TestListFindings:
    def test_list_all(self, db):
        db.add(title="Finding A", severity="High")
        db.add(title="Finding B", severity="Low")
        findings = db.list_findings()
        assert len(findings) >= 2

    def test_filter_by_status(self, db):
        fid = db.add(title="Pending finding", severity="Medium")
        db.update_status(fid, "submitted")
        submitted = db.list_findings(status="submitted")
        assert any(f["id"] == fid for f in submitted)
        pending = db.list_findings(status="pending")
        assert not any(f["id"] == fid for f in pending)

    def test_filter_by_severity(self, db):
        db.add(title="Critical one", severity="Critical")
        criticals = db.list_findings(severity="Critical")
        assert all(f["severity"] == "Critical" for f in criticals)

    def test_returns_dicts(self, db):
        db.add(title="Dict test", severity="Info")
        findings = db.list_findings()
        assert all(isinstance(f, dict) for f in findings)


class TestSearch:
    def test_search_by_title_keyword(self, db):
        db.add(title="Uniswap hook reentrancy", severity="High")
        results = db.search("uniswap")
        assert any("Uniswap" in r["title"] for r in results)

    def test_search_by_hypothesis(self, db):
        fid = db.add(
            title="Storage collision",
            severity="Critical",
            hypothesis="IF proxy slot overlaps with implementation owner slot",
        )
        results = db.search("proxy slot")
        assert any(r["id"] == fid for r in results)

    def test_search_case_insensitive(self, db):
        db.add(title="MORPHO vault inflation", severity="High")
        results = db.search("morpho")
        assert len(results) > 0

    def test_search_no_match_returns_empty(self, db):
        results = db.search("xyzzy_never_matches_anything_12345")
        assert results == []
