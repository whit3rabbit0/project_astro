import pytest

from astro.core.engagement import EngagementManager


@pytest.fixture
async def manager(tmp_path):
    db_path = str(tmp_path / "test.db")
    mgr = EngagementManager(db_path=db_path)
    await mgr.initialize()
    return mgr


class TestCreateEngagement:
    async def test_returns_uuid_string(self, manager):
        eng_id = await manager.create_engagement("Test Engagement")
        assert isinstance(eng_id, str)
        assert len(eng_id) == 36

    async def test_create_with_scope_config(self, manager):
        scope = {"allowed_cidrs": ["10.0.0.0/8"]}
        eng_id = await manager.create_engagement("Scoped", scope_config=scope)
        engagements = await manager.list_engagements()
        match = [e for e in engagements if e["id"] == eng_id]
        assert len(match) == 1
        assert match[0]["scope_config"] == scope

    async def test_create_without_scope_config(self, manager):
        eng_id = await manager.create_engagement("No Scope")
        engagements = await manager.list_engagements()
        match = [e for e in engagements if e["id"] == eng_id]
        assert match[0]["scope_config"] is None


class TestRecordFinding:
    async def test_record_and_retrieve_finding(self, manager):
        eng_id = await manager.create_engagement("FindingTest")
        finding_id = await manager.record_finding(
            engagement_id=eng_id,
            tool="nmap",
            target="10.10.10.1",
            params={"scan_type": "-sV"},
            raw_output={"stdout": "open ports", "return_code": 0},
            parsed_output={"hosts": []},
        )
        assert isinstance(finding_id, str)
        findings = await manager.get_findings(eng_id)
        assert len(findings) == 1
        assert findings[0]["tool"] == "nmap"
        assert findings[0]["target"] == "10.10.10.1"
        assert findings[0]["parsed_output"] == {"hosts": []}

    async def test_record_finding_without_parsed_output(self, manager):
        eng_id = await manager.create_engagement("NoParsed")
        await manager.record_finding(
            engagement_id=eng_id,
            tool="gobuster",
            target="http://target.htb",
            params={"wordlist": "/usr/share/wordlists/common.txt"},
            raw_output={"stdout": "results"},
        )
        findings = await manager.get_findings(eng_id)
        assert findings[0]["parsed_output"] is None


class TestGetFindingsFiltering:
    async def test_filter_by_tool(self, manager):
        eng_id = await manager.create_engagement("FilterTest")
        await manager.record_finding(eng_id, "nmap", "10.0.0.1", {}, {"stdout": ""})
        await manager.record_finding(eng_id, "nikto", "10.0.0.1", {}, {"stdout": ""})
        await manager.record_finding(eng_id, "nmap", "10.0.0.2", {}, {"stdout": ""})

        nmap_findings = await manager.get_findings(eng_id, tool="nmap")
        assert len(nmap_findings) == 2
        assert all(f["tool"] == "nmap" for f in nmap_findings)

    async def test_filter_by_target(self, manager):
        eng_id = await manager.create_engagement("TargetFilter")
        await manager.record_finding(eng_id, "nmap", "10.0.0.1", {}, {"stdout": ""})
        await manager.record_finding(eng_id, "nmap", "10.0.0.2", {}, {"stdout": ""})

        findings = await manager.get_findings(eng_id, target="10.0.0.1")
        assert len(findings) == 1
        assert findings[0]["target"] == "10.0.0.1"

    async def test_filter_by_tool_and_target(self, manager):
        eng_id = await manager.create_engagement("BothFilter")
        await manager.record_finding(eng_id, "nmap", "10.0.0.1", {}, {"stdout": ""})
        await manager.record_finding(eng_id, "nikto", "10.0.0.1", {}, {"stdout": ""})
        await manager.record_finding(eng_id, "nmap", "10.0.0.2", {}, {"stdout": ""})

        findings = await manager.get_findings(eng_id, tool="nmap", target="10.0.0.1")
        assert len(findings) == 1


class TestListEngagements:
    async def test_list_ordered_by_date_descending(self, manager):
        id1 = await manager.create_engagement("First")
        id2 = await manager.create_engagement("Second")
        id3 = await manager.create_engagement("Third")

        engagements = await manager.list_engagements()
        assert len(engagements) == 3
        assert engagements[0]["id"] == id3
        assert engagements[2]["id"] == id1

    async def test_empty_list_when_no_engagements(self, manager):
        engagements = await manager.list_engagements()
        assert engagements == []


class TestMultipleEngagements:
    async def test_findings_isolated_between_engagements(self, manager):
        eng1 = await manager.create_engagement("Engagement 1")
        eng2 = await manager.create_engagement("Engagement 2")

        await manager.record_finding(eng1, "nmap", "10.0.0.1", {}, {"stdout": ""})
        await manager.record_finding(eng2, "nikto", "10.0.0.2", {}, {"stdout": ""})

        findings1 = await manager.get_findings(eng1)
        findings2 = await manager.get_findings(eng2)

        assert len(findings1) == 1
        assert findings1[0]["tool"] == "nmap"
        assert len(findings2) == 1
        assert findings2[0]["tool"] == "nikto"
