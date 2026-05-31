import pytest
import yaml

from astro.core.engagement import EngagementManager
from astro.core.scope import ScopeEnforcer, ScopeViolationError
from astro.core.validators import (
    SHELL_METACHARACTERS,
    validate_additional_args,
    validate_no_control_chars,
    validate_url,
)
from astro.tools.nmap import NmapTool


class TestShellInjectionInTargets:
    @pytest.fixture
    def nmap(self):
        return NmapTool()

    def test_semicolon_injection(self, nmap):
        with pytest.raises(ValueError):
            nmap.validate({"target": "10.10.10.1;id"})

    def test_pipe_injection(self, nmap):
        with pytest.raises(ValueError):
            nmap.validate({"target": "10.10.10.1|cat /etc/passwd"})

    def test_ampersand_injection(self, nmap):
        with pytest.raises(ValueError):
            nmap.validate({"target": "10.10.10.1&&whoami"})

    def test_dollar_subshell_injection(self, nmap):
        with pytest.raises(ValueError):
            nmap.validate({"target": "$(whoami)"})

    def test_backtick_injection(self, nmap):
        with pytest.raises(ValueError):
            nmap.validate({"target": "`id`"})

    def test_command_substitution_in_additional_args(self):
        with pytest.raises(ValueError):
            validate_additional_args("$(cat /etc/shadow)")

    def test_backtick_in_additional_args(self):
        with pytest.raises(ValueError):
            validate_additional_args("`whoami`")

    def test_semicolon_in_additional_args(self):
        with pytest.raises(ValueError):
            validate_additional_args("-v; rm -rf /")


class TestShellInjectionInUrls:
    def test_url_with_semicolon(self):
        assert validate_url("http://target.com;rm -rf /") is False

    def test_url_with_pipe(self):
        assert validate_url("http://target.com|id") is False

    def test_url_with_backtick(self):
        assert validate_url("http://target.com`whoami`") is False

    def test_url_with_dollar(self):
        assert validate_url("http://target.com/$USER") is False

    def test_url_with_ampersand(self):
        assert validate_url("http://target.com&cat /etc/passwd") is False


class TestPathTraversal:
    def test_nmap_rejects_path_chars_in_target(self):
        nmap = NmapTool()
        with pytest.raises(ValueError):
            nmap.validate({"target": "../../etc/passwd"})

    def test_nmap_rejects_slash_in_target(self):
        nmap = NmapTool()
        with pytest.raises(ValueError):
            nmap.validate({"target": "/etc/passwd"})


class TestSqlInjectionInEngagement:
    async def test_sql_injection_in_engagement_name(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        mgr = EngagementManager(db_path=db_path)
        await mgr.initialize()

        malicious_name = "'; DROP TABLE engagements; --"
        eng_id = await mgr.create_engagement(malicious_name)

        engagements = await mgr.list_engagements()
        assert len(engagements) == 1
        assert engagements[0]["name"] == malicious_name

    async def test_sql_injection_in_finding_tool(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        mgr = EngagementManager(db_path=db_path)
        await mgr.initialize()

        eng_id = await mgr.create_engagement("Test")
        malicious_tool = "nmap'; DELETE FROM findings; --"
        await mgr.record_finding(
            eng_id, malicious_tool, "10.0.0.1", {}, {"stdout": ""}
        )

        findings = await mgr.get_findings(eng_id)
        assert len(findings) == 1
        assert findings[0]["tool"] == malicious_tool


class TestScopeBypassAttempts:
    @pytest.fixture
    def scope_config_path(self, tmp_path):
        config = {
            "scope": {
                "allowed_cidrs": ["10.10.10.0/24"],
                "allowed_domains": ["*.htb"],
                "excluded_targets": ["10.10.10.255"],
            }
        }
        config_file = tmp_path / "scope.yaml"
        config_file.write_text(yaml.dump(config))
        return str(config_file)

    def test_excluded_target_cannot_bypass(self, scope_config_path):
        enforcer = ScopeEnforcer(config_path=scope_config_path)
        with pytest.raises(ScopeViolationError):
            enforcer.validate_target("10.10.10.255")

    def test_out_of_cidr_target_blocked(self, scope_config_path):
        enforcer = ScopeEnforcer(config_path=scope_config_path)
        with pytest.raises(ScopeViolationError):
            enforcer.validate_target("192.168.1.1")

    def test_non_matching_domain_blocked(self, scope_config_path):
        enforcer = ScopeEnforcer(config_path=scope_config_path)
        with pytest.raises(ScopeViolationError):
            enforcer.validate_target("evil.com")


class TestControlCharacterInjection:
    def test_null_byte_rejected(self):
        assert validate_no_control_chars("target\x00.htb") is False

    def test_newline_injection_rejected(self):
        assert validate_no_control_chars("target\n.htb") is False

    def test_carriage_return_rejected(self):
        assert validate_no_control_chars("target\r.htb") is False

    def test_escape_char_rejected(self):
        assert validate_no_control_chars("target\x1b.htb") is False

    def test_bell_char_rejected(self):
        assert validate_no_control_chars("target\x07.htb") is False

    @pytest.mark.parametrize("char_code", range(0, 32))
    def test_all_control_chars_blocked(self, char_code):
        test_str = f"before{chr(char_code)}after"
        assert validate_no_control_chars(test_str) is False
