import pytest
import yaml

from astro.core.scope import ScopeEnforcer, ScopeViolationError


@pytest.fixture
def scope_config_path(tmp_path):
    config = {
        "scope": {
            "allowed_cidrs": ["10.10.10.0/24", "192.168.1.0/24"],
            "allowed_domains": ["*.htb", "target.local"],
            "excluded_targets": ["10.10.10.255", "admin.htb"],
            "tool_restrictions": {
                "sqlmap": {"max_threads": 5, "risk_level": 2},
            },
        }
    }
    config_file = tmp_path / "scope.yaml"
    config_file.write_text(yaml.dump(config))
    return str(config_file)


@pytest.fixture
def enforcer(scope_config_path):
    return ScopeEnforcer(config_path=scope_config_path)


class TestScopeEnforcerInScope:
    def test_ip_in_allowed_cidr(self, enforcer):
        enforcer.validate_target("10.10.10.1")

    def test_ip_in_second_cidr(self, enforcer):
        enforcer.validate_target("192.168.1.100")

    def test_domain_matches_glob(self, enforcer):
        enforcer.validate_target("box.htb")

    def test_domain_matches_exact(self, enforcer):
        enforcer.validate_target("target.local")

    def test_subdomain_matches_glob(self, enforcer):
        enforcer.validate_target("admin.panel.htb")


class TestScopeEnforcerOutOfScope:
    def test_ip_outside_cidr(self, enforcer):
        with pytest.raises(ScopeViolationError, match="not in scope"):
            enforcer.validate_target("172.16.0.1")

    def test_domain_not_matching_any_pattern(self, enforcer):
        with pytest.raises(ScopeViolationError, match="not in scope"):
            enforcer.validate_target("evil.com")


class TestScopeEnforcerExcluded:
    def test_excluded_ip(self, enforcer):
        with pytest.raises(ScopeViolationError, match="explicitly excluded"):
            enforcer.validate_target("10.10.10.255")

    def test_excluded_domain(self, enforcer):
        with pytest.raises(ScopeViolationError, match="explicitly excluded"):
            enforcer.validate_target("admin.htb")


class TestScopeEnforcerPermissive:
    def test_no_config_allows_everything(self):
        enforcer = ScopeEnforcer(config_path=None)
        enforcer.validate_target("anything.com")

    def test_empty_scope_allows_everything(self, tmp_path):
        config_file = tmp_path / "empty.yaml"
        config_file.write_text(yaml.dump({}))
        enforcer = ScopeEnforcer(config_path=str(config_file))
        enforcer.validate_target("anything.com")

    def test_empty_allowed_lists_permissive(self, tmp_path):
        config = {"scope": {"allowed_cidrs": [], "allowed_domains": []}}
        config_file = tmp_path / "empty_lists.yaml"
        config_file.write_text(yaml.dump(config))
        enforcer = ScopeEnforcer(config_path=str(config_file))
        enforcer.validate_target("anything.com")


class TestToolRestrictions:
    def test_returns_restrictions_for_known_tool(self, enforcer):
        restrictions = enforcer.get_tool_restrictions("sqlmap")
        assert restrictions["max_threads"] == 5
        assert restrictions["risk_level"] == 2

    def test_returns_empty_dict_for_unknown_tool(self, enforcer):
        restrictions = enforcer.get_tool_restrictions("gobuster")
        assert restrictions == {}

    def test_returns_empty_when_no_scope_config(self):
        enforcer = ScopeEnforcer(config_path=None)
        assert enforcer.get_tool_restrictions("nmap") == {}
