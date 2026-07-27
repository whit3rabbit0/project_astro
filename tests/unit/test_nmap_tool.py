import pytest

from astro.tools.nmap import NmapTool


@pytest.fixture
def nmap():
    return NmapTool()


class TestNmapValidation:
    def test_valid_target(self, nmap):
        result = nmap.validate({"target": "10.10.10.1"})
        assert result["target"] == "10.10.10.1"
        assert result["scan_type"] == "-sV"

    def test_hostname_target(self, nmap):
        result = nmap.validate({"target": "box.htb"})
        assert result["target"] == "box.htb"

    def test_cidr_target(self, nmap):
        result = nmap.validate({"target": "10.10.10.0/24"})
        assert result["target"] == "10.10.10.0/24"

    def test_missing_target_raises(self, nmap):
        with pytest.raises(ValueError, match="Target parameter is required"):
            nmap.validate({})

    def test_invalid_scan_type_raises(self, nmap):
        with pytest.raises(ValueError, match="Invalid scan type"):
            nmap.validate({"target": "10.10.10.1", "scan_type": "-sZ"})

    def test_valid_ports(self, nmap):
        result = nmap.validate({"target": "10.10.10.1", "ports": "80,443,8080"})
        assert result["ports"] == "80,443,8080"

    def test_port_range(self, nmap):
        result = nmap.validate({"target": "10.10.10.1", "ports": "1-1024"})
        assert result["ports"] == "1-1024"

    def test_invalid_ports_raises(self, nmap):
        with pytest.raises(ValueError, match="Invalid ports"):
            nmap.validate({"target": "10.10.10.1", "ports": "80;rm"})

    def test_invalid_target_characters_raises(self, nmap):
        with pytest.raises(ValueError, match="Invalid target"):
            nmap.validate({"target": "10.10.10.1;id"})

    @pytest.mark.parametrize(
        "scan_type",
        ["-sV", "-sS", "-sU", "-sT", "-sA", "-sN", "-sF", "-sX", "-sC", "-sP", "-sn", "-O", "-A"],
    )
    def test_all_valid_scan_types(self, nmap, scan_type):
        validated = nmap.validate({"target": "10.10.10.1", "scan_type": scan_type})
        assert validated["scan_type"] == scan_type


class TestNmapBuildCommand:
    def test_basic_command(self, nmap):
        validated = nmap.validate({"target": "10.10.10.1"})
        cmd = nmap.build_command(validated)
        assert cmd == ["nmap", "-sV", "10.10.10.1"]

    def test_command_with_ports(self, nmap):
        validated = nmap.validate({"target": "10.10.10.1", "ports": "80,443"})
        cmd = nmap.build_command(validated)
        assert cmd == ["nmap", "-sV", "-p", "80,443", "10.10.10.1"]

    def test_command_with_additional_args(self, nmap):
        validated = nmap.validate({
            "target": "10.10.10.1",
            "additional_args": "-v --reason",
        })
        cmd = nmap.build_command(validated)
        assert cmd == ["nmap", "-sV", "-v", "--reason", "10.10.10.1"]

    def test_target_is_last_in_command(self, nmap):
        validated = nmap.validate({
            "target": "box.htb",
            "scan_type": "-sS",
            "ports": "1-1000",
            "additional_args": "-v",
        })
        cmd = nmap.build_command(validated)
        assert cmd[-1] == "box.htb"

    def test_scan_type_is_second_element(self, nmap):
        validated = nmap.validate({"target": "10.10.10.1", "scan_type": "-sS"})
        cmd = nmap.build_command(validated)
        assert cmd[1] == "-sS"
