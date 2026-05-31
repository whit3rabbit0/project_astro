import pytest

from astro.tools.nmap import NmapTool


@pytest.fixture
def nmap():
    return NmapTool()


class TestNmapValidation:
    def test_valid_params(self, nmap):
        params = {"target": "10.10.10.1", "scan_type": "-sV", "ports": "80,443"}
        validated = nmap.validate(params)
        assert validated["target"] == "10.10.10.1"
        assert validated["scan_type"] == "-sV"
        assert validated["ports"] == "80,443"

    def test_missing_target_raises(self, nmap):
        with pytest.raises(ValueError, match="Target parameter is required"):
            nmap.validate({"scan_type": "-sV"})

    def test_empty_target_raises(self, nmap):
        with pytest.raises(ValueError, match="Target parameter is required"):
            nmap.validate({"target": "", "scan_type": "-sV"})

    def test_invalid_scan_type_raises(self, nmap):
        with pytest.raises(ValueError, match="Invalid scan_type"):
            nmap.validate({"target": "10.10.10.1", "scan_type": "-sZ"})

    def test_invalid_ports_raises(self, nmap):
        with pytest.raises(ValueError, match="Invalid ports"):
            nmap.validate({"target": "10.10.10.1", "ports": "80;rm"})

    def test_shell_metacharacters_in_additional_args_raises(self, nmap):
        with pytest.raises(ValueError, match="Unsafe token"):
            nmap.validate({
                "target": "10.10.10.1",
                "additional_args": "--script=`id`",
            })

    def test_default_scan_type_is_sV(self, nmap):
        validated = nmap.validate({"target": "10.10.10.1"})
        assert validated["scan_type"] == "-sV"

    def test_default_ports_is_empty(self, nmap):
        validated = nmap.validate({"target": "10.10.10.1"})
        assert validated["ports"] == ""

    def test_invalid_target_characters_raises(self, nmap):
        with pytest.raises(ValueError, match="Invalid target"):
            nmap.validate({"target": "10.10.10.1;id"})

    @pytest.mark.parametrize(
        "scan_type",
        ["-sV", "-sS", "-sU", "-sT", "-sA", "-sN", "-sF", "-sX",
         "-sC", "-sP", "-sn", "-O", "-A"],
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
            "additional_args": "-v --script=http-enum",
        })
        cmd = nmap.build_command(validated)
        assert cmd == ["nmap", "-sV", "-v", "--script=http-enum", "10.10.10.1"]

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
        assert cmd[0] == "nmap"
        assert cmd[1] == "-sS"
