import pytest

from astro.core.validators import (
    SHELL_METACHARACTERS,
    validate_additional_args,
    validate_no_control_chars,
    validate_path,
    validate_url,
)


class TestValidateUrl:
    def test_valid_http_url(self):
        assert validate_url("http://example.com") is True

    def test_valid_https_url(self):
        assert validate_url("https://example.com/path") is True

    def test_rejects_ftp_scheme(self):
        assert validate_url("ftp://example.com") is False

    def test_rejects_no_scheme(self):
        assert validate_url("example.com") is False

    def test_rejects_empty_string(self):
        assert validate_url("") is False

    def test_rejects_shell_metacharacter_semicolon(self):
        assert validate_url("http://example.com;rm -rf /") is False

    def test_rejects_shell_metacharacter_pipe(self):
        assert validate_url("http://example.com|cat /etc/passwd") is False

    def test_rejects_shell_metacharacter_backtick(self):
        assert validate_url("http://example.com`id`") is False

    def test_rejects_shell_metacharacter_dollar(self):
        assert validate_url("http://example.com/$HOME") is False

    def test_rejects_shell_metacharacter_ampersand(self):
        assert validate_url("http://example.com&echo pwned") is False

    def test_valid_url_with_port(self):
        assert validate_url("http://10.10.10.1:8080/api") is True

    def test_valid_url_with_query_params_no_metachar(self):
        assert validate_url("http://example.com/search?q=test") is True


class TestValidatePath:
    def test_valid_absolute_path(self):
        assert validate_path("/usr/bin/nmap") is True

    def test_valid_path_with_dots(self):
        assert validate_path("/home/user/.config/file.txt") is True

    def test_valid_path_with_hyphens_underscores(self):
        assert validate_path("/var/log/my-app_logs/run.log") is True

    def test_rejects_relative_path(self):
        assert validate_path("relative/path") is False

    def test_rejects_empty_string(self):
        assert validate_path("") is False

    def test_rejects_path_with_spaces(self):
        assert validate_path("/path/with space") is False

    def test_rejects_path_with_semicolon(self):
        assert validate_path("/path;rm -rf /") is False

    def test_rejects_path_with_backtick(self):
        assert validate_path("/path/`id`") is False

    def test_rejects_path_with_special_chars(self):
        assert validate_path("/path/$HOME") is False


class TestValidateAdditionalArgs:
    def test_empty_string_returns_empty_list(self):
        assert validate_additional_args("") == []

    def test_single_safe_token(self):
        assert validate_additional_args("-v") == ["-v"]

    def test_multiple_safe_tokens(self):
        result = validate_additional_args("-v --script=http-enum")
        assert result == ["-v", "--script=http-enum"]

    def test_raises_on_semicolon(self):
        with pytest.raises(ValueError, match="Unsafe token"):
            validate_additional_args("-v; rm -rf /")

    def test_raises_on_pipe(self):
        with pytest.raises(ValueError, match="Unsafe token"):
            validate_additional_args("-v | cat")

    def test_raises_on_backtick(self):
        with pytest.raises(ValueError, match="Unsafe token"):
            validate_additional_args("`id`")

    def test_raises_on_dollar_sign(self):
        with pytest.raises(ValueError, match="Unsafe token"):
            validate_additional_args("$HOME")

    def test_raises_on_unmatched_quote(self):
        with pytest.raises(ValueError, match="Could not parse"):
            validate_additional_args("'unterminated")


class TestValidateNoControlChars:
    def test_clean_string(self):
        assert validate_no_control_chars("hello world") is True

    def test_alphanumeric_and_symbols(self):
        assert validate_no_control_chars("test-target_123.htb") is True

    def test_rejects_newline(self):
        assert validate_no_control_chars("line1\nline2") is False

    def test_rejects_carriage_return(self):
        assert validate_no_control_chars("line1\rline2") is False

    def test_rejects_semicolon(self):
        assert validate_no_control_chars("cmd;evil") is False

    def test_rejects_null_byte(self):
        assert validate_no_control_chars("hello\x00world") is False

    def test_rejects_tab(self):
        assert validate_no_control_chars("hello\tworld") is False

    def test_empty_string_passes(self):
        assert validate_no_control_chars("") is True


class TestShellMetacharactersPattern:
    @pytest.mark.parametrize(
        "char",
        [";", "&", "|", "`", "$", "<", ">", "(", ")", "\\", "'", '"', "!", "{", "}"],
    )
    def test_catches_dangerous_character(self, char):
        assert SHELL_METACHARACTERS.search(char) is not None

    def test_does_not_match_safe_string(self):
        assert SHELL_METACHARACTERS.search("safe-string_123.htb") is None

    def test_does_not_match_digits(self):
        assert SHELL_METACHARACTERS.search("1234567890") is None

    def test_catches_metacharacter_in_longer_string(self):
        assert SHELL_METACHARACTERS.search("normal;injection") is not None
