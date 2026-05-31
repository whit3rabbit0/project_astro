import re
import shlex
from typing import List

SHELL_METACHARACTERS = re.compile(r'[;&|`$<>()\\\'"!{}]')

NMAP_SCAN_FLAGS = {
    "-sV", "-sS", "-sU", "-sT", "-sA", "-sN", "-sF", "-sX",
    "-sC", "-sP", "-sn", "-O", "-A",
}


def validate_url(u: str) -> bool:
    """Return True if u starts with http:// or https:// and has no shell metacharacters."""
    if not (u.startswith("http://") or u.startswith("https://")):
        return False
    return not SHELL_METACHARACTERS.search(u)


def validate_path(p: str) -> bool:
    """Return True if p is an absolute path containing only safe characters."""
    if not p.startswith("/"):
        return False
    return bool(re.fullmatch(r'[a-zA-Z0-9/.\-_]+', p))


def validate_additional_args(args_str: str) -> List[str]:
    """Split additional_args with shlex and reject any token containing shell metacharacters."""
    try:
        tokens = shlex.split(args_str)
    except ValueError as exc:
        raise ValueError(f"Could not parse additional_args: {exc}") from exc
    for token in tokens:
        if SHELL_METACHARACTERS.search(token):
            raise ValueError(f"Unsafe token in additional_args: {token!r}")
    return tokens


def validate_no_control_chars(value: str) -> bool:
    """Return True if value contains no newlines, carriage returns, semicolons, or control chars."""
    return not re.search(r'[\n\r;]|[\x00-\x1f]', value)
