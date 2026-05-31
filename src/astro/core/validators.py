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


BLOCKED_FLAGS = [
    "-oN", "-oX", "-oG", "-oA", "-oS",  # nmap file output
    "--os-shell", "--os-cmd", "--os-pwn",  # sqlmap OS access
    "--file-read", "--file-write", "--file-dest",  # sqlmap file access
    "--script=", "-sC",  # nmap scripting (prefix match for --script=)
    "--priv-esc", "--reg-read", "--reg-add",  # sqlmap registry
    "-o",  # generic output redirect (hydra, john, etc.)
]


def validate_additional_args(args_str: str) -> List[str]:
    """Split additional_args with shlex and reject any token containing shell metacharacters or blocked flags."""
    try:
        tokens = shlex.split(args_str)
    except ValueError as exc:
        raise ValueError(f"Could not parse additional_args: {exc}") from exc
    for token in tokens:
        if SHELL_METACHARACTERS.search(token):
            raise ValueError(f"Unsafe token in additional_args: {token!r}")
        # Check against blocked flags
        token_upper = token
        for flag in BLOCKED_FLAGS:
            if flag.endswith("="):
                # Prefix match for flags like --script=
                if token.startswith(flag) or token.lower().startswith(flag.lower()):
                    raise ValueError(f"Blocked flag in additional_args: {token!r}")
            else:
                # Exact match
                if token == flag:
                    raise ValueError(f"Blocked flag in additional_args: {token!r}")
    return tokens


def validate_no_control_chars(value: str) -> bool:
    """Return True if value contains no newlines, carriage returns, semicolons, or control chars."""
    return not re.search(r'[\n\r;]|[\x00-\x1f]', value)
