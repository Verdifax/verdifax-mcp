"""Text cleaning and redaction.

Every string and key in every answer passes through Redactor.value:
characters in the contract's remove ranges are dropped, tab, line breaks and
the Unicode line and paragraph separators become a space, and then every
configured secret is replaced. Cleaning runs before redaction, so a secret
split by a hidden character is still caught.
"""

import re
from typing import Any, Iterable, Optional

from .contract import IMPL

_CLEAN = IMPL["text_cleaning"]
_SPACE = [tuple(r) for r in _CLEAN["replace_with_space"]]
_REMOVE = [tuple(r) for r in _CLEAN["remove"]]
_LINE_SEPARATORS = [(0x2028, 0x2029)]


def _in(cp: int, ranges: list) -> bool:
    return any(low <= cp <= high for low, high in ranges)


def clean_string(text: str) -> str:
    """The string with hidden characters removed and line breaks as spaces."""
    out = []
    for ch in text:
        cp = ord(ch)
        if _in(cp, _SPACE):
            out.append(" ")
        elif not _in(cp, _REMOVE):
            out.append(ch)
    return "".join(out)


def has_refused_character(text: str) -> bool:
    """Whether seal_decision must refuse this string. Tab, line feed and
    carriage return are allowed."""
    return any(_in(ord(ch), _REMOVE) or _in(ord(ch), _LINE_SEPARATORS) for ch in text)


class Redactor:
    def __init__(self, secrets: Iterable[Optional[str]]) -> None:
        unique = {s for s in secrets if isinstance(s, str) and len(s) >= 8}
        self._secrets = sorted(unique, key=len, reverse=True)
        self._pattern = re.compile(IMPL["redaction"]["pattern"])
        self._replacement = IMPL["redaction"]["replacement"]

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, self._replacement)
        return self._pattern.sub(self._replacement, text)

    def text(self, value: str) -> str:
        """Cleaning, then redaction, of one string."""
        return self.redact(clean_string(value))

    def value(self, data: Any) -> Any:
        """A copy of a JSON value with every string and key cleaned and redacted."""
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, list):
            return [self.value(v) for v in data]
        if isinstance(data, dict):
            return {self.text(str(k)): self.value(v) for k, v in data.items()}
        return data
