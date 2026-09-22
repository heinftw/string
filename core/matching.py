"""Pure string-matching logic: keyword -> encoding byte patterns + boundary rules.

No win32 imports here; every function is unit-testable on any platform.

Encoding policy
---------------
ANSI     single-byte latin-1 (the low 256 code points cover the ANSI/CP1252
         range used by narrow Win32 strings).  Case folding is per character
         (exact / lower / upper variants of the same encoded width).
UTF-16LE two bytes per code unit.  Case alternatives must keep the same
         encoded width so matches stay aligned to the string's unit grid;
         both byte alignments of that grid (even/odd buffer offsets) are
         scanned implicitly because matching is a plain byte search.
UTF-8    optional (only built for keywords containing non-ASCII characters;
         for pure-ASCII keywords it is identical to the ANSI pattern).

Boundary policy (what gets wiped together with the keyword)
-----------------------------------------------------------
A "string" is the maximal run of *printable* bytes/units containing the match:
* narrow:  bytes 0x20-0x7E and 0x80-0xFF are content; 0x00-0x1F and 0x7F
  (including the NUL terminator) stop the run.
* wide:    code units >= 0x20 except 0x007F are content; NUL and control
  units stop the run.  The NUL / double-NUL terminator itself is left intact
  (it is already zero and marks the structural end of the string).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

# Process Hacker's Strings view does not display strings shorter than this.
PROCESS_HACKER_MIN_STRING_LENGTH = 4

ENCODING_ANSI = "ansi"
ENCODING_UTF8 = "utf-8"
ENCODING_UTF16LE = "utf-16le"

_ANSI_CODEC = "latin-1"


def parse_keywords(text: str) -> List[str]:
    """Split a comma-separated keyword box into stripped, deduped keywords.

    Empty and whitespace-only segments are dropped; multi-word phrases are
    kept intact (they contain no comma).  Dedup is case-insensitive and keeps
    the first spelling.
    """
    if not text:
        return []
    out: List[str] = []
    seen = set()
    for part in text.split(","):
        kw = part.strip()
        if not kw:
            continue
        key = kw.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(kw)
    return out


@dataclass(frozen=True)
class Pattern:
    """One compiled byte pattern for one keyword in one encoding."""

    keyword: str
    encoding: str
    regex: "re.Pattern[bytes]"
    min_size: int
    max_size: int


@dataclass(frozen=True)
class PatternSet:
    """All patterns built for a keyword list, plus human-readable notes."""

    patterns: Tuple[Pattern, ...]
    notes: Tuple[str, ...] = ()

    @property
    def max_size(self) -> int:
        """Longest possible match, for chunk-overlap sizing."""
        return max((p.max_size for p in self.patterns), default=1)


@dataclass(frozen=True)
class Match:
    """A raw pattern hit at buffer-relative byte offsets [start, end)."""

    keyword: str
    start: int
    end: int
    encoding: str


def _case_variants(ch: str) -> List[str]:
    out: List[str] = []
    for v in (ch, ch.lower(), ch.upper()):
        if v not in out:
            out.append(v)
    return out


def _char_variants_bytes(ch: str, encoding: str, fixed_width: bool) -> Optional[List[bytes]]:
    """Encoded case variants of one character, or None if it cannot be encoded.

    With ``fixed_width`` every variant must keep the byte width of ``ch``
    itself (required for single-byte and UTF-16LE patterns so match lengths
    and unit alignment stay stable).
    """
    base_len: Optional[int] = None
    parts: List[bytes] = []
    for v in _case_variants(ch):
        try:
            b = v.encode(encoding)
        except UnicodeEncodeError:
            continue
        if base_len is None:
            base_len = len(b)  # width of ch itself (first variant)
        if fixed_width and len(b) != base_len:
            continue
        if b not in parts:
            parts.append(b)
    return parts or None


def _fragment(parts: Sequence[bytes]) -> bytes:
    if len(parts) == 1:
        return re.escape(parts[0])
    return b"(?:" + b"|".join(re.escape(p) for p in parts) + b")"


def _keyword_pattern(
    keyword: str, codec: str, label: str, fixed_width: bool
) -> Optional[Pattern]:
    frags: List[bytes] = []
    mn = 0
    mx = 0
    for ch in keyword:
        parts = _char_variants_bytes(ch, codec, fixed_width)
        if not parts:
            return None
        frags.append(_fragment(parts))
        mn += min(len(p) for p in parts)
        mx += max(len(p) for p in parts)
    if not frags:
        return None
    return Pattern(keyword, label, re.compile(b"".join(frags)), mn, mx)


def build_patterns(keywords: Sequence[str], include_utf8: bool = True) -> PatternSet:
    """Build case-insensitive byte patterns for every keyword.

    ANSI and UTF-16LE patterns are always attempted; the optional UTF-8
    pattern is added only for keywords with non-ASCII characters (for ASCII
    keywords UTF-8 bytes equal the ANSI bytes).  A keyword that cannot be
    represented in a given encoding simply yields no pattern there and a note.
    """
    patterns: List[Pattern] = []
    notes: List[str] = []
    for kw in keywords:
        ansi = _keyword_pattern(kw, _ANSI_CODEC, ENCODING_ANSI, fixed_width=True)
        if ansi is not None:
            patterns.append(ansi)
        else:
            notes.append(
                f"keyword {kw!r}: not representable as single-byte ANSI (latin-1); "
                "only UTF-16LE/UTF-8 patterns will be used for it."
            )
        if include_utf8 and any(ord(c) > 127 for c in kw):
            utf8 = _keyword_pattern(kw, "utf-8", ENCODING_UTF8, fixed_width=False)
            if utf8 is not None:
                patterns.append(utf8)
        wide = _keyword_pattern(kw, "utf-16le", ENCODING_UTF16LE, fixed_width=True)
        if wide is not None:
            patterns.append(wide)
    notes.extend(short_keyword_notes(keywords))
    return PatternSet(tuple(patterns), tuple(notes))


def short_keyword_notes(keywords: Sequence[str]) -> List[str]:
    """Notes about keywords below Process Hacker's minimum string length."""
    notes: List[str] = []
    for kw in keywords:
        if len(kw) < PROCESS_HACKER_MIN_STRING_LENGTH:
            notes.append(
                f"keyword {kw!r} is shorter than Process Hacker's minimum string "
                f"length ({PROCESS_HACKER_MIN_STRING_LENGTH}); Process Hacker's "
                "Strings view may not display such strings even though this tool "
                "matches and wipes them."
            )
    return notes


def find_matches(data: bytes, patterns: Iterable[Pattern]) -> List[Match]:
    """Return every pattern hit in ``data``, sorted by position.

    Duplicate (keyword, start, end) hits from overlapping encodings are
    reported once (first pattern wins).
    """
    out: List[Match] = []
    seen = set()
    for p in patterns:
        for m in p.regex.finditer(data):
            key = (p.keyword, m.start(), m.end())
            if key in seen:
                continue
            seen.add(key)
            out.append(Match(p.keyword, m.start(), m.end(), p.encoding))
    out.sort(key=lambda m: (m.start, m.end, m.keyword))
    return out


def _is_narrow_content(b: int) -> bool:
    """Printable single byte: 0x20-0x7E and 0x80-0xFF."""
    return b >= 0x20 and b != 0x7F


def _wide_unit(data: bytes, i: int) -> int:
    return data[i] | (data[i + 1] << 8)


def _is_wide_content(unit: int) -> bool:
    """Printable UTF-16LE code unit (stops at NUL and C0/C1-style controls)."""
    return unit >= 0x20 and unit != 0x7F


def resolve_string_bounds(
    data: bytes, start: int, end: int, encoding: str
) -> Tuple[int, int]:
    """Grow [start, end) to the full printable run containing the match.

    Wide runs step two bytes at a time, preserving the match's own byte
    alignment (even or odd).  The terminator (NUL for narrow, NUL/double-NUL
    for wide) and any non-printable boundary bytes are NOT included: they are
    structural, and the terminator is already zero.  Buffer edges clip the run
    (the scanner re-reads more context when that happens).
    """
    if encoding == ENCODING_UTF16LE:
        s = start
        while s >= 2 and _is_wide_content(_wide_unit(data, s - 2)):
            s -= 2
        e = end
        while e + 2 <= len(data) and _is_wide_content(_wide_unit(data, e)):
            e += 2
        return s, e
    s = start
    while s > 0 and _is_narrow_content(data[s - 1]):
        s -= 1
    e = end
    while e < len(data) and _is_narrow_content(data[e]):
        e += 1
    return s, e


def merge_spans(spans: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Sort and merge overlapping/adjacent [start, end) spans."""
    items = sorted((s, e) for s, e in spans if e > s)
    out: List[Tuple[int, int]] = []
    for s, e in items:
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def string_contains_any(text: str, keywords: Sequence[str]) -> Optional[str]:
    """Case-insensitive substring test over a str; returns the first hit keyword."""
    folded = text.casefold()
    for kw in keywords:
        if kw.casefold() in folded:
            return kw
    return None
