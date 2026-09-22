"""Cross-platform unit tests for core.matching (pure logic, no win32 calls).

Run from the repository root:

    python -m unittest tests.test_matching -v
"""

from __future__ import annotations

import unittest

from core.matching import (
    ENCODING_ANSI,
    ENCODING_UTF16LE,
    ENCODING_UTF8,
    PROCESS_HACKER_MIN_STRING_LENGTH,
    build_patterns,
    build_scan_plan,
    find_matches,
    merge_spans,
    parse_keywords,
    resolve_string_bounds,
    short_keyword_notes,
    string_contains_any,
)


def _hits(data: bytes, keywords, include_utf8: bool = True):
    pset = build_patterns(keywords, include_utf8=include_utf8)
    return find_matches(data, pset.patterns)


class ParseKeywordsTests(unittest.TestCase):
    def test_single(self):
        self.assertEqual(parse_keywords("madium"), ["madium"])

    def test_commas_and_whitespace(self):
        self.assertEqual(parse_keywords("  madium ,\t secret project \n"),
                         ["madium", "secret project"])

    def test_empty_and_whitespace_only(self):
        self.assertEqual(parse_keywords(""), [])
        self.assertEqual(parse_keywords("   "), [])
        self.assertEqual(parse_keywords(" , , , "), [])

    def test_phrase_with_spaces_kept(self):
        self.assertEqual(parse_keywords("i bought madium"), ["i bought madium"])

    def test_case_insensitive_dedupe_keeps_first(self):
        self.assertEqual(parse_keywords("Madium, madium, MADIUM"), ["Madium"])


class AnsiMatchTests(unittest.TestCase):
    def test_case_insensitive_substring(self):
        data = b"\x00i BoUgHt MaDiUm yesterday\x00tail\x00"
        hits = _hits(data, ["madium"])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].keyword, "madium")
        self.assertEqual(hits[0].encoding, ENCODING_ANSI)

    def test_full_sentence_boundary_resolution(self):
        sentence = b"i bought madium yesterday morning"
        data = b"\x00" + sentence + b"\x00\x00next\x00"
        hits = _hits(data, ["madium"])
        self.assertEqual(len(hits), 1)
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], sentence)  # ENTIRE containing string

    def test_boundary_stops_at_tab_and_control(self):
        data = b"mad\tmadium\x07madium2"
        hits = _hits(data, ["madium2"])
        self.assertEqual(len(hits), 1)
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], b"madium2")

    def test_high_ansi_bytes_are_content(self):
        data = b"\x00caf\xe9 madium au lait\x00"
        hits = _hits(data, ["madium"])
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], b"caf\xe9 madium au lait")

    def test_multiple_strings_in_one_buffer(self):
        data = b"\x00alpha madium\x00beta madium\x00"
        hits = _hits(data, ["madium"])
        self.assertEqual(len(hits), 2)
        spans = merge_spans(
            resolve_string_bounds(data, h.start, h.end, h.encoding) for h in hits
        )
        self.assertEqual([data[s:e] for s, e in spans],
                         [b"alpha madium", b"beta madium"])


class Utf16MatchTests(unittest.TestCase):
    def test_wide_even_alignment_full_sentence(self):
        sentence = "i bought madium today"
        data = b"\x00\x00" + sentence.encode("utf-16le") + b"\x00\x00junk"
        hits = _hits(data, ["madium"])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].encoding, ENCODING_UTF16LE)
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], sentence.encode("utf-16le"))
        self.assertEqual(lo % 2, 0)

    def test_wide_odd_alignment(self):
        sentence = "i bought madium today"
        data = b"\xcc" + b"\x00\x00" + sentence.encode("utf-16le") + b"\x00\x00"
        hits = _hits(data, ["madium"])
        self.assertEqual(len(hits), 1)
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], sentence.encode("utf-16le"))
        self.assertEqual(lo % 2, 1)  # odd unit grid preserved

    def test_wide_case_insensitive(self):
        data = "x MaDiUm y".encode("utf-16le")
        hits = _hits(data, ["madium"])
        self.assertEqual(len(hits), 1)

    def test_wide_double_null_terminator_boundary(self):
        prev = "old folder".encode("utf-16le")
        target = "madium here".encode("utf-16le")
        data = prev + b"\x00\x00" + target + b"\x00\x00" + "after".encode("utf-16le")
        hits = _hits(data, ["madium"])
        self.assertEqual(len(hits), 1)
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], target)  # terminator itself not included
        self.assertEqual(data[hi:hi + 2], b"\x00\x00")

    def test_wide_control_unit_stops_run(self):
        text = "aaa\tmadium"  # \t as its own wide unit (0x0009) terminates
        data = text.encode("utf-16le")
        hits = _hits(data, ["madium"])
        self.assertEqual(len(hits), 1)
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], "madium".encode("utf-16le"))

    def test_non_ascii_keyword_wide_casefold(self):
        target = "MÄDIUM projekt".encode("utf-16le")
        data = b"\x00\x00" + target + b"\x00\x00"
        hits = _hits(data, ["mädi"])
        self.assertEqual(len(hits), 1)
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], target)

    def test_wide_mixed_case_variants(self):
        for spelling in ("madium", "Madium", "MADIUM", "mAdIuM"):
            data = f"keep {spelling} gone".encode("utf-16le")
            self.assertEqual(len(_hits(data, ["madium"])), 1, spelling)


class Utf8MatchTests(unittest.TestCase):
    def test_utf8_pattern_only_for_non_ascii(self):
        pset = build_patterns(["madium"], include_utf8=True)
        encodings = {p.encoding for p in pset.patterns}
        self.assertIn(ENCODING_ANSI, encodings)
        self.assertIn(ENCODING_UTF16LE, encodings)
        self.assertNotIn(ENCODING_UTF8, encodings)  # pure ASCII: UTF-8 == ANSI

    def test_utf8_multibyte_match(self):
        data = "x MÄ y".encode("utf-8") + b"\x00" + "mä z".encode("utf-8")
        hits = _hits(data, ["mä"])
        self.assertEqual(len(hits), 2)
        encodings = {h.encoding for h in hits}
        self.assertIn(ENCODING_UTF8, encodings)

    def test_utf8_disabled_skips_pattern(self):
        pset = build_patterns(["mä"], include_utf8=False)
        encodings = {p.encoding for p in pset.patterns}
        self.assertNotIn(ENCODING_UTF8, encodings)


class BoundaryAndMergeTests(unittest.TestCase):
    def test_run_clipped_at_buffer_edge(self):
        data = b"purchased madium"
        hits = _hits(data, ["madium"])
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual((lo, hi), (0, len(data)))

    def test_merge_spans_overlapping_and_adjacent(self):
        self.assertEqual(merge_spans([(5, 10), (1, 6), (10, 12), (20, 22)]),
                         [(1, 12), (20, 22)])

    def test_merge_spans_empty_and_invalid(self):
        self.assertEqual(merge_spans([]), [])
        self.assertEqual(merge_spans([(5, 5)]), [])

    def test_overlapping_keywords_one_span(self):
        data = b"\x00xx madium yy\x00"
        hits = _hits(data, ["mad", "madium", "ium"])
        self.assertGreaterEqual(len(hits), 2)
        spans = merge_spans(
            resolve_string_bounds(data, h.start, h.end, h.encoding) for h in hits
        )
        self.assertEqual(spans, [(1, 13)])

    def test_multiword_phrase(self):
        sentence = b"the whole secret project is here"
        data = b"\x00" + sentence + b"\x00"
        hits = _hits(data, ["secret project"])
        self.assertEqual(len(hits), 1)
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], sentence)

    def test_keyword_hits_do_not_split_long_sentence(self):
        sentence = b"i bought madium yesterday and then more words followed"
        data = sentence + b"\x00"
        hits = _hits(data, ["madium"])
        lo, hi = resolve_string_bounds(data, hits[0].start, hits[0].end, hits[0].encoding)
        self.assertEqual(data[lo:hi], sentence)


class ScanPlanTests(unittest.TestCase):
    """The fused per-encoding scanner must agree with find_matches where the
    per-keyword scanner is authoritative, and never create false hits around
    zero-filled unreadable pages (scanner gap semantics)."""

    @staticmethod
    def _keyed(matches):
        return [(m.keyword, m.start, m.end, m.encoding) for m in matches]

    def test_equivalent_to_find_matches_on_disjoint_keywords(self):
        data = (
            b"\x00i bought madium\x00"
            + "top secret project".encode("utf-16le")
            + b"\x00\x00"
            + b"madium again\x00"
        )
        plan = build_scan_plan(["madium", "secret project"])
        pset = build_patterns(["madium", "secret project"])
        self.assertEqual(self._keyed(plan.find(data)), self._keyed(find_matches(data, pset.patterns)))

    def test_equivalent_to_find_matches_with_overlapping_keywords(self):
        data = b"\x00madium\x00"
        plan = build_scan_plan(["mad", "madium"])
        pset = build_patterns(["mad", "madium"])
        self.assertEqual(self._keyed(plan.find(data)), self._keyed(find_matches(data, pset.patterns)))
        self.assertEqual({h.keyword for h in plan.find(data)}, {"mad", "madium"})

    def test_merged_span_same_for_overlapping_keywords(self):
        data = b"\x00xx madium yy\x00"
        plan = build_scan_plan(["mad", "ium", "madium"])
        spans = merge_spans(
            resolve_string_bounds(data, h.start, h.end, h.encoding) for h in plan.find(data)
        )
        self.assertEqual(spans, [(1, 13)])

    def test_mixed_encodings_in_one_plan(self):
        data = b"\x00madium\x00" + "madium".encode("utf-16le") + b"\x00\x00"
        plan = build_scan_plan(["madium"])
        hits = plan.find(data)
        self.assertEqual(len(hits), 2)
        self.assertEqual(
            {h.encoding for h in hits}, {ENCODING_ANSI, ENCODING_UTF16LE}
        )

    def test_zero_filled_gap_is_a_boundary_not_a_bridge(self):
        # Two runs separated by an unreadable (zero-filled) gap must yield two
        # separate wipe spans, and no false hit may be stitched across the gap.
        run1 = b"aaa madium bbb"
        run2 = b"ccc madium ddd"
        data = b"\x00" + run1 + b"\x00" + b"\x00" * 16 + run2 + b"\x00"
        plan = build_scan_plan(["madium"])
        hits = plan.find(data)
        self.assertEqual(len(hits), 2)
        spans = merge_spans(
            resolve_string_bounds(data, h.start, h.end, h.encoding) for h in hits
        )
        self.assertEqual([data[s:e] for s, e in spans], [run1, run2])

    def test_zero_gap_does_not_synthesize_wide_hits(self):
        # alternating letters and zeros must NOT match a UTF-16LE pattern
        # across a zero gap (group positions must hold real letters).
        data = b"\x00m\x00a\x00" + b"\x00" * 8 + b"d\x00i\x00u\x00m\x00"
        plan = build_scan_plan(["madium"])
        self.assertEqual(plan.find(data), [])


class HelperTests(unittest.TestCase):
    def test_short_keyword_notes(self):
        notes = short_keyword_notes(["ab", "madium"])
        self.assertEqual(len(notes), 1)
        self.assertIn("ab", notes[0])
        self.assertIn(str(PROCESS_HACKER_MIN_STRING_LENGTH), notes[0])

    def test_no_notes_for_long_keywords(self):
        self.assertEqual(short_keyword_notes(["madium"]), [])

    def test_pattern_set_notes_include_short_keyword(self):
        pset = build_patterns(["abc"])
        self.assertTrue(any("abc" in n for n in pset.notes))

    def test_string_contains_any_casefold(self):
        self.assertEqual(string_contains_any("MÄDIUM Projekt", ["mädi"]), "mädi")
        self.assertIsNone(string_contains_any("nothing here", ["madium"]))

    def test_duplicate_matches_deduped_across_patterns(self):
        # ANSI + UTF-16LE + (skipped UTF-8) patterns exist; narrow text yields
        # exactly one hit per occurrence.
        data = b"madium\x00madium"
        hits = _hits(data, ["madium"])
        self.assertEqual(len(hits), 2)

    def test_match_sorting(self):
        data = b"\x00b madium\x00a madium\x00"
        hits = _hits(data, ["madium"])
        self.assertEqual([h.start for h in hits], sorted(h.start for h in hits))

    def test_unrepresentable_ansi_keyword_reports_note(self):
        pset = build_patterns(["\u0130stanbul"])  # latin-1 cannot encode 'İ'
        self.assertTrue(any("ANSI" in n or "ansi" in n for n in pset.notes))
        encodings = {p.encoding for p in pset.patterns}
        self.assertIn(ENCODING_UTF16LE, encodings)
        self.assertNotIn(ENCODING_ANSI, encodings)


if __name__ == "__main__":
    unittest.main()
