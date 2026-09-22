"""Cross-platform unit tests for the pure helpers in core.persistence.

Run from the repository root:

    python -m unittest tests.test_persistence -v
"""

from __future__ import annotations

import struct
import unittest

from core.persistence import rebuild_mru_list_ex


def _mru(*slots: int) -> bytes:
    return struct.pack(f"<{len(slots) + 1}I", *slots, 0xFFFFFFFF)


class RebuildMruListExTests(unittest.TestCase):
    def test_drops_slots_and_keeps_order(self):
        self.assertEqual(rebuild_mru_list_ex(_mru(2, 0, 5), [0]), _mru(2, 5))

    def test_drops_multiple(self):
        self.assertEqual(rebuild_mru_list_ex(_mru(7, 3, 1, 4), [3, 4]), _mru(7, 1))

    def test_all_dropped_leaves_terminator_only(self):
        self.assertEqual(rebuild_mru_list_ex(_mru(1, 2), [1, 2]), _mru())

    def test_missing_slots_are_noop(self):
        data = _mru(9, 8)
        self.assertEqual(rebuild_mru_list_ex(data, [3]), data)

    def test_adds_terminator_when_absent(self):
        raw = struct.pack("<2I", 4, 6)
        self.assertEqual(rebuild_mru_list_ex(raw, []), _mru(4, 6))

    def test_existing_terminator_not_duplicated(self):
        self.assertEqual(rebuild_mru_list_ex(_mru(1), [99]), _mru(1))

    def test_odd_sized_input_unchanged(self):
        raw = b"\x01\x02\x03"
        self.assertEqual(rebuild_mru_list_ex(raw, [1]), raw)

    def test_empty_input_unchanged(self):
        self.assertEqual(rebuild_mru_list_ex(b"", [0]), b"")


if __name__ == "__main__":
    unittest.main()
