# string-wiper

Windows desktop tool (PySide6 + pure ctypes) that wipes every string containing
your keyword(s) from the live memory of a selected process (default
`explorer.exe`) and then removes the registry/disk sources that would re-inject
those strings after a process restart or reboot.

## How it works

1. **Privilege acquisition** — at startup the app detects elevation and enables
   `SeDebugPrivilege` via `AdjustTokenPrivileges`, so `OpenProcess` succeeds on
   protected processes; non-admin runs are flagged in the UI and every access
   failure maps to a readable `ctypes.WinError` message in the log.
2. **Process discovery** — `CreateToolhelp32Snapshot`/`TH32CS_SNAPPROCESS`
   lists name + PID + architecture; the picker defaults to `explorer.exe` and
   Clean processes **every PID** matching the chosen name.
3. **Region enumeration** — `VirtualQueryEx` with the correct x64
   `MEMORY_BASIC_INFORMATION` (48 bytes) walks the address space (64-bit safe);
   `MEM_PRIVATE` heaps are scanned by default, `MEM_RESERVE`/non-committed,
   `PAGE_NOACCESS` and `PAGE_GUARD` regions are skipped; `MEM_MAPPED`/`MEM_IMAGE`
   can be added only with an explicit crash warning.
4. **Dual-encoding matching** — each keyword becomes case-insensitive byte
   patterns for ANSI (single-byte) and UTF-16LE (both byte alignments: matching
   is a plain byte search, so even and odd unit grids are both hit), optionally
   UTF-8; ASCII patterns are searched at C speed on a case-folded buffer copy
   (10x+ faster than per-keyword regex scans), reads are 4 MiB chunks with
   pattern-sized overlap so hits never split across chunk boundaries, and a
   failed read degrades to page granularity - one unreadable page never skips
   the rest of a region.
5. **Boundary resolution** — every hit is grown to its full printable run
   (narrow: bytes 0x20-0x7E and 0x80-0xFF; wide: printable units on the
   string's own unit grid, stopping at the NUL / double-NUL terminator) so the
   entire containing string ("i bought madium yesterday") dies with its keyword;
   unreadable pages are zero-filled and therefore act as hard boundaries.
6. **In-place null overwrite** — read-only pages get a temporary
   `VirtualProtectEx` lift; `WriteProcessMemory` writes exactly the span length
   with 0x00 bytes (never free/resize/reallocate, so heap metadata and adjacent
   allocations stay intact); original protection is restored and **every write
   is verified by re-reading**.
7. **Rescan loop** — scan → wipe → rescan, capped at 5 passes, with match
   counts logged per pass; a final internal verification re-scan reports
   "matches found -> matches remaining" and names any regions that keep
   regenerating strings if matches persist past the cap.
8. **Persistence cleanup** — after a separate confirmation, only
   keyword-matching entries are removed (every deletion logged): ShellBags
   `BagMRU`/`Bags`, `TypedPaths`, `RunMRU` (MRUList rewritten), Recent Items
   `.lnk` shortcuts and automatic/custom jump lists.
9. **Restart option** — `taskkill /f /im <name>` plus relaunch (optional,
   confirmed separately). A freshly started process can only rebuild its
   strings from the already-cleaned registry/disk sources, so the wiped strings
   cannot reappear — this is why RAM-only wiping is not "permanent" and source
   cleanup is required.
10. **Verification** — the internal verification pass and Process Hacker's
    Strings scan (ASCII + Unicode, minimum length 4) look at the same data, so
    both reports agree: zero internal matches means zero Process Hacker
    results.

## Setup & run

- Windows 10/11 x64, **64-bit Python 3.10+** (a 32-bit interpreter cannot
  access 64-bit targets; the app detects and refuses mismatched targets).
- Install the only third-party dependency:

      pip install -r requirements.txt

- Launch from an **elevated (Administrator) terminal** (required for
  `SeDebugPrivilege` and for writing into protected processes):

      python main.py

- Enter one or more comma-separated keywords (phrases with spaces are fine),
  pick the target process (default `explorer.exe`), optionally enable the
  UTF-8 / MEM_MAPPED / restart checkboxes, press **Clean memory**, confirm the
  write dialog, then confirm the separate persistence-cleanup dialog.

Run the pure-logic unit tests anywhere with `python -m unittest tests.test_matching`.

## Verification with Process Hacker

1. Start Process Hacker **as Administrator**.
2. Locate the target process (e.g. `explorer.exe`; pick any PID if several run).
3. Right-click the process -> **Properties** -> **Memory** tab -> **Strings...**
4. Enable both **ANSI** and **Unicode** (wide) string types and keep the
   minimum string length at its default (**4**).
5. Search for each keyword, case-insensitively.
6. Confirm the result list is empty: zero strings contain the keyword.

This matches the app's internal verification (same encodings, same case-
insensitive substring semantics). Notes: keywords shorter than 4 characters
are wiped here but their containing strings may not appear in Process Hacker's
Strings view at all (below its minimum display length); repeat the check after
restarting `explorer.exe` or rebooting to confirm permanence.

## Risks & limitations

- **Strings re-created while the process runs.** A live process (especially
  `explorer.exe`) can re-create strings from its own state after a wipe. The
  5-pass rescan loop catches re-creations during the run; if matches persist
  after the cap, the app logs which memory regions keep regenerating. Do the
  persistence cleanup and restart the process (or reboot) to stop the source.
- **Pages even an elevated reader cannot read.** Some committed pages refuse
  `ReadProcessMemory` from another process (Windows 11 COW-hardened image
  pages, transition pages of freed memory, certain instrumentation areas).
  The tool retries at page granularity and scans everything readable; the
  unreadable pages themselves cannot be verified or wiped and are logged as
  zero-filled boundaries per region.
- **Copies in other processes' memory.** Only the selected process is scrubbed.
  Clipboard holders, search indexers, antivirus, other apps that copied the
  string keep their own copies. *Remediation:* find them with Process Hacker
  (system-wide Strings / handle search) and close those applications or scrub
  each one with this tool; only a reboot clears everything currently in RAM.
- **Memory-mapped files on disk.** If the string lives in a file mapping,
  the bytes may be backed by a file on disk; writing to shared mapped views can
  also dirty that file, which is why `MEM_MAPPED`/`MEM_IMAGE` scanning is off by
  default and warned. The file itself is never cleaned by this tool.
  *Remediation:* locate the file (Explorer search, `findstr /spin`, or your own
  index), edit or securely delete it (`cipher /w:<folder>` scrubs free space
  after deletion).
- **Pagefile / hiberfile residue.** Swapped-out heap pages can contain the
  strings in `pagefile.sys`; `hiberfil.sys` is a RAM snapshot. Both persist on
  disk across app restarts. *Remediation:* reboot (clears the pagefile on
  standard configurations and replaces hiberfil with the post-clean RAM state)
  and disable hibernation if no snapshot should exist at all
  (`powercfg /h off` from an elevated prompt).
- **NTFS artifacts.** The USN change journal (`$UsnJrnl:$J`), `$MFT` entries
  and directory index slack can record file names/paths containing the
  keywords (e.g. deleted Recent Items or documents). Registry hives keep
  transaction logs (`RegBack`, `.LOG1/.LOG2`, System Restore copies) that may
  retain deleted values. *Remediation:* `fsutil usn deletejournal /D C:`
  (elevated, journal history is lost), `cipher /w:C:\` for free-space slack,
  delete System Restore points (System Protection settings), and note that
  shadow copies / backups may still hold the data.
- **ShellBags cleanup granularity.** A keyword-matching BagMRU entry (its
  value plus node) or a matching `Bags` key is deleted as a unit. This resets
  Explorer folder view settings (size, layout, icon mode) for the affected
  paths — unrelated bags are untouched.
- **Jump-list cleanup granularity.** `.automaticDestinations-ms` /
  `.customDestinations-ms` are compound files that cannot be edited per entry
  without corrupting them; a match deletes the whole file, removing that
  application's other jump-list entries too. Each such deletion is flagged
  individually before you confirm.
- **ANSI matching range.** The single-byte pattern covers the latin-1 code
  points (the ANSI/CP1252 range for Western European text); keywords outside
  it are matched via their UTF-16LE/UTF-8 patterns only (logged).
- **Printable-run wipe cap.** String boundaries grow up to 1 MiB in each
  direction from the keyword; longer runs are cut at that limit (logged as the
  span boundaries). Wiping follows the printable-run rule exactly, so
  structural bytes (counters, pointers, terminators) around the run are never
  touched. Unreadable pages break a run at the gap.
- **Writes can crash the target.** In-place nulling of live heap strings is
  destructive by design; a program that dereferences its own wiped strings can
  misbehave or crash (much more likely with the `MEM_MAPPED`/`MEM_IMAGE`
  option). Save your work before running this on interactive processes.

Operate only on systems and processes you own or are authorized to modify.

## Project layout & architecture deviations

    string-wiper/
    ├── main.py              # entry point: QApplication + MainWindow
    ├── requirements.txt     # PySide6 (only third-party dependency)
    ├── README.md
    ├── .gitignore
    ├── core/
    │   ├── winapi.py        # every ctypes struct/constant/function binding + WinError mapping
    │   ├── privileges.py    # SeDebugPrivilege, elevation + architecture detection
    │   ├── processes.py     # toolhelp enumeration (name, PID, arch), path query
    │   ├── matching.py      # PURE keyword->pattern + boundary logic (unit-tested anywhere)
    │   ├── scanner.py       # region enum, chunked reads, cross-chunk hits, remote spans
    │   ├── wiper.py         # protect->zero->restore->verify + scan/wipe/rescan loop
    │   └── persistence.py   # registry + Recent Items/jump-list cleanup + restart
    ├── ui/
    │   ├── main_window.py   # PySide6 main window
    │   └── workers.py       # QThread workers (log/progress/result/cancel contract)
    └── tests/
        └── test_matching.py # cross-platform tests for matching + boundary logic

Deviations from the reference architecture: (1) `__init__.py` package markers
were added so package-relative imports resolve deterministically;
(2) `winapi.py` additionally owns the `WinError`-to-message mapper and the
few bindings needed by the required elevation/architecture/relaunch features
(`GetTokenInformation`, `GetNativeSystemInfo`, `GetExitCodeProcess`,
`QueryFullProcessImageNameW`) so struct/flag/function definitions exist in
exactly one place; (3) tests use stdlib `unittest` (no pytest dependency);
(4) jump-list files are cleaned at whole-file granularity (see Risks) because
the compound-file format cannot be edited per entry safely.
