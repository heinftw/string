"""Permanence: persistence-source cleanup (registry + Recent Items / jump lists),
re-injection source identification, and optional target-process restart.

Memory wipes do not survive a process restart or reboot: what "comes back" is
reloaded from disk/registry.  This module (1) identifies keyword-matching
persistence entries AND re-injection sources (files Explorer re-parses, live
window titles the taskbar re-imports), (2) after explicit user confirmation,
removes ONLY keyword-matching entries while logging every deletion, and
(3) can taskkill + relaunch the target so a fresh process reloads only the
cleaned sources.

Granularity notes (kept honest):
* ShellBags: a matching BagMRU entry deletes that entry's value plus its node
  subkey; a matching bag under ``Bags`` deletes that numbered bag key.  This
  resets Explorer folder-view settings for the affected paths.
* Indexed MRU lists (RecentDocs, ComDlg32\\*MRU, WordWheelQuery): matching
  values are deleted and the key's ``MRUListEx`` slot table is rewritten
  without the dropped slots.
* Jump lists (``.automaticDestinations-ms`` / ``.customDestinations-ms``) are
  compound files that cannot be edited entry-by-entry without corrupting them;
  a match deletes the whole file (all of that application's jump-list
  entries), which is flagged per file and in the confirmation dialog.
* Files on Desktop / Start Menu / Downloads and live window titles are
  re-injection sources (Explorer re-parses/shown them on every start).  They
  are REPORTED; deletion is optional, explicit and per item.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from .matching import (
    Pattern,
    PatternSet,
    build_patterns,
    find_matches,
    string_contains_any,
)
from .processes import enum_window_titles

if sys.platform == "win32":
    import winreg
else:  # pragma: no cover - off-Windows stub so this module imports anywhere
    winreg = None

# Registry paths relative to HKCU.
BAGMRU_PATH = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
BAGS_PATH = r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
TYPED_PATHS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
RUNMRU_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
RECENTDOCS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
COMDLG32_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"
WORDWHEELQUERY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"

SHELLBAG_WARNING = (
    "Resets Explorer folder view settings for the affected path and removes its "
    "ShellBag history node."
)
JUMPLIST_WARNING = (
    "Deletes the whole jump-list file: ALL of that application's jump-list entries "
    "go away, including entries that do not match the keywords (the file format "
    "cannot be edited per entry without corrupting it)."
)
SHELL_FILE_WARNING = (
    "Deletes a real file/shortcut. Do this only if the item should not exist on "
    "disk: as long as it is displayed by Explorer, its name/metadata is re-parsed "
    "into explorer.exe memory after every restart."
)

_KIND_REG_VALUE_DEL = "reg-value-del"
_KIND_REG_KEY_DEL = "reg-key-del"
_KIND_REG_VALUE_SET = "reg-value-set"
_KIND_FILE_DEL = "file-del"


@dataclass(frozen=True)
class PendingAction:
    """One proposed deletion/edit, produced by the scan phase."""

    kind: str  # reg-value-del | reg-key-del | reg-value-set | file-del
    path: str  # HKCU-relative registry path, or directory path for files
    name: str  # value name / subkey name / file name
    matched_keyword: str
    detail: str
    warning: Optional[str] = None
    payload: Tuple[object, ...] = ()  # kind-specific (e.g. (reg_type, value))


@dataclass(frozen=True)
class CleanupResult:
    action: PendingAction
    ok: bool
    message: str


@dataclass(frozen=True)
class ReinjectionReport:
    """A keyword source that reloads into explorer.exe but is outside the
    automatic cleanup set (user files, live windows).  ``action`` is set when
    the item can be deleted after explicit opt-in."""

    source: str
    location: str
    detail: str
    matched_keyword: str
    deletable: bool
    action: Optional[PendingAction]


@dataclass(frozen=True)
class ScanReport:
    """Two-phase scan result: confirmed-candidate actions + re-injection reports."""

    actions: Tuple[PendingAction, ...]
    reports: Tuple[ReinjectionReport, ...]


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested anywhere)
# ---------------------------------------------------------------------------


def rebuild_mru_list_ex(data: bytes, dropped: Sequence[int]) -> bytes:
    """Rewrite an MRUListEx slot table (DWORD slots + 0xFFFFFFFF terminator)
    without the dropped slot numbers.  Odd-sized input is returned unchanged."""
    if len(data) % 4 or not data:
        return data
    drop = set(dropped)
    slots = struct.unpack(f"<{len(data) // 4}I", data)
    kept = [s for s in slots if s != 0xFFFFFFFF and s not in drop]
    return struct.pack(f"<{len(kept) + 1}I", *kept, 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# Registry scanning
# ---------------------------------------------------------------------------


def _require_windows() -> None:
    if winreg is None:
        raise OSError("persistence cleanup requires Windows (winreg is unavailable here)")


def _value_match(data, patterns: Sequence[Pattern], keywords: Sequence[str]) -> Optional[str]:
    """Return the first keyword found in a registry value's data, if any."""
    if isinstance(data, str):
        return string_contains_any(data, keywords)
    if isinstance(data, bytes):
        matches = find_matches(data, patterns)
        return matches[0].keyword if matches else None
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                kw = string_contains_any(item, keywords)
                if kw:
                    return kw
    return None


def _subkey_exists(path: str, name: str) -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
    except OSError:
        return False
    try:
        sub = winreg.OpenKey(key, name, 0, winreg.KEY_READ)
        winreg.CloseKey(sub)
        return True
    except OSError:
        return False
    finally:
        winreg.CloseKey(key)


def _first_tree_match(
    path: str, patterns: Sequence[Pattern], keywords: Sequence[str]
) -> Optional[Tuple[str, str, str]]:
    """First keyword-matching value at ``path`` or below -> (keyword, value, subpath)."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
    except OSError:
        return None
    try:
        i = 0
        while True:
            try:
                name, data, _vtype = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            kw = _value_match(data, patterns, keywords)
            if kw:
                return kw, name, path
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                break
            i += 1
            found = _first_tree_match(path + "\\" + sub, patterns, keywords)
            if found:
                return found
        return None
    finally:
        winreg.CloseKey(key)


def _scan_bagmru_key(
    full_path: str,
    actions: List[PendingAction],
    patterns: Sequence[Pattern],
    keywords: Sequence[str],
) -> None:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, full_path, 0, winreg.KEY_READ)
    except OSError:
        return
    remove_subkeys = set()
    try:
        i = 0
        while True:
            try:
                name, data, _vtype = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            kw = _value_match(data, patterns, keywords)
            if not kw:
                continue
            actions.append(
                PendingAction(
                    _KIND_REG_VALUE_DEL,
                    full_path,
                    name,
                    kw,
                    f"ShellBag MRU entry data matched {kw!r}",
                    SHELLBAG_WARNING,
                )
            )
            if name.isdigit() and _subkey_exists(full_path, name):
                actions.append(
                    PendingAction(
                        _KIND_REG_KEY_DEL,
                        full_path,
                        name,
                        kw,
                        f"ShellBag node '{full_path}\\{name}' belongs to matched entry {kw!r}",
                        SHELLBAG_WARNING,
                    )
                )
                remove_subkeys.add(name)
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                break
            i += 1
            if sub in remove_subkeys:
                continue
            _scan_bagmru_key(full_path + "\\" + sub, actions, patterns, keywords)
    finally:
        winreg.CloseKey(key)


def _scan_bags(
    actions: List[PendingAction],
    patterns: Sequence[Pattern],
    keywords: Sequence[str],
) -> None:
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, BAGS_PATH, 0, winreg.KEY_READ)
    except OSError:
        return
    try:
        i = 0
        bag_names: List[str] = []
        while True:
            try:
                bag_names.append(winreg.EnumKey(root, i))
            except OSError:
                break
            i += 1
    finally:
        winreg.CloseKey(root)
    for bag in bag_names:
        bag_path = BAGS_PATH + "\\" + bag
        found = _first_tree_match(bag_path, patterns, keywords)
        if found:
            kw, value_name, subpath = found
            actions.append(
                PendingAction(
                    _KIND_REG_KEY_DEL,
                    BAGS_PATH,
                    bag,
                    kw,
                    f"folder view settings bag {bag} matched {kw!r} (value '{value_name}' in '{subpath}')",
                    SHELLBAG_WARNING,
                )
            )


def _scan_indexed_mru_tree(
    full_path: str,
    actions: List[PendingAction],
    patterns: Sequence[Pattern],
    keywords: Sequence[str],
) -> None:
    """Recursively clean indexed MRU lists (RecentDocs, ComDlg32, WordWheelQuery).

    Matching values are deleted (slot name = decimal index) and the key's
    MRUListEx table is rewritten without the dropped slots.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, full_path, 0, winreg.KEY_READ)
    except OSError:
        return
    dropped_slots: List[int] = []
    try:
        i = 0
        while True:
            try:
                name, data, _vtype = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            if name == "MRUListEx":
                continue
            kw = _value_match(data, patterns, keywords)
            if kw:
                actions.append(
                    PendingAction(
                        _KIND_REG_VALUE_DEL,
                        full_path,
                        name,
                        kw,
                        f"MRU entry {full_path}\\{name} matched {kw!r}",
                    )
                )
                if name.isdigit():
                    dropped_slots.append(int(name))
        if dropped_slots:
            try:
                mru, _t = winreg.QueryValueEx(key, "MRUListEx")
            except OSError:
                mru = None
            if isinstance(mru, bytes) and mru:
                new_mru = rebuild_mru_list_ex(mru, dropped_slots)
                if new_mru != mru:
                    actions.append(
                        PendingAction(
                            _KIND_REG_VALUE_SET,
                            full_path,
                            "MRUListEx",
                            str(dropped_slots[0]),
                            f"rewrite MRUListEx in '{full_path}' without slot(s) "
                            f"{sorted(dropped_slots)}",
                            payload=(winreg.REG_BINARY, new_mru),
                        )
                    )
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                break
            i += 1
            _scan_indexed_mru_tree(full_path + "\\" + sub, actions, patterns, keywords)
    finally:
        winreg.CloseKey(key)


def _scan_typed_paths(
    actions: List[PendingAction],
    patterns: Sequence[Pattern],
    keywords: Sequence[str],
) -> None:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, TYPED_PATHS_PATH, 0, winreg.KEY_READ)
    except OSError:
        return
    try:
        i = 0
        while True:
            try:
                name, data, _vtype = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            kw = _value_match(data, patterns, keywords)
            if kw:
                actions.append(
                    PendingAction(
                        _KIND_REG_VALUE_DEL,
                        TYPED_PATHS_PATH,
                        name,
                        kw,
                        f"TypedPaths entry {name} matched {kw!r}",
                    )
                )
    finally:
        winreg.CloseKey(key)


def _scan_runmru(
    actions: List[PendingAction],
    patterns: Sequence[Pattern],
    keywords: Sequence[str],
) -> None:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUNMRU_PATH, 0, winreg.KEY_READ)
    except OSError:
        return
    deleted_letters: List[str] = []
    mru_list: Optional[str] = None
    try:
        i = 0
        while True:
            try:
                name, data, _vtype = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            if name == "MRUList":
                if isinstance(data, str):
                    mru_list = data
                continue
            kw = _value_match(data, patterns, keywords)
            if kw:
                actions.append(
                    PendingAction(
                        _KIND_REG_VALUE_DEL,
                        RUNMRU_PATH,
                        name,
                        kw,
                        f"RunMRU command {name} matched {kw!r}",
                    )
                )
                deleted_letters.append(name)
    finally:
        winreg.CloseKey(key)
    if mru_list is not None and deleted_letters:
        drop = {letter.casefold() for letter in deleted_letters}
        new_list = "".join(ch for ch in mru_list if ch.casefold() not in drop)
        if new_list != mru_list:
            actions.append(
                PendingAction(
                    _KIND_REG_VALUE_SET,
                    RUNMRU_PATH,
                    "MRUList",
                    deleted_letters[0],
                    f"rewrite RunMRU MRUList {mru_list!r} -> {new_list!r} (dropped {', '.join(deleted_letters)})",
                    payload=(winreg.REG_SZ, new_list),
                )
            )


# ---------------------------------------------------------------------------
# File + window scanning (re-injection sources)
# ---------------------------------------------------------------------------


def _recent_root() -> str:
    appdata = os.environ.get("APPDATA") or ""
    return os.path.join(appdata, "Microsoft", "Windows", "Recent")


def _shell_locations() -> List[Tuple[str, str, bool]]:
    """(label, directory, recursive) places whose items Explorer displays."""
    profile = os.environ.get("USERPROFILE") or ""
    public = os.environ.get("PUBLIC") or ""
    appdata = os.environ.get("APPDATA") or ""
    programdata = os.environ.get("PROGRAMDATA") or ""
    out: List[Tuple[str, str, bool]] = []
    if profile:
        out.append(("Desktop", os.path.join(profile, "Desktop"), False))
        out.append(("Downloads", os.path.join(profile, "Downloads"), False))
        out.append(
            (
                "Start Menu",
                os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs"),
                True,
            )
        )
    if public:
        out.append(("Public Desktop", os.path.join(public, "Desktop"), False))
    if programdata:
        out.append(
            (
                "Common Start Menu",
                os.path.join(programdata, "Microsoft", "Windows", "Start Menu", "Programs"),
                True,
            )
        )
    return out


def _file_matches(
    full: str,
    entry: str,
    patterns: Sequence[Pattern],
    keywords: Sequence[str],
) -> Optional[str]:
    kw = string_contains_any(os.path.splitext(entry)[0], keywords)
    if kw:
        return kw
    try:
        if os.path.getsize(full) > 32 * 1024 * 1024:
            return None
        with open(full, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    matches = find_matches(data, patterns)
    return matches[0].keyword if matches else None


def _scan_file_actions(
    actions: List[PendingAction],
    directory: str,
    suffixes: Tuple[str, ...],
    patterns: Sequence[Pattern],
    keywords: Sequence[str],
    detail_kind: str,
    warning: Optional[str],
    match_name: bool,
) -> None:
    try:
        entries = os.listdir(directory)
    except OSError:
        return
    for entry in entries:
        if suffixes and not entry.casefold().endswith(suffixes):
            continue
        full = os.path.join(directory, entry)
        if not os.path.isfile(full):
            continue
        matched_kw: Optional[str] = None
        if match_name:
            matched_kw = string_contains_any(os.path.splitext(entry)[0], keywords)
        if matched_kw is None:
            try:
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            matches = find_matches(data, patterns)
            if matches:
                matched_kw = matches[0].keyword
        if matched_kw is None:
            continue
        actions.append(
            PendingAction(
                _KIND_FILE_DEL,
                directory,
                entry,
                matched_kw,
                f"{detail_kind} '{entry}' matched {matched_kw!r}",
                warning,
            )
        )


def _scan_shell_files(
    reports: List[ReinjectionReport],
    patterns: Sequence[Pattern],
    keywords: Sequence[str],
) -> None:
    """Identify Desktop/Start Menu/Downloads items that re-inject the keywords.

    Shortcuts and other files alike are reported with a deletable action; the
    UI only executes them after explicit per-run opt-in (the confirm dialog's
    checkbox) because these are real user files outside the standard cleanup
    set.
    """
    for label, directory, recursive in _shell_locations():
        if recursive:
            stack = [directory]
            files: List[Tuple[str, str]] = []
            while stack:
                current = stack.pop()
                try:
                    entries = os.listdir(current)
                except OSError:
                    continue
                for entry in entries:
                    full = os.path.join(current, entry)
                    if os.path.isdir(full):
                        stack.append(full)
                    elif os.path.isfile(full):
                        files.append((full, entry))
        else:
            try:
                files = [
                    (os.path.join(directory, e), e)
                    for e in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, e))
                ]
            except OSError:
                continue
        for full, entry in files:
            matched_kw = _file_matches(full, entry, patterns, keywords)
            if matched_kw is None:
                continue
            directory_name = os.path.dirname(full)
            action = PendingAction(
                _KIND_FILE_DEL,
                directory_name,
                entry,
                matched_kw,
                f"{label} item '{entry}' matched {matched_kw!r}",
                SHELL_FILE_WARNING,
            )
            reports.append(
                ReinjectionReport(
                    f"file on {label}",
                    full,
                    f"'{entry}' (name/content matched {matched_kw!r}) is re-parsed by "
                    "Explorer whenever this location is displayed - delete or rename "
                    "it to stop re-injection",
                    matched_kw,
                    True,
                    action,
                )
            )


def _scan_window_titles(reports: List[ReinjectionReport], keywords: Sequence[str]) -> None:
    """Report live windows whose titles contain the keywords.

    Every explorer.exe taskbar re-imports window titles of running programs on
    startup, so titles come back unless the owning application is closed.
    """
    try:
        windows = enum_window_titles()
    except OSError:
        return
    for window in windows:
        kw = string_contains_any(window.title, keywords)
        if kw:
            reports.append(
                ReinjectionReport(
                    "live window title",
                    f"PID {window.pid} HWND 0x{window.hwnd:X}",
                    f"window title {window.title!r} matched {kw!r} - the taskbar of "
                    "every explorer.exe instance re-imports it; close the owning "
                    "application to stop re-injection",
                    kw,
                    False,
                    None,
                )
            )


# ---------------------------------------------------------------------------
# Public two-phase API
# ---------------------------------------------------------------------------


def scan_persistence(keywords: Sequence[str], include_utf8: bool = True) -> ScanReport:
    """Read-only identification phase.  Nothing is modified.

    ``actions`` are keyword-matching entries from the standard cleanup set
    (ShellBags, TypedPaths, RunMRU, RecentDocs, ComDlg32 MRUs, WordWheelQuery,
    Recent Items .lnk, jump lists) - one confirmation away from deletion.
    ``reports`` are re-injection sources outside that set (shell-visible files,
    live window titles) with optional per-item delete actions.
    """
    _require_windows()
    pattern_set: PatternSet = build_patterns(keywords, include_utf8=include_utf8)
    actions: List[PendingAction] = []
    reports: List[ReinjectionReport] = []

    _scan_bagmru_key(BAGMRU_PATH, actions, pattern_set.patterns, keywords)
    _scan_bags(actions, pattern_set.patterns, keywords)
    _scan_typed_paths(actions, pattern_set.patterns, keywords)
    _scan_runmru(actions, pattern_set.patterns, keywords)
    _scan_indexed_mru_tree(RECENTDOCS_PATH, actions, pattern_set.patterns, keywords)
    _scan_indexed_mru_tree(COMDLG32_PATH, actions, pattern_set.patterns, keywords)
    _scan_indexed_mru_tree(WORDWHEELQUERY_PATH, actions, pattern_set.patterns, keywords)

    recent = _recent_root()
    _scan_file_actions(
        actions,
        recent,
        (".lnk",),
        pattern_set.patterns,
        keywords,
        "Recent Items shortcut",
        None,
        match_name=True,
    )
    auto_dir = os.path.join(recent, "AutomaticDestinations")
    _scan_file_actions(
        actions,
        auto_dir,
        (".automaticdestinations-ms",),
        pattern_set.patterns,
        keywords,
        "automatic jump list",
        JUMPLIST_WARNING,
        match_name=False,
    )
    custom_dir = os.path.join(recent, "CustomDestinations")
    _scan_file_actions(
        actions,
        custom_dir,
        (".customdestinations-ms",),
        pattern_set.patterns,
        keywords,
        "custom jump list",
        JUMPLIST_WARNING,
        match_name=False,
    )

    _scan_shell_files(reports, pattern_set.patterns, keywords)
    _scan_window_titles(reports, keywords)

    return ScanReport(tuple(actions), tuple(reports))


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


def _delete_tree(parent_path: str, name: str) -> None:
    parent = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        parent_path,
        0,
        winreg.KEY_READ | winreg.KEY_SET_VALUE,
    )
    try:
        _delete_tree_opened(parent, name)
    finally:
        winreg.CloseKey(parent)


def _delete_tree_opened(parent, name: str) -> None:
    """Recursively delete ``parent\\name`` (values go with the key)."""
    try:
        sub = winreg.OpenKey(parent, name, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
    except OSError:
        winreg.DeleteKey(parent, name)
        return
    try:
        children: List[str] = []
        i = 0
        while True:
            try:
                children.append(winreg.EnumKey(sub, i))
            except OSError:
                break
            i += 1
        for child in children:
            _delete_tree_opened(sub, child)
    finally:
        winreg.CloseKey(sub)
    winreg.DeleteKey(parent, name)


def execute_action(action: PendingAction) -> CleanupResult:
    """Execute one confirmed action; never raises."""
    _require_windows()
    label = f"{action.kind} '{action.path}\\{action.name}'"
    try:
        if action.kind == _KIND_REG_VALUE_DEL:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                action.path,
                0,
                winreg.KEY_READ | winreg.KEY_SET_VALUE,
            )
            try:
                winreg.DeleteValue(key, action.name)
            finally:
                winreg.CloseKey(key)
            return CleanupResult(action, True, f"deleted registry value {label}")
        if action.kind == _KIND_REG_KEY_DEL:
            _delete_tree(action.path, action.name)
            return CleanupResult(action, True, f"deleted registry key {label} (subtree)")
        if action.kind == _KIND_REG_VALUE_SET:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                action.path,
                0,
                winreg.KEY_READ | winreg.KEY_SET_VALUE,
            )
            try:
                reg_type, value = action.payload
                winreg.SetValueEx(key, action.name, 0, int(reg_type), value)
            finally:
                winreg.CloseKey(key)
            return CleanupResult(action, True, f"updated registry value {label}")
        if action.kind == _KIND_FILE_DEL:
            os.remove(os.path.join(action.path, action.name))
            return CleanupResult(
                action, True, f"deleted file '{os.path.join(action.path, action.name)}'"
            )
        return CleanupResult(action, False, f"unknown action kind {action.kind!r} - skipped")
    except (OSError, ValueError, TypeError) as exc:
        return CleanupResult(action, False, f"{label} failed: {exc}")


def execute_cleanup(actions: Sequence[PendingAction]) -> List[CleanupResult]:
    """Execute confirmed actions in order; one failure never stops the rest."""
    _require_windows()
    results: List[CleanupResult] = []
    for action in actions:
        results.append(execute_action(action))
    return results


def restart_processes(process_name: str, image_paths: Sequence[str]) -> List[str]:
    """taskkill /f /im <name> then relaunch.  Returns log lines; never raises.

    explorer.exe is relaunched by image name (the shell re-registers itself).
    Other processes are relaunched from their captured image paths.
    """
    lines: List[str] = []
    try:
        proc = subprocess.run(
            ["taskkill", "/f", "/im", process_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        out = " ".join(out.split())
        if proc.returncode == 0:
            lines.append(f"[restart] taskkill /f /im {process_name}: OK {out}".rstrip())
        else:
            lines.append(
                f"[restart] taskkill /f /im {process_name}: exit {proc.returncode} {out}".rstrip()
            )
    except (OSError, subprocess.SubprocessError) as exc:
        lines.append(f"[restart] taskkill /f /im {process_name} failed: {exc}")
        return lines
    time.sleep(1.0)
    try:
        if process_name.casefold() == "explorer.exe":
            subprocess.Popen(["explorer.exe"])
            lines.append("[restart] launched explorer.exe (new shell instance)")
        else:
            launched = False
            for path in dict.fromkeys(p for p in image_paths if p):
                if os.path.isfile(path):
                    subprocess.Popen([path])
                    lines.append(f"[restart] launched '{path}'")
                    launched = True
                else:
                    lines.append(f"[restart] image path '{path}' no longer exists - not launched")
            if not launched:
                lines.append(
                    f"[restart] {process_name} was not relaunched: no valid image path was captured."
                )
    except OSError as exc:
        lines.append(f"[restart] relaunch failed: {exc}")
    return lines
