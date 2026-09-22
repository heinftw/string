"""Process enumeration and per-PID queries (toolhelp snapshot, no external tools)."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import List, Optional, Sequence

from . import privileges, winapi


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    arch: str  # "x86" | "x64" | "ia64" | "arm64" | "unknown"


@dataclass(frozen=True)
class WindowInfo:
    hwnd: int
    pid: int
    title: str


def enum_window_titles() -> List[WindowInfo]:
    """Titles of all visible top-level windows (Explorer's taskbar re-imports
    these into every new explorer.exe instance - a key re-injection source)."""
    out: List[WindowInfo] = []

    @winapi.WNDENUMPROC
    def _callback(hwnd, _lparam):
        try:
            if winapi.IsWindowVisible(hwnd):
                length = winapi.GetWindowTextLengthW(hwnd)
                if 0 < length < 4096:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    if winapi.GetWindowTextW(hwnd, buf, length + 1):
                        pid = winapi.DWORD(0)
                        winapi.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                        out.append(
                            WindowInfo(int(hwnd or 0), pid.value, buf.value)
                        )
        except OSError:
            pass  # a window can vanish mid-enumeration; keep going
        return True

    winapi.EnumWindows(_callback, 0)
    return out


def get_process_arch(pid: int) -> str:
    """Architecture of a running process ('x86'/'x64'/..., or 'unknown')."""
    handle = winapi.OpenProcess(winapi.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return "unknown"
    try:
        wow64 = winapi.BOOL(0)
        if not winapi.IsWow64Process(handle, ctypes.byref(wow64)):
            return "unknown"
        if wow64.value:
            return "x86"
        return privileges.native_arch()
    finally:
        winapi.CloseHandle(handle)


def get_process_path(pid: int) -> Optional[str]:
    """Full image path of a process (for relaunching after taskkill)."""
    handle = winapi.OpenProcess(winapi.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = winapi.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if winapi.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        winapi.CloseHandle(handle)


def enumerate_processes() -> List[ProcessInfo]:
    """All running processes as (pid, name, arch), via CreateToolhelp32Snapshot."""
    snapshot = winapi.CreateToolhelp32Snapshot(winapi.TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == winapi.INVALID_HANDLE_VALUE:
        raise OSError(winapi.win_error_message("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)"))
    try:
        entry = winapi.PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(winapi.PROCESSENTRY32W)
        out: List[ProcessInfo] = []
        ok = winapi.Process32FirstW(snapshot, ctypes.byref(entry))
        if not ok:
            raise OSError(winapi.win_error_message("Process32FirstW"))
        while ok:
            pid = entry.th32ProcessID
            if pid != 0:
                out.append(ProcessInfo(pid, entry.szExeFile, get_process_arch(pid)))
            ok = winapi.Process32NextW(snapshot, ctypes.byref(entry))
        return out
    finally:
        winapi.CloseHandle(snapshot)


def pids_for_name(name: str, processes: Optional[Sequence[ProcessInfo]] = None) -> List[int]:
    """Every PID whose image name matches (case-insensitive)."""
    target = name.casefold()
    pool = processes if processes is not None else enumerate_processes()
    return [p.pid for p in pool if p.name.casefold() == target]
