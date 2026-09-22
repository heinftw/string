"""Address-space enumeration and chunked memory scanning (pure ctypes).

Holds the process-memory access layer shared by the wiper: open with VM rights,
enumerate regions with VirtualQueryEx, read in overlapping chunks, and resolve
string boundaries around raw pattern hits (re-reading extra context when a
printable run reaches a read boundary).
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from . import winapi
from .matching import Pattern, find_matches, resolve_string_bounds

SCAN_CHUNK_SIZE = 1 << 20  # 1 MiB owned bytes per read
INITIAL_CONTEXT = 4096  # first boundary-context window around a hit
MAX_STRING_PAD = 1 << 20  # cap for boundary expansion (limits wipe-span size)

# Base-protection classes (modifiers such as PAGE_GUARD masked out).
_READABLE = {
    winapi.PAGE_READONLY,
    winapi.PAGE_READWRITE,
    winapi.PAGE_WRITECOPY,
    winapi.PAGE_EXECUTE_READ,
    winapi.PAGE_EXECUTE_READWRITE,
    winapi.PAGE_EXECUTE_WRITECOPY,
}
_WRITABLE = {
    winapi.PAGE_READWRITE,
    winapi.PAGE_WRITECOPY,
    winapi.PAGE_EXECUTE_READWRITE,
    winapi.PAGE_EXECUTE_WRITECOPY,
}
_EXECUTABLE = {
    winapi.PAGE_EXECUTE,
    winapi.PAGE_EXECUTE_READ,
    winapi.PAGE_EXECUTE_READWRITE,
    winapi.PAGE_EXECUTE_WRITECOPY,
}

_PROTECT_NAMES = {
    winapi.PAGE_NOACCESS: "PAGE_NOACCESS",
    winapi.PAGE_READONLY: "PAGE_READONLY",
    winapi.PAGE_READWRITE: "PAGE_READWRITE",
    winapi.PAGE_WRITECOPY: "PAGE_WRITECOPY",
    winapi.PAGE_EXECUTE: "PAGE_EXECUTE",
    winapi.PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
    winapi.PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
    winapi.PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
}

_TYPE_NAMES = {
    winapi.MEM_PRIVATE: "MEM_PRIVATE",
    winapi.MEM_MAPPED: "MEM_MAPPED",
    winapi.MEM_IMAGE: "MEM_IMAGE",
}


def protect_name(protect: int) -> str:
    base = _PROTECT_NAMES.get(protect & 0xFF, f"0x{protect & 0xFF:02X}")
    if protect & winapi.PAGE_GUARD:
        base += "|PAGE_GUARD"
    return base


def type_name(type_: int) -> str:
    return _TYPE_NAMES.get(type_, f"0x{type_:X}")


def base_protect(protect: int) -> int:
    return protect & 0xFF


def is_readable(protect: int) -> bool:
    return base_protect(protect) in _READABLE and not (protect & winapi.PAGE_GUARD)


def is_writable(protect: int) -> bool:
    return base_protect(protect) in _WRITABLE and not (protect & winapi.PAGE_GUARD)


def is_executable(protect: int) -> bool:
    return base_protect(protect) in _EXECUTABLE


@dataclass(frozen=True)
class RegionInfo:
    base: int
    size: int
    state: int
    protect: int
    type: int

    @property
    def end(self) -> int:
        return self.base + self.size

    def describe(self) -> str:
        return (
            f"0x{self.base:X}-0x{self.end:X} "
            f"{type_name(self.type)} {protect_name(self.protect)}"
        )


@dataclass(frozen=True)
class Hit:
    """Raw pattern hit with its absolute address and owning region."""

    address: int
    size: int
    keyword: str
    encoding: str
    region: RegionInfo


def open_target_process(pid: int) -> int:
    """Open a process for read/write/query; raises OSError with guidance on failure."""
    access = (
        winapi.PROCESS_VM_READ
        | winapi.PROCESS_VM_WRITE
        | winapi.PROCESS_VM_OPERATION
        | winapi.PROCESS_QUERY_INFORMATION
    )
    handle = winapi.OpenProcess(access, False, pid)
    if not handle:
        raise OSError(
            winapi.win_error_message(f"OpenProcess(PID {pid})")
            + " If this is access denied: run the tool as Administrator; some "
            "protected processes (antivirus, system) still refuse VM access."
        )
    return handle


def process_alive(handle: int) -> bool:
    code = winapi.DWORD(0)
    if not winapi.GetExitCodeProcess(handle, ctypes.byref(code)):
        return False
    return code.value == winapi.STILL_ACTIVE


def virtual_query(handle: int, address: int) -> Optional[winapi.MEMORY_BASIC_INFORMATION]:
    mbi = winapi.MEMORY_BASIC_INFORMATION()
    got = winapi.VirtualQueryEx(
        handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)
    )
    if not got:
        return None
    return mbi


def read_bytes(handle: int, address: int, size: int) -> Optional[bytes]:
    """Read ``size`` bytes at ``address``; None on failure, possibly short on success."""
    if size <= 0:
        return b""
    buf = (ctypes.c_uint8 * size)()
    read = winapi.SIZE_T(0)
    ok = winapi.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buf,
        size,
        ctypes.byref(read),
    )
    if not ok:
        return None
    return bytes(buf[: read.value])


def write_bytes(handle: int, address: int, data: bytes) -> bool:
    written = winapi.SIZE_T(0)
    buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    ok = winapi.WriteProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buf,
        len(data),
        ctypes.byref(written),
    )
    return bool(ok and written.value == len(data))


def virtual_protect(handle: int, address: int, size: int, new_protect: int) -> Tuple[bool, int]:
    """VirtualProtectEx; returns (ok, previous_protect)."""
    old = winapi.DWORD(0)
    ok = winapi.VirtualProtectEx(
        handle,
        ctypes.c_void_p(address),
        size,
        new_protect,
        ctypes.byref(old),
    )
    return bool(ok), old.value


def user_address_limit() -> int:
    """Top of user-mode address space (stop VirtualQueryEx here)."""
    info = winapi.SYSTEM_INFO()
    winapi.GetNativeSystemInfo(ctypes.byref(info))
    limit = info.lpMaximumApplicationAddress
    return limit if isinstance(limit, int) else ctypes.cast(limit, ctypes.c_void_p).value or 0


def enum_regions(
    handle: int,
    include_mapped_image: bool = False,
    on_log: Optional[Callable[[str], None]] = None,
) -> List[RegionInfo]:
    """Enumerate scannable regions.

    Skips MEM_RESERVE/MEM_FREE state, PAGE_NOACCESS and PAGE_GUARD protection.
    Default policy scans MEM_PRIVATE (heaps) only; ``include_mapped_image``
    adds MEM_MAPPED and MEM_IMAGE (overwriting constants/code there can crash
    the target).
    """
    log = on_log or (lambda _m: None)
    regions: List[RegionInfo] = []
    skipped_guard = 0
    skipped_noaccess = 0
    skipped_type = 0
    addr = 0
    limit = user_address_limit()
    while addr < limit:
        mbi = virtual_query(handle, addr)
        if mbi is None:
            break
        base = mbi.BaseAddress if isinstance(mbi.BaseAddress, int) else 0
        size = int(mbi.RegionSize)
        next_addr = base + size
        if size <= 0 or next_addr <= addr:
            break
        if mbi.State == winapi.MEM_COMMIT and is_readable(mbi.Protect):
            t = mbi.Type
            wanted = t == winapi.MEM_PRIVATE
            if include_mapped_image and t in (winapi.MEM_MAPPED, winapi.MEM_IMAGE):
                wanted = True
            if wanted:
                regions.append(RegionInfo(base, size, mbi.State, mbi.Protect, t))
            else:
                skipped_type += 1
        else:
            if mbi.Protect & winapi.PAGE_GUARD:
                skipped_guard += 1
            elif base_protect(mbi.Protect) == winapi.PAGE_NOACCESS:
                skipped_noaccess += 1
        addr = next_addr
    log(
        f"[regions] {len(regions)} scannable region(s); skipped "
        f"{skipped_type} region(s) by type policy (use the checkbox to include "
        f"MEM_MAPPED/MEM_IMAGE), {skipped_guard} PAGE_GUARD, {skipped_noaccess} "
        f"PAGE_NOACCESS, non-committed states excluded."
    )
    return regions


def scan_region(
    handle: int,
    region: RegionInfo,
    patterns: Sequence[Pattern],
    overlap: int,
    on_log: Optional[Callable[[str], None]] = None,
    cancel: Optional[object] = None,
) -> Tuple[List[Hit], bool]:
    """Chunked scan of one region.  Returns (hits, cancelled).

    Chunks overlap by ``overlap`` bytes so a pattern spanning a chunk
    boundary is fully visible in one window; matches are credited only to the
    chunk that owns their start offset.
    """
    log = on_log or (lambda _m: None)
    hits: List[Hit] = []
    pos = region.base
    while pos < region.end:
        if cancel is not None and cancel.is_set():
            return hits, True
        want = min(SCAN_CHUNK_SIZE + overlap, region.end - pos)
        data = read_bytes(handle, pos, want)
        if data is None:
            log(
                f"[scan] {region.describe()}: ReadProcessMemory failed at "
                f"0x{pos:X}: {winapi.win_error_message('ReadProcessMemory')} "
                "- skipping the rest of this region."
            )
            break
        if not data:
            break
        owned_end = pos + min(SCAN_CHUNK_SIZE, len(data))
        for m in find_matches(data, patterns):
            abs_start = pos + m.start
            if abs_start >= owned_end:
                continue  # credited to the next chunk
            hits.append(
                Hit(abs_start, m.end - m.start, m.keyword, m.encoding, region)
            )
        # Advance by the owned size; a full-length read keeps ``overlap`` bytes
        # in scope for the next chunk, a short read is the region's tail.
        advance = SCAN_CHUNK_SIZE if len(data) >= SCAN_CHUNK_SIZE else max(len(data), 1)
        pos += advance
    return hits, False


def scan_regions(
    handle: int,
    regions: Sequence[RegionInfo],
    patterns: Sequence[Pattern],
    on_log: Optional[Callable[[str], None]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
    cancel: Optional[object] = None,
) -> Tuple[List[Hit], bool]:
    """Scan every region; logs per-region hit counts.  Returns (hits, cancelled)."""
    log = on_log or (lambda _m: None)
    progress = on_progress or (lambda _d, _t: None)
    total = sum(r.size for r in regions)
    done = 0
    all_hits: List[Hit] = []
    overlap = max((p.max_size for p in patterns), default=1)
    for region in regions:
        if cancel is not None and cancel.is_set():
            return all_hits, True
        hits, cancelled = scan_region(handle, region, patterns, overlap, log, cancel)
        if hits:
            log(f"[scan] {region.describe()}: {len(hits)} hit(s)")
            all_hits.extend(hits)
        done += region.size
        progress(min(done, total), total)
        if cancelled:
            return all_hits, True
    return all_hits, False


def remote_string_span(
    handle: int, region: RegionInfo, hit: Hit
) -> Tuple[int, int]:
    """Absolute [start, end) of the printable run containing ``hit``.

    Re-reads doubling context windows (capped at MAX_STRING_PAD) when the run
    touches a read boundary and more of the region exists beyond it.  Falls
    back to the raw match span if the region cannot be read.
    """
    pad = INITIAL_CONTEXT
    while True:
        buf_lo = max(region.base, hit.address - pad)
        buf_hi = min(region.end, hit.address + hit.size + pad)
        data = read_bytes(handle, buf_lo, buf_hi - buf_lo)
        if not data:
            return hit.address, hit.address + hit.size
        buf_hi = buf_lo + len(data)
        rel_s = hit.address - buf_lo
        rel_e = rel_s + hit.size
        lo, hi = resolve_string_bounds(data, rel_s, rel_e, hit.encoding)
        clipped_lo = lo == 0 and buf_lo > region.base
        clipped_hi = hi == len(data) and buf_hi < region.end
        if (clipped_lo or clipped_hi) and pad < MAX_STRING_PAD:
            pad = min(pad * 2, MAX_STRING_PAD)
            continue
        return buf_lo + lo, buf_lo + hi


__all__ = [
    "SCAN_CHUNK_SIZE",
    "INITIAL_CONTEXT",
    "MAX_STRING_PAD",
    "RegionInfo",
    "Hit",
    "open_target_process",
    "process_alive",
    "virtual_query",
    "read_bytes",
    "write_bytes",
    "virtual_protect",
    "enum_regions",
    "scan_region",
    "scan_regions",
    "remote_string_span",
    "protect_name",
    "type_name",
    "base_protect",
    "is_readable",
    "is_writable",
    "is_executable",
]
