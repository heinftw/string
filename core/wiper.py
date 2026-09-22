"""Scrub engine: protect -> in-place zero overwrite -> restore -> verify, in a
scan/wipe/rescan loop.

Every overwrite preserves the exact byte length (pure in-place nulling): no
free, resize or reallocation, so heap metadata and adjacent allocations stay
intact.  Read-only pages get a temporary VirtualProtectEx lift which is
restored immediately after the write; every write is verified by re-reading.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence

from . import scanner, winapi
from .matching import (
    PatternSet,
    build_patterns,
    merge_spans,
)

MAX_WIPE_PASSES = 5

LogFn = Callable[[str], None]
ProgressFn = Callable[[int, int], None]
PassFn = Callable[[int, int], None]


@dataclass
class ScrubSummary:
    """Aggregate result of a scrub run (all PIDs)."""

    pids: List[int] = field(default_factory=list)
    opened: List[int] = field(default_factory=list)
    open_failures: List[str] = field(default_factory=list)
    matches_found: int = 0  # raw hits in the first scan
    matches_remaining: int = 0  # hits in the final verification scan
    passes_run: int = 0
    matches_per_pass: List[int] = field(default_factory=list)
    spans_wiped: int = 0
    wipe_failures: List[str] = field(default_factory=list)
    regenerating_regions: List[str] = field(default_factory=list)
    process_died: List[int] = field(default_factory=list)
    cancelled: bool = False


def wipe_span(handle: int, address: int, length: int, on_log: Optional[LogFn] = None) -> bool:
    """Zero ``length`` bytes at ``address`` in place.  Returns True when the
    whole span was written AND verified.

    Protection dance per sub-span: lift (VirtualProtectEx) when the page is
    not writable, WriteProcessMemory zeros, verify by re-read, restore the
    original protection.  Any failure is logged and the sub-span is skipped
    safely so the rest of the span still gets wiped.
    """
    log = on_log or (lambda _m: None)
    pos = address
    end = address + length
    all_ok = True
    while pos < end:
        mbi = scanner.virtual_query(handle, pos)
        if mbi is None:
            log(
                f"[wipe] 0x{pos:X}: VirtualQueryEx failed: "
                f"{winapi.win_error_message('VirtualQueryEx')} - aborting this span."
            )
            return False
        region_end = (mbi.BaseAddress if isinstance(mbi.BaseAddress, int) else pos) + int(
            mbi.RegionSize
        )
        chunk_end = min(end, region_end) if region_end > pos else end
        size = chunk_end - pos
        if size <= 0:
            break
        span_txt = _hexspan(pos, chunk_end)
        protect = mbi.Protect
        lifted = False
        old_protect = protect
        if not scanner.is_writable(protect):
            new_protect = (
                winapi.PAGE_EXECUTE_READWRITE
                if scanner.is_executable(protect)
                else winapi.PAGE_READWRITE
            )
            ok, old_protect = scanner.virtual_protect(handle, pos, size, new_protect)
            if not ok:
                log(
                    f"[protect] {span_txt} ({size} byte(s)): VirtualProtectEx failed: "
                    f"{winapi.win_error_message('VirtualProtectEx')} - skipping this sub-span."
                )
                all_ok = False
                pos = chunk_end
                continue
            lifted = True
            log(
                f"[protect] {span_txt}: {scanner.protect_name(old_protect)} -> "
                f"{scanner.protect_name(new_protect)} (temporary)"
            )
        zeros = bytes(size)
        wrote = scanner.write_bytes(handle, pos, zeros)
        verified = False
        if wrote:
            back = scanner.read_bytes(handle, pos, size)
            verified = back == zeros
        if wrote and verified:
            log(f"[wipe] {span_txt}: {size} byte(s) overwritten and verified")
        else:
            if not wrote:
                reason = winapi.win_error_message("WriteProcessMemory")
            else:
                reason = "verification re-read mismatch (bytes are not all zero)"
            log(f"[wipe] {span_txt}: FAILED ({reason}) - skipped safely.")
            all_ok = False
        if lifted:
            ok, _ = scanner.virtual_protect(handle, pos, size, old_protect)
            if ok:
                log(
                    f"[protect] {span_txt}: protection restored to "
                    f"{scanner.protect_name(old_protect)}"
                )
            else:
                log(
                    f"[protect] {span_txt}: FAILED to restore "
                    f"{scanner.protect_name(old_protect)}: "
                    f"{winapi.win_error_message('VirtualProtectEx')} "
                    "(left at the temporary protection)."
                )
                all_ok = False
        pos = chunk_end
    return all_ok


def _hexspan(start: int, end: int) -> str:
    return f"0x{start:X}-0x{end:X}"


def _scrub_one_pid(
    handle: int,
    pid: int,
    pattern_set: PatternSet,
    include_mapped_image: bool,
    log: LogFn,
    progress: ProgressFn,
    on_pass: Optional[PassFn],
    cancel,
    summary: ScrubSummary,
) -> None:
    found_first_recorded = False

    for pass_no in range(1, MAX_WIPE_PASSES + 1):
        if cancel is not None and cancel.is_set():
            summary.cancelled = True
            return
        if not scanner.process_alive(handle):
            summary.process_died.append(pid)
            log(f"[error] PID {pid} exited mid-scrub - reporting partial results.")
            return

        log(f"[pass {pass_no}] PID {pid}: scanning...")
        regions = scanner.enum_regions(handle, include_mapped_image, log)
        hits, cancelled = scanner.scan_regions(handle, regions, pattern_set.patterns, log, progress, cancel)
        if cancelled:
            summary.cancelled = True
            log(f"[pass {pass_no}] PID {pid}: cancelled between regions.")
            return

        # Record immediately so partial/cancelled runs keep their counts.
        if not found_first_recorded:
            summary.matches_found += len(hits)
            found_first_recorded = True
        summary.matches_per_pass.append(len(hits))
        summary.passes_run = pass_no
        log(f"[pass {pass_no}] PID {pid}: {len(hits)} match(es) found.")
        if on_pass is not None:
            on_pass(pass_no, len(hits))

        if not hits:
            break

        spans: List[tuple] = []
        for hit in hits:
            lo, hi = scanner.remote_string_span(handle, hit.region, hit)
            if hi > lo:
                spans.append((lo, hi))
        merged = merge_spans(spans)
        log(f"[pass {pass_no}] PID {pid}: wiping {len(merged)} string span(s) (from {len(hits)} hit(s))...")
        for idx, (lo, hi) in enumerate(merged):
            if cancel is not None and cancel.is_set():
                summary.cancelled = True
                log(f"[pass {pass_no}] PID {pid}: cancelled before wipe {idx + 1}/{len(merged)}.")
                return
            if not scanner.process_alive(handle):
                summary.process_died.append(pid)
                log(f"[error] PID {pid} exited during wipe - reporting partial results.")
                return
            ok = wipe_span(handle, lo, hi - lo, log)
            if ok:
                summary.spans_wiped += 1
            else:
                summary.wipe_failures.append(f"PID {pid} {_hexspan(lo, hi)}")

    # Verification re-scan (no wiping).
    if cancel is not None and cancel.is_set():
        summary.cancelled = True
        return
    if not scanner.process_alive(handle):
        summary.process_died.append(pid)
        log(f"[verify] PID {pid} exited before verification - partial results only.")
        return
    log(f"[verify] PID {pid}: verification re-scan...")
    regions = scanner.enum_regions(handle, include_mapped_image, log)
    v_hits, cancelled = scanner.scan_regions(handle, regions, pattern_set.patterns, log, progress, cancel)
    if cancelled:
        summary.cancelled = True
        return
    summary.matches_remaining += len(v_hits)
    log(f"[verify] PID {pid}: {len(v_hits)} match(es) remaining.")
    if v_hits:
        regen: List[str] = []
        for hit in v_hits:
            desc = hit.region.describe()
            if desc not in regen:
                regen.append(desc)
        summary.regenerating_regions.extend(regen)
        log(
            f"[verify] PID {pid}: matches persist after {MAX_WIPE_PASSES} pass cap "
            f"(or were re-created by the running process). Regions still regenerating:"
        )
        for desc in regen:
            log(f"[verify]   {desc}")


def scrub_processes(
    pids: Sequence[int],
    keywords: Sequence[str],
    *,
    include_mapped_image: bool = False,
    include_utf8: bool = True,
    on_log: Optional[LogFn] = None,
    on_progress: Optional[ProgressFn] = None,
    on_pass: Optional[PassFn] = None,
    cancel: Optional[object] = None,
) -> ScrubSummary:
    """Scrub every PID in ``pids``: scan -> wipe -> rescan (max 5 passes) -> verify.

    Per-PID open failures are logged and skipped (other PIDs still run);
    per-span write failures never abort the run.  Cancellation (any object
    with ``is_set()``) is honored between regions, chunks and spans.
    """
    log = on_log or (lambda _m: None)
    progress = on_progress or (lambda _d, _t: None)
    summary = ScrubSummary(pids=list(pids))
    pattern_set = build_patterns(keywords, include_utf8=include_utf8)
    if not pattern_set.patterns:
        log("[error] no usable byte patterns for the given keywords - nothing to do.")
        return summary
    for note in pattern_set.notes:
        log(f"[note] {note}")
    if include_mapped_image:
        log(
            "[warning] MEM_MAPPED/MEM_IMAGE scanning enabled: overwriting mapped "
            "files, image constants or code can crash the target process."
        )

    for pid in pids:
        if cancel is not None and cancel.is_set():
            summary.cancelled = True
            break
        log(f"[open] PID {pid}...")
        try:
            handle = scanner.open_target_process(pid)
        except OSError as exc:
            summary.open_failures.append(f"PID {pid}: {exc}")
            log(f"[error] {exc}")
            continue
        summary.opened.append(pid)
        try:
            _scrub_one_pid(
                handle,
                pid,
                pattern_set,
                include_mapped_image,
                log,
                progress,
                on_pass,
                cancel,
                summary,
            )
        finally:
            winapi.CloseHandle(handle)
    return summary
