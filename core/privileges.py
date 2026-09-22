"""Privilege acquisition and architecture detection.

* SeDebugPrivilege enablement via AdjustTokenPrivileges.
* Elevation detection (TokenElevation).
* Python / OS architecture detection and target-compatibility checks.
"""

from __future__ import annotations

import ctypes
from typing import Optional, Tuple

from . import winapi

SE_DEBUG_NAME = "SeDebugPrivilege"


def python_bits() -> int:
    """Bitness of this Python interpreter (32 or 64)."""
    return ctypes.sizeof(ctypes.c_void_p) * 8


def python_is_64bit() -> bool:
    return python_bits() == 64


def native_arch() -> str:
    """Native OS architecture: 'x86', 'x64', 'ia64', 'arm64' or 'unknown(...)'."""
    info = winapi.SYSTEM_INFO()
    winapi.GetNativeSystemInfo(ctypes.byref(info))
    return {
        winapi.PROCESSOR_ARCHITECTURE_INTEL: "x86",
        winapi.PROCESSOR_ARCHITECTURE_AMD64: "x64",
        winapi.PROCESSOR_ARCHITECTURE_IA64: "ia64",
        winapi.PROCESSOR_ARCHITECTURE_ARM64: "arm64",
    }.get(info.wProcessorArchitecture, f"unknown({info.wProcessorArchitecture})")


def is_elevated() -> bool:
    """True when the current process token is elevated (full Administrator)."""
    token = winapi.HANDLE()
    if not winapi.OpenProcessToken(
        winapi.GetCurrentProcess(), winapi.TOKEN_QUERY, ctypes.byref(token)
    ):
        return False
    try:
        elevation = winapi.TOKEN_ELEVATION()
        returned = winapi.DWORD()
        ok = winapi.GetTokenInformation(
            token,
            winapi.TokenElevation,
            ctypes.byref(elevation),
            ctypes.sizeof(elevation),
            ctypes.byref(returned),
        )
        return bool(ok and elevation.TokenIsElevated)
    finally:
        winapi.CloseHandle(token)


def enable_debug_privilege() -> Tuple[bool, str]:
    """Enable SeDebugPrivilege for the current process.

    Returns (success, human-readable status).  Fails cleanly when not
    elevated: SeDebugPrivilege is only *assignable* to Administrator tokens.
    """
    token = winapi.HANDLE()
    if not winapi.OpenProcessToken(
        winapi.GetCurrentProcess(),
        winapi.TOKEN_ADJUST_PRIVILEGES | winapi.TOKEN_QUERY,
        ctypes.byref(token),
    ):
        return False, winapi.win_error_message("OpenProcessToken")
    try:
        luid = winapi.LUID()
        if not winapi.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            return False, winapi.win_error_message(f"LookupPrivilegeValueW({SE_DEBUG_NAME})")
        state = winapi.TOKEN_PRIVILEGES()
        state.PrivilegeCount = 1
        state.Privileges[0].Luid = luid
        state.Privileges[0].Attributes = winapi.SE_PRIVILEGE_ENABLED
        winapi.set_last_error(0)
        if not winapi.AdjustTokenPrivileges(
            token, False, ctypes.byref(state), ctypes.sizeof(state), None, None
        ):
            return False, winapi.win_error_message("AdjustTokenPrivileges")
        err = winapi.get_last_error()
        if err == winapi.ERROR_NOT_ALL_ASSIGNED:
            return (
                False,
                f"{SE_DEBUG_NAME} was not assigned (Win32 error "
                f"{winapi.ERROR_NOT_ALL_ASSIGNED}). Run elevated as Administrator "
                "to enable it; without it, protected processes cannot be opened.",
            )
        return True, f"{SE_DEBUG_NAME} enabled. OpenProcess on protected processes should now succeed."
    finally:
        winapi.CloseHandle(token)


def architecture_summary() -> str:
    """One-line description of interpreter/OS bitness for the UI log."""
    return f"Python {python_bits()}-bit on {native_arch()} OS"


def arch_compatibility(process_arch: str) -> Tuple[bool, Optional[str]]:
    """Check this interpreter against a target process architecture.

    Returns (compatible, note).  ``note`` is a warning string even on
    success, or None when there is nothing to say.
    """
    if process_arch == "unknown":
        return (
            True,
            "Target architecture could not be determined (limited query rights); "
            "a 32/64-bit mismatch may cause failures.",
        )
    if process_arch.startswith("unknown"):
        return (True, f"Target reports {process_arch}; proceeding anyway.")
    bits = python_bits()
    if bits == 32:
        if process_arch in ("x64", "arm64"):
            return (
                False,
                f"32-bit Python cannot read or write a 64-bit ({process_arch}) target. "
                "Install 64-bit Python 3.10+ and re-run this tool elevated.",
            )
        return (
            True,
            "32-bit Python with a 32-bit target works, but 64-bit Python is recommended.",
        )
    # 64-bit Python
    if process_arch == "x86":
        return (
            True,
            "64-bit Python writing a 32-bit (WOW64) target is supported; the target's "
            "address space is the 4 GB WOW64 space.",
        )
    return (True, None)
