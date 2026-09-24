"""Single source of truth for the Windows (ctypes) API surface used by string-wiper.

Everything win32-related lives here: constants/flags, structure definitions,
function bindings and error-message mapping.  Other modules import these
symbols and never redefine them.  Functions come from kernel32, user32
(window enumeration/text) and advapi32 (tokens/privileges).

Structure notes (layout is asserted at import time on Windows):

* ``MEMORY_BASIC_INFORMATION`` uses native pointer-sized fields.  Under 64-bit
  Python this is exactly the documented x64 layout (48 bytes, matching
  ``MEMORY_BASIC_INFORMATION64``): BaseAddress(8) AllocationBase(8)
  AllocationProtect(4) +pad(4) RegionSize(8) State(4) Protect(4) Type(4)
  +pad(4).  Under 32-bit Python it collapses to the native 32-bit layout
  (28 bytes), which is correct for 32-bit-only use; the application refuses
  64-bit targets from 32-bit Python (see ``privileges.arch_compatibility``).
* ``PROCESSENTRY32W`` mirrors the wide toolhelp entry (``WCHAR szExeFile``
  with ``WCHAR`` = 2 bytes on Windows).

On non-Windows platforms the module still imports cleanly (constants and
structs are plain ctypes); calling any bound function raises ``OSError`` so
the pure-logic modules and their tests remain platform independent.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import (
    POINTER,
    Structure,
    c_int,
    c_int32,
    c_size_t,
    c_uint16,
    c_uint32,
    c_void_p,
    c_wchar,
)

# ---------------------------------------------------------------------------
# Platform gate
# ---------------------------------------------------------------------------

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Basic Windows types (defined once here; import from this module elsewhere)
# ---------------------------------------------------------------------------

BOOL = c_int
DWORD = c_uint32
WORD = c_uint16
LONG = c_int32
ULONG_PTR = c_size_t
SIZE_T = c_size_t
LPARAM = c_size_t
HANDLE = c_void_p
LPVOID = c_void_p
LPCVOID = c_void_p
LPDWORD = POINTER(DWORD)
UINT = ctypes.c_uint

# EnumWindows callback (stdcall on x86; identical to CFUNCTYPE on x64 - the
# supported target per README).  WINFUNCTYPE is Windows-only, hence the guard.
WNDENUMPROC = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)(BOOL, HANDLE, LPARAM)

MAX_PATH = 260

# ---------------------------------------------------------------------------
# Process access rights
# ---------------------------------------------------------------------------

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

STILL_ACTIVE = 259

# ---------------------------------------------------------------------------
# MessageBox (user32) flags - used by the startup preflight
# ---------------------------------------------------------------------------

MB_OK = 0x0000
MB_YESNO = 0x0004
MB_ICONERROR = 0x0010
MB_ICONWARNING = 0x0030
MB_DEFBUTTON2 = 0x0100
IDYES = 6
IDNO = 7

# ---------------------------------------------------------------------------
# Toolhelp
# ---------------------------------------------------------------------------

TH32CS_SNAPPROCESS = 0x00000002

# ---------------------------------------------------------------------------
# Memory constants (VirtualQueryEx state / type / protection)
# ---------------------------------------------------------------------------

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

# ---------------------------------------------------------------------------
# Token / privilege constants
# ---------------------------------------------------------------------------

TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020

SE_PRIVILEGE_ENABLED = 0x00000002

TokenElevation = 20  # TOKEN_INFORMATION_CLASS

ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
ERROR_PARTIAL_COPY = 299
ERROR_NOT_ALL_ASSIGNED = 1300
ERROR_MOD_NOT_FOUND = 126
ERROR_BAD_EXE_FORMAT = 193

# LoadLibraryExW flag: resolve the loaded DLL's own dependencies next to it
LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008

# ---------------------------------------------------------------------------
# Processor architecture constants (GetNativeSystemInfo)
# ---------------------------------------------------------------------------

PROCESSOR_ARCHITECTURE_INTEL = 0
PROCESSOR_ARCHITECTURE_IA64 = 6
PROCESSOR_ARCHITECTURE_AMD64 = 9
PROCESSOR_ARCHITECTURE_ARM64 = 12

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# ---------------------------------------------------------------------------
# Structures (each defined exactly once)
# ---------------------------------------------------------------------------


class MEMORY_BASIC_INFORMATION(Structure):
    """VirtualQueryEx region descriptor (native layout; 48 bytes on x64)."""

    _fields_ = [
        ("BaseAddress", LPVOID),
        ("AllocationBase", LPVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


class PROCESSENTRY32W(Structure):
    """CreateToolhelp32Snapshot / Process32FirstW wide entry."""

    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", c_wchar * MAX_PATH),
    ]


class SYSTEM_INFO(Structure):
    """GetNativeSystemInfo / GetSystemInfo (union flattened to the used fields)."""

    _fields_ = [
        ("wProcessorArchitecture", WORD),
        ("wReserved", WORD),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", ULONG_PTR),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
    ]


class LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]


class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


class TOKEN_ELEVATION(Structure):
    _fields_ = [
        ("TokenIsElevated", DWORD),
    ]


class OSVERSIONINFOW(Structure):
    """GetVersionExW input/output (276 bytes on Windows).

    The startup preflight compares what this reports (shim-influenceable)
    against the registry build number (shim-proof) to detect compatibility
    mode version lies.
    """

    _fields_ = [
        ("dwOSVersionInfoSize", DWORD),
        ("dwMajorVersion", DWORD),
        ("dwMinorVersion", DWORD),
        ("dwBuildNumber", DWORD),
        ("dwPlatformId", DWORD),
        ("szCSDVersion", c_wchar * 128),
    ]


# ---------------------------------------------------------------------------
# Function bindings
# ---------------------------------------------------------------------------

if IS_WINDOWS:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
else:  # pragma: no cover - exercised only off-Windows
    _kernel32 = None
    _user32 = None
    _advapi32 = None


def _unavailable(name: str):
    def _fn(*_args, **_kwargs):
        raise OSError(f"{name} is a Windows API and is unavailable on {sys.platform}")

    _fn.__name__ = name
    return _fn


def _bind(lib, name: str, restype, argtypes):
    if lib is None:
        return _unavailable(name)
    fn = getattr(lib, name)
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


OpenProcess = _bind(
    _kernel32,
    "OpenProcess",
    HANDLE,
    [DWORD, BOOL, DWORD],
)
CloseHandle = _bind(
    _kernel32,
    "CloseHandle",
    BOOL,
    [HANDLE],
)
GetCurrentProcess = _bind(
    _kernel32,
    "GetCurrentProcess",
    HANDLE,
    [],
)
VirtualQueryEx = _bind(
    _kernel32,
    "VirtualQueryEx",
    SIZE_T,
    [HANDLE, LPCVOID, LPVOID, SIZE_T],
)
ReadProcessMemory = _bind(
    _kernel32,
    "ReadProcessMemory",
    BOOL,
    [HANDLE, LPCVOID, LPVOID, SIZE_T, POINTER(SIZE_T)],
)
WriteProcessMemory = _bind(
    _kernel32,
    "WriteProcessMemory",
    BOOL,
    [HANDLE, LPVOID, LPCVOID, SIZE_T, POINTER(SIZE_T)],
)
VirtualProtectEx = _bind(
    _kernel32,
    "VirtualProtectEx",
    BOOL,
    [HANDLE, LPVOID, SIZE_T, DWORD, LPDWORD],
)
GetExitCodeProcess = _bind(
    _kernel32,
    "GetExitCodeProcess",
    BOOL,
    [HANDLE, LPDWORD],
)
CreateToolhelp32Snapshot = _bind(
    _kernel32,
    "CreateToolhelp32Snapshot",
    HANDLE,
    [DWORD, DWORD],
)
Process32FirstW = _bind(
    _kernel32,
    "Process32FirstW",
    BOOL,
    [HANDLE, POINTER(PROCESSENTRY32W)],
)
Process32NextW = _bind(
    _kernel32,
    "Process32NextW",
    BOOL,
    [HANDLE, POINTER(PROCESSENTRY32W)],
)
IsWow64Process = _bind(
    _kernel32,
    "IsWow64Process",
    BOOL,
    [HANDLE, POINTER(BOOL)],
)
GetNativeSystemInfo = _bind(
    _kernel32,
    "GetNativeSystemInfo",
    None,
    [POINTER(SYSTEM_INFO)],
)
QueryFullProcessImageNameW = _bind(
    _kernel32,
    "QueryFullProcessImageNameW",
    BOOL,
    [HANDLE, DWORD, ctypes.c_wchar_p, LPDWORD],
)
EnumWindows = _bind(
    _user32,
    "EnumWindows",
    BOOL,
    [WNDENUMPROC, LPARAM],
)
IsWindowVisible = _bind(
    _user32,
    "IsWindowVisible",
    BOOL,
    [HANDLE],
)
GetWindowTextLengthW = _bind(
    _user32,
    "GetWindowTextLengthW",
    c_int,
    [HANDLE],
)
GetWindowTextW = _bind(
    _user32,
    "GetWindowTextW",
    c_int,
    [HANDLE, LPVOID, c_int],
)
GetWindowThreadProcessId = _bind(
    _user32,
    "GetWindowThreadProcessId",
    DWORD,
    [HANDLE, LPDWORD],
)
GetVersionExW = _bind(
    _kernel32,
    "GetVersionExW",
    BOOL,
    [POINTER(OSVERSIONINFOW)],
)
MessageBoxW = _bind(
    _user32,
    "MessageBoxW",
    c_int,
    [HANDLE, ctypes.c_wchar_p, ctypes.c_wchar_p, UINT],
)
LoadLibraryExW = _bind(
    _kernel32,
    "LoadLibraryExW",
    HANDLE,
    [ctypes.c_wchar_p, HANDLE, DWORD],
)
FreeLibrary = _bind(
    _kernel32,
    "FreeLibrary",
    BOOL,
    [HANDLE],
)

OpenProcessToken = _bind(
    _advapi32,
    "OpenProcessToken",
    BOOL,
    [HANDLE, DWORD, POINTER(HANDLE)],
)
LookupPrivilegeValueW = _bind(
    _advapi32,
    "LookupPrivilegeValueW",
    BOOL,
    [ctypes.c_wchar_p, ctypes.c_wchar_p, POINTER(LUID)],
)
AdjustTokenPrivileges = _bind(
    _advapi32,
    "AdjustTokenPrivileges",
    BOOL,
    [HANDLE, BOOL, POINTER(TOKEN_PRIVILEGES), DWORD, POINTER(TOKEN_PRIVILEGES), LPDWORD],
)
GetTokenInformation = _bind(
    _advapi32,
    "GetTokenInformation",
    BOOL,
    [HANDLE, c_int, LPVOID, DWORD, LPDWORD],
)


# ---------------------------------------------------------------------------
# Error helpers
# ---------------------------------------------------------------------------


def get_last_error() -> int:
    """Return the calling thread's last Win32 error code (0 off-Windows)."""
    if IS_WINDOWS:
        return ctypes.get_last_error()
    return 0


def set_last_error(code: int) -> None:
    """Set the calling thread's last Win32 error code (no-op off-Windows)."""
    if IS_WINDOWS:
        ctypes.set_last_error(code)


def win_error_message(context: str) -> str:
    """Map the last ctypes/Win32 failure to a human-readable message."""
    if not IS_WINDOWS:
        return f"{context}: not running on Windows"
    code = get_last_error()
    if code == ERROR_ACCESS_DENIED:
        detail = (
            "Access denied. Run this application from an elevated (Administrator) "
            "terminal; protected processes may still refuse access."
        )
    elif code == ERROR_PARTIAL_COPY:
        detail = (
            "Only part of a region could be copied (the target may have exited, "
            "or the region became invalid)."
        )
    elif code == ERROR_NOT_ALL_ASSIGNED:
        detail = "The privilege is not held by the token (run elevated as Administrator)."
    else:
        detail = str(ctypes.WinError(code))
    return f"{context} failed: {detail} [Win32 error {code}]"


if IS_WINDOWS:  # layout sanity checks, run once at import
    _ptr = ctypes.sizeof(c_void_p)
    _mbi = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
    _expected_mbi = 48 if _ptr == 8 else 28
    if _mbi != _expected_mbi:
        raise RuntimeError(
            f"MEMORY_BASIC_INFORMATION layout is {_mbi} bytes, expected {_expected_mbi} "
            f"for a {_ptr * 8}-bit interpreter"
        )
    _ovi = ctypes.sizeof(OSVERSIONINFOW)
    if _ovi != 276:
        raise RuntimeError(
            f"OSVERSIONINFOW layout is {_ovi} bytes, expected 276 on Windows"
        )
