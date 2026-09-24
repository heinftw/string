"""Startup preflight: detect compatibility-mode version lies before Qt loads.

A Windows "compatibility mode" shim (set by hand or by the Program
Compatibility Assistant) makes this process *look* like it runs on a
pre-Windows 7 system to every ``GetVersionExW`` caller.  Native libraries
that require Windows 7+ then abort with a cryptic dialog::

    Fatal Error
    Windows 7 is the minimum supported platform

even on a perfectly modern PC.  The registry's ``CurrentBuildNumber`` is not
virtualized by those shims, so comparing it against ``GetVersionExW``
detects the lie and we can show the actual fix instead of letting a native
library abort mid-import.

``classify_versions`` is pure logic (unit-tested on any platform); the rest
is thin I/O over ``winreg`` and :mod:`core.winapi`.
"""

from __future__ import annotations

import ctypes
import os
import sys
from typing import Optional, Tuple

from core import winapi

# Windows 10 RTM; PySide6 / Qt 6 require Windows 10 or later.
WIN10_MIN_BUILD = 10240

_VERSION_NAMES = {
    (5, 0): "Windows 2000",
    (5, 1): "Windows XP",
    (5, 2): "Windows XP x64 / Server 2003",
    (6, 0): "Windows Vista",
    (6, 1): "Windows 7",
    (6, 2): "Windows 8",
    (6, 3): "Windows 8.1",
    (10, 0): "Windows 10 / 11",
}


def _version_name(major: int, minor: int) -> str:
    return _VERSION_NAMES.get((major, minor), f"Windows {major}.{minor}")


def classify_versions(
    reported: Optional[Tuple[int, int]],
    true_build: Optional[int],
) -> Optional[Tuple[str, bool]]:
    """Decide whether the OS version picture is healthy.

    ``reported`` is what ``GetVersionExW`` returns (shim-influenceable);
    ``true_build`` is the registry's ``CurrentBuildNumber`` (shim-proof).

    Returns ``None`` when fine, otherwise ``(message, allow_continue)``.
    """
    if true_build is not None and true_build < WIN10_MIN_BUILD:
        name = _version_name(*(reported or (0, 0)))
        return (
            "This tool requires Windows 10 or later (PySide6 / Qt 6).\n\n"
            f"This PC reports build {true_build}"
            + (f" ({name})" if reported else "")
            + ".\n\nUpgrade Windows to run string-wiper.",
            False,
        )

    if true_build is None:
        # Ground truth unavailable; only warn when the report is suspicious.
        if reported is not None and reported < (6, 1):
            return (
                "Windows is reporting "
                f"{_version_name(*reported)}, which is below the Windows 7 "
                "minimum that native libraries require. If a 'Fatal Error: "
                "Windows 7 is the minimum supported platform' dialog appears, "
                "a compatibility-mode shim is set on python.exe / pythonw.exe "
                "(Properties > Compatibility) - turn it off and run "
                "'python main.py' from a terminal instead of double-clicking.",
                True,
            )
        return None

    # Real OS is Windows 10/11.  A report below 10.0 means a shim is lying.
    if reported is not None and reported < (10, 0):
        name = _version_name(*reported)
        return (
            "COMPATIBILITY-MODE VERSION LIE DETECTED\n\n"
            f"This PC is a modern Windows (build {true_build}), but native "
            f"libraries in this process are being told it is {name}.\n\n"
            "With that lie active, a native library aborts with:\n\n"
            '    "Fatal Error: Windows 7 is the minimum supported platform"\n\n'
            "HOW TO FIX\n"
            "1. Press Win+R and run:  where python\n"
            "2. Right-click python.exe > Properties > Compatibility tab\n"
            "3. UNcheck \"Run this program in compatibility mode for:\"\n"
            "   (do the same for pythonw.exe in the same folder)\n"
            "4. Run again from a terminal:  python main.py",
            True,
        )

    return None


def read_reported_version() -> Optional[Tuple[int, int]]:
    """``GetVersionExW`` result - exactly what shimmed native code sees."""
    info = winapi.OSVERSIONINFOW()
    info.dwOSVersionInfoSize = ctypes.sizeof(winapi.OSVERSIONINFOW)
    try:
        ok = winapi.GetVersionExW(ctypes.byref(info))
    except OSError:
        return None
    if not ok:
        return None
    return (info.dwMajorVersion, info.dwMinorVersion)


def read_true_build() -> Optional[int]:
    """Registry ``CurrentBuildNumber`` - not virtualized by compat shims."""
    try:
        import winreg
    except ImportError:
        return None
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        )
    except OSError:
        return None
    try:
        with key:
            try:
                value, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
                return int(value)
            except (OSError, TypeError, ValueError):
                return None
    except OSError:
        return None


# ---- Qt platform-plugin preflight (runs after `import PySide6`, before
# ---- QApplication): "Could not load the Qt platform plugin \"windows\" ...
# ---- even though it was found" means qwindows.dll exists but its own
# ---- dependencies failed to load - usually the VC++ 2015-2022 runtime.

_QT_CRT_DEPS = (
    "msvcp140.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140_atomic_wait.dll",
    "msvcp140_codecvt_ids.dll",
)

_VCREDIST_FIX = (
    "FIX - install the missing C/C++ runtime:\n"
    "1. Download \"Microsoft Visual C++ Redistributable 2015-2022\" (x64)\n"
    "   from microsoft.com (search: latest supported Visual C++ downloads).\n"
    "2. Install it, then run the app again."
)


def describe_plugin_failure(
    error_code: int,
    missing: Tuple[str, ...],
    plugin_name: str,
) -> str:
    """Pure: map a plugin load failure to an actionable explanation."""
    lines = [
        f"The Qt platform plugin '{plugin_name}' exists but could not be loaded.",
        "",
    ]
    if missing:
        lines += [
            "These runtime files are missing on this PC:",
            "    " + ", ".join(missing),
            "",
            _VCREDIST_FIX,
        ]
    elif error_code == winapi.ERROR_MOD_NOT_FOUND:
        lines += [
            "Windows error 126 (module not found): the plugin or one of its "
            "dependencies is missing. This is usually the C/C++ runtime.",
            "",
            _VCREDIST_FIX,
        ]
    elif error_code == winapi.ERROR_BAD_EXE_FORMAT:
        lines += [
            "Windows error 193 (not a valid Win32 application): 32/64-bit "
            "mismatch. Install 64-bit Python 3.10+ and PySide6 into it.",
        ]
    elif error_code == winapi.ERROR_ACCESS_DENIED:
        lines += [
            "Windows error 5 (access denied): antivirus or Controlled Folder "
            "Access is blocking the plugin. Allow python.exe, or move this "
            "folder out of Downloads into Documents and try again.",
        ]
    else:
        try:
            detail = str(ctypes.WinError(error_code))  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            detail = f"error {error_code}"
        lines += [f"Windows reported: {detail}", "", _VCREDIST_FIX]
    lines += [
        "",
        "Also worth trying:",
        "    python -m pip install --force-reinstall PySide6",
    ]
    return "\n".join(lines)


def probe_missing_dlls(names: Tuple[str, ...]) -> Tuple[str, ...]:
    """Return which of ``names`` cannot be LoadLibrary'd right now."""
    missing = []
    for name in names:
        handle = winapi.LoadLibraryExW(name, None, 0)
        if handle:
            winapi.FreeLibrary(handle)
        else:
            winapi.set_last_error(0)  # keep probing; the name is what matters
            missing.append(name)
    return tuple(missing)


def find_qt_platform_plugin() -> Optional[str]:
    """Locate ``platforms/qwindows.dll`` inside the installed PySide6 tree."""
    try:
        import PySide6
    except ImportError:
        return None
    root = os.path.dirname(PySide6.__file__)
    for rel in (
        ("plugins", "platforms", "qwindows.dll"),
        ("Qt", "plugins", "platforms", "qwindows.dll"),
        ("Qt6", "plugins", "platforms", "qwindows.dll"),
    ):
        candidate = os.path.join(root, *rel)
        if os.path.isfile(candidate):
            return candidate
    for dirpath, _dirnames, filenames in os.walk(root):
        if "qwindows.dll" in filenames and dirpath.endswith("platforms"):
            return os.path.join(dirpath, "qwindows.dll")
    return None


def check_qt_platform() -> bool:
    """Probe qwindows.dll before QApplication(); True = continue launching."""
    if not winapi.IS_WINDOWS:
        return True
    plugin = find_qt_platform_plugin()
    if plugin is None:
        return True  # let Qt report its own error
    handle = winapi.LoadLibraryExW(plugin, None, winapi.LOAD_WITH_ALTERED_SEARCH_PATH)
    if handle:
        winapi.FreeLibrary(handle)
        return True
    code = winapi.get_last_error()
    missing = probe_missing_dlls(_QT_CRT_DEPS)
    message = describe_plugin_failure(code, missing, os.path.basename(plugin))
    print(f"[preflight] {message}", file=sys.stderr)
    text = message + "\n\nClick Yes to try launching anyway, No to exit."
    flags = winapi.MB_YESNO | winapi.MB_ICONERROR | winapi.MB_DEFBUTTON2
    try:
        choice = winapi.MessageBoxW(None, text, "string-wiper - startup check", flags)
    except OSError:
        return False
    return choice == winapi.IDYES


def run_preflight() -> bool:
    """Run the startup check; True = continue launching, False = exit."""
    result = classify_versions(read_reported_version(), read_true_build())
    if result is None:
        return True
    message, allow_continue = result
    print(f"[preflight] {message}", file=sys.stderr)
    caption = "string-wiper - startup check"
    if allow_continue:
        text = message + "\n\nClick Yes to try launching anyway, No to exit."
        flags = winapi.MB_YESNO | winapi.MB_ICONWARNING | winapi.MB_DEFBUTTON2
    else:
        text = message
        flags = winapi.MB_OK | winapi.MB_ICONERROR
    try:
        choice = winapi.MessageBoxW(None, text, caption, flags)
    except OSError:
        return allow_continue
    if not allow_continue:
        return False
    return choice == winapi.IDYES
