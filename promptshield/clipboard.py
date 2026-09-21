"""Clipboard helper to sanitise copied text before pasting into AI models."""

import sys
import time
from typing import Optional

from promptshield.detector import Detector
from promptshield.redactor import Redactor


def get_clipboard_text() -> Optional[str]:
    """Retrieve current text from Windows clipboard via tkinter or ctypes."""
    try:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        try:
            content = root.clipboard_get()
        except tk.TclError:
            content = None
        root.destroy()
        return content
    except Exception:
        pass

    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        CF_UNICODETEXT = 13
        if not user32.OpenClipboard(None):
            return None
        try:
            h_data = user32.GetClipboardData(CF_UNICODETEXT)
            if not h_data:
                return None
            p_data = kernel32.GlobalLock(h_data)
            if not p_data:
                return None
            try:
                text = ctypes.c_wchar_p(p_data).value
                return text
            finally:
                kernel32.GlobalUnlock(h_data)
        finally:
            user32.CloseClipboard()
    except Exception:
        return None


def set_clipboard_text(text: str) -> bool:
    """Put sanitised text back into the Windows clipboard."""
    try:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()  # Required on Windows to ensure clipboard stays after destroy
        root.destroy()
        return True
    except Exception:
        pass

    try:
        import ctypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        CF_UNICODETEXT = 13
        GMEM_MOVEABLE = 0x0002

        text_bytes = (text + "\0").encode("utf-16le")
        buffer_len = len(text_bytes)

        h_mem = kernel32.GlobalAlloc(GMEM_MOVEABLE, buffer_len)
        if not h_mem:
            return False

        p_mem = kernel32.GlobalLock(h_mem)
        if not p_mem:
            kernel32.GlobalFree(h_mem)
            return False

        ctypes.memmove(p_mem, text_bytes, buffer_len)
        kernel32.GlobalUnlock(h_mem)

        if not user32.OpenClipboard(None):
            kernel32.GlobalFree(h_mem)
            return False

        try:
            user32.EmptyClipboard()
            user32.SetClipboardData(CF_UNICODETEXT, h_mem)
            return True
        finally:
            user32.CloseClipboard()
    except Exception:
        return False


def sanitise_clipboard(session_id: Optional[str] = None) -> int:
    """Sanitise whatever is currently copied on the system clipboard."""
    text = get_clipboard_text()
    if not text:
        sys.stderr.write("Clipboard is empty or contains non-text data.\n")
        return 0

    redactor = Redactor()
    result = redactor.redact(text, session_id=session_id)

    if not result.findings:
        sys.stderr.write("Clipboard clean: No sensitive tokens detected.\n")
        return 0

    success = set_clipboard_text(result.sanitised_text)
    if success:
        sys.stderr.write(
            f"PromptShield: Sanitised {len(result.findings)} sensitive token(s) on your clipboard!\n"
        )
        return len(result.findings)
    else:
        sys.stderr.write("Failed to update clipboard.\n")
        return 0
