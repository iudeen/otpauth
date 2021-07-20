__version__ = '1.8.0'

import contextlib
import ctypes
import os
import platform
import subprocess
import time

from ctypes import c_size_t, sizeof, c_wchar_p, get_errno, c_wchar

# `import PyQt4` sys.exit()s if DISPLAY is not in the environment.
# Thus, we need to detect the presence of $DISPLAY manually
# and not load PyQt4 if it is absent.

EXCEPT_MSG = """
    Pyperclip could not find a copy/paste mechanism for your system.
    For more information, please visit https://pyperclip.readthedocs.io/en/latest/index.html#not-implemented-error """

STR_OR_UNICODE = str  # For paste(): Python 3 uses str, Python 2 uses unicode.

ENCODING = 'utf-8'

try:
    from shutil import which as _executable_exists
except ImportError:
    # The "which" unix command finds where a command is.
    if platform.system() == 'Windows':
        WHICH_CMD = 'where'
    else:
        WHICH_CMD = 'which'


    def _executable_exists(name):
        return subprocess.call([WHICH_CMD, name],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


# Exceptions
class PyperclipException(RuntimeError):
    pass


class PyperclipWindowsException(PyperclipException):
    def __init__(self, message):
        message += " (%s)" % ctypes.WinError()
        super(PyperclipWindowsException, self).__init__(message)


class PyperclipTimeoutException(PyperclipException):
    pass


def __stringify_text__(text):
    accepted_types = (str, int, float, bool)
    if not isinstance(text, accepted_types):
        raise PyperclipException(
            'only str, int, float, and bool values can be '
            'copied to the clipboard, not %s' % text.__class__.__name__)
    return STR_OR_UNICODE(text)


def init_no_clipboard():
    class ClipboardUnavailable(object):

        def __call__(self, *args, **kwargs):
            raise PyperclipException(EXCEPT_MSG)

        def __bool__(self):
            return False

    return ClipboardUnavailable(), ClipboardUnavailable()


# Windows-related clipboard functions:
class CheckedCall(object):
    def __init__(self, f):
        super(CheckedCall, self).__setattr__("f", f)

    def __call__(self, *args):
        ret = self.f(*args)
        if not ret and get_errno():
            raise PyperclipWindowsException("Error calling " + self.f.__name__)
        return ret

    def __setattr__(self, key, value):
        setattr(self.f, key, value)


def init_windows_clipboard():
    global HGLOBAL, LPVOID, DWORD, LPCSTR, INT, HWND, HINSTANCE, HMENU, BOOL, UINT, HANDLE
    from ctypes.wintypes import (HGLOBAL, LPVOID, DWORD, LPCSTR, INT, HWND,
                                 HINSTANCE, HMENU, BOOL, UINT, HANDLE)

    windll = ctypes.windll
    msvcrt = ctypes.CDLL('msvcrt')

    safe_create_window_ex_a = CheckedCall(windll.user32.CreateWindowExA)
    safe_create_window_ex_a.argtypes = [DWORD, LPCSTR, LPCSTR, DWORD, INT, INT,
                                        INT, INT, HWND, HMENU, HINSTANCE, LPVOID]
    safe_create_window_ex_a.restype = HWND

    safe_destroy_window = CheckedCall(windll.user32.DestroyWindow)
    safe_destroy_window.argtypes = [HWND]
    safe_destroy_window.restype = BOOL

    open_clipboard = windll.user32.OpenClipboard
    open_clipboard.argtypes = [HWND]
    open_clipboard.restype = BOOL

    safe_close_clipboard = CheckedCall(windll.user32.CloseClipboard)
    safe_close_clipboard.argtypes = []
    safe_close_clipboard.restype = BOOL

    safe_empty_clipboard = CheckedCall(windll.user32.EmptyClipboard)
    safe_empty_clipboard.argtypes = []
    safe_empty_clipboard.restype = BOOL

    safe_get_clipboard_data = CheckedCall(windll.user32.GetClipboardData)
    safe_get_clipboard_data.argtypes = [UINT]
    safe_get_clipboard_data.restype = HANDLE

    safe_set_clipboard_data = CheckedCall(windll.user32.SetClipboardData)
    safe_set_clipboard_data.argtypes = [UINT, HANDLE]
    safe_set_clipboard_data.restype = HANDLE

    safe_global_alloc = CheckedCall(windll.kernel32.GlobalAlloc)
    safe_global_alloc.argtypes = [UINT, c_size_t]
    safe_global_alloc.restype = HGLOBAL

    safe_global_lock = CheckedCall(windll.kernel32.GlobalLock)
    safe_global_lock.argtypes = [HGLOBAL]
    safe_global_lock.restype = LPVOID

    safe_global_unlock = CheckedCall(windll.kernel32.GlobalUnlock)
    safe_global_unlock.argtypes = [HGLOBAL]
    safe_global_unlock.restype = BOOL

    wcslen = CheckedCall(msvcrt.wcslen)
    wcslen.argtypes = [c_wchar_p]
    wcslen.restype = UINT

    gmem_moveable = 0x0002
    cf_unicodetext = 13

    @contextlib.contextmanager
    def window():
        """
        Context that provides a valid Windows hwnd.
        """
        # we really just need the hwnd, so setting "STATIC"
        # as predefined lpClass is just fine.
        hwnd = safe_create_window_ex_a(0, b"STATIC", None, 0, 0, 0, 0, 0,
                                       None, None, None, None)
        try:
            yield hwnd
        finally:
            safe_destroy_window(hwnd)

    @contextlib.contextmanager
    def clipboard(hwnd):
        """
        Context manager that opens the clipboard and prevents
        other applications from modifying the clipboard content.
        """
        # We may not get the clipboard handle immediately because
        # some other application is accessing it (?)
        # We try for at least 500ms to get the clipboard.
        t = time.time() + 0.5
        success = False
        while time.time() < t:
            success = open_clipboard(hwnd)
            if success:
                break
            time.sleep(0.01)
        if not success:
            raise PyperclipWindowsException("Error calling OpenClipboard")

        try:
            yield
        finally:
            safe_close_clipboard()

    def copy_windows(text):
        # This function is heavily based on
        # http://msdn.com/ms649016#_win32_Copying_Information_to_the_Clipboard

        text = __stringify_text__(text)  # Converts non-str values to str.

        with window() as hwnd:
            # http://msdn.com/ms649048
            # If an application calls OpenClipboard with hwnd set to NULL,
            # EmptyClipboard sets the clipboard owner to NULL;
            # this causes SetClipboardData to fail.
            # => We need a valid hwnd to copy something.
            with clipboard(hwnd):
                safe_empty_clipboard()

                if text:
                    # http://msdn.com/ms649051
                    # If the hMem parameter identifies a memory object,
                    # the object must have been allocated using the
                    # function with the GMEM_MOVEABLE flag.
                    count = wcslen(text) + 1
                    handle = safe_global_alloc(gmem_moveable,
                                               count * sizeof(c_wchar))
                    locked_handle = safe_global_lock(handle)

                    ctypes.memmove(c_wchar_p(locked_handle), c_wchar_p(text), count * sizeof(c_wchar))

                    safe_global_unlock(handle)
                    safe_set_clipboard_data(cf_unicodetext, handle)

    def paste_windows():
        with clipboard(None):
            handle = safe_get_clipboard_data(cf_unicodetext)
            if not handle:
                # GetClipboardData may return NULL with errno == NO_ERROR
                # if the clipboard is empty.
                # (Also, it may return a handle to an empty buffer,
                # but technically that's not empty)
                return ""
            return c_wchar_p(handle).value

    return copy_windows, paste_windows


def init_wsl_clipboard():
    def copy_wsl(text):
        text = __stringify_text__(text)  # Converts non-str values to str.
        p = subprocess.Popen(['clip.exe'],
                             stdin=subprocess.PIPE, close_fds=True)
        p.communicate(input=text.encode(ENCODING))

    def paste_wsl():
        p = subprocess.Popen(['powershell.exe', '-command', 'Get-Clipboard'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             close_fds=True)
        stdout, stderr = p.communicate()
        # WSL appends "\r\n" to the contents.
        return stdout[:-2].decode(ENCODING)

    return copy_wsl, paste_wsl


# Automatic detection of clipboard mechanisms and importing is done in determine_clipboard():
def determine_clipboard():
    """
    Determine the OS/platform and set the copy() and paste() functions
    accordingly.
    """
    # Setup for the WINDOWS platform:
    if os.name == 'nt' or platform.system() == 'Windows':
        return init_windows_clipboard()


def set_clipboard(clipboard):
    """
    Explicitly sets the clipboard mechanism. The "clipboard mechanism" is how
    the copy() and paste() functions interact with the operating system to
    implement the copy/paste feature. The clipboard parameter must be one of:
        - windows (default on Windows)
        - no (this is what is set when no clipboard mechanism can be found)
    """
    global copy, paste

    clipboard_types = {
        "windows": init_windows_clipboard,
        "no": init_no_clipboard,
    }

    if clipboard not in clipboard_types:
        raise ValueError('Argument must be one of %s' % (', '.join([repr(_) for _ in clipboard_types.keys()])))

    # Sets pyperclip's copy() and paste() functions:
    copy, paste = clipboard_types[clipboard]()


def lazy_load_stub_copy(text):
    """
    A stub function for copy(), which will load the real copy() function when
    called so that the real copy() function is used for later calls.

    This allows users to import pyperclip without having determine_clipboard()
    automatically run, which will automatically select a clipboard mechanism.
    This could be a problem if it selects, say, the memory-heavy PyQt4 module
    but the user was just going to immediately call set_clipboard() to use a
    different clipboard mechanism.

    The lazy loading this stub function implements gives the user a chance to
    call set_clipboard() to pick another clipboard mechanism. Or, if the user
    simply calls copy() or paste() without calling set_clipboard() first,
    will fall back on whatever clipboard mechanism that determine_clipboard()
    automatically chooses.
    """
    global copy, paste
    copy, paste = determine_clipboard()
    return copy(text)


def lazy_load_stub_paste():
    """
    A stub function for paste(), which will load the real paste() function when
    called so that the real paste() function is used for later calls.

    This allows users to import pyperclip without having determine_clipboard()
    automatically run, which will automatically select a clipboard mechanism.
    This could be a problem if it selects, say, the memory-heavy PyQt4 module
    but the user was just going to immediately call set_clipboard() to use a
    different clipboard mechanism.

    The lazy loading this stub function implements gives the user a chance to
    call set_clipboard() to pick another clipboard mechanism. Or, if the user
    simply calls copy() or paste() without calling set_clipboard() first,
    will fall back on whatever clipboard mechanism that determine_clipboard()
    automatically chooses.
    """
    global copy, paste
    copy, paste = determine_clipboard()
    return paste()


def is_available():
    return copy != lazy_load_stub_copy and paste != lazy_load_stub_paste


# Initially, copy() and paste() are set to lazy loading wrappers which will
# set `copy` and `paste` to real functions the first time they're used, unless
# set_clipboard() or determine_clipboard() is called first.
copy, paste = lazy_load_stub_copy, lazy_load_stub_paste


def wait_for_paste(timeout=None):
    """This function call blocks until a non-empty text string exists on the
    clipboard. It returns this text.

    This function raises PyperclipTimeoutException if timeout was set to
    a number of seconds that has elapsed without non-empty text being put on
    the clipboard."""
    start_time = time.time()
    while True:
        clipboard_text = paste()
        if clipboard_text != '':
            return clipboard_text
        time.sleep(0.01)

        if timeout is not None and time.time() > start_time + timeout:
            raise PyperclipTimeoutException('waitForPaste() timed out after ' + str(timeout) + ' seconds.')


def wait_for_new_paste(timeout=None):
    """This function call blocks until a new text string exists on the
    clipboard that is different from the text that was there when the function
    was first called. It returns this text.

    This function raises PyperclipTimeoutException if timeout was set to
    a number of seconds that has elapsed without non-empty text being put on
    the clipboard."""
    start_time = time.time()
    original_text = paste()
    while True:
        current_text = paste()
        if current_text != original_text:
            return current_text
        time.sleep(0.01)

        if timeout is not None and time.time() > start_time + timeout:
            raise PyperclipTimeoutException('waitForNewPaste() timed out after ' + str(timeout) + ' seconds.')
