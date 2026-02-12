#!/usr/bin/env python3
"""
Purple Team Platform - Terminal UI Components
Beautiful, consistent terminal interface elements.
"""

import os
import sys
import shutil
import time
from datetime import datetime


# --- Non-interactive mode support (FIX 2) ---
_NON_INTERACTIVE = not sys.stdin.isatty()


def set_non_interactive(value=True):
    """Force non-interactive mode."""
    global _NON_INTERACTIVE
    _NON_INTERACTIVE = value


def is_non_interactive():
    """Check if running in non-interactive mode."""
    return _NON_INTERACTIVE


def safe_input(prompt='', default=''):
    """Input that returns default in non-interactive mode or on EOFError."""
    if _NON_INTERACTIVE:
        return default
    try:
        return input(prompt)
    except (EOFError, OSError):
        return default


# Colors
class Colors:
    # Basic
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'

    # Foreground
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright foreground
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Background
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

# Disable colors if not a TTY or NO_COLOR is set
if not sys.stdout.isatty() or os.environ.get('NO_COLOR'):
    for attr in dir(Colors):
        if not attr.startswith('_'):
            setattr(Colors, attr, '')

C = Colors  # Short alias


class TUI:
    """Terminal UI helper class."""

    def __init__(self):
        self.term_width = shutil.get_terminal_size().columns
        self.term_height = shutil.get_terminal_size().lines

    def refresh_size(self):
        """Refresh terminal dimensions."""
        self.term_width = shutil.get_terminal_size().columns
        self.term_height = shutil.get_terminal_size().lines

    # Box drawing characters
    BOX_TL = '╔'
    BOX_TR = '╗'
    BOX_BL = '╚'
    BOX_BR = '╝'
    BOX_H = '═'
    BOX_V = '║'
    BOX_LT = '╠'
    BOX_RT = '╣'
    BOX_TT = '╦'
    BOX_BT = '╩'
    BOX_X = '╬'

    # Light box
    LBOX_TL = '┌'
    LBOX_TR = '┐'
    LBOX_BL = '└'
    LBOX_BR = '┘'
    LBOX_H = '─'
    LBOX_V = '│'

    # Symbols
    CHECK = '✓'
    CROSS = '✗'
    ARROW = '→'
    BULLET = '•'
    STAR = '★'
    DIAMOND = '◆'
    CIRCLE = '●'
    CIRCLE_EMPTY = '○'
    SQUARE = '■'
    SQUARE_EMPTY = '□'
    TRIANGLE = '▶'
    WARNING = '⚠'
    INFO = 'ℹ'
    LOCK = '🔒'
    UNLOCK = '🔓'
    SHIELD = '🛡'

    # Progress bar characters
    BAR_FILLED = '█'
    BAR_EMPTY = '░'

    # Spinner frames
    SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    def clear(self):
        """Clear the terminal."""
        os.system('clear' if os.name != 'nt' else 'cls')

    def banner(self, title: str, subtitle: str = None, version: str = "5.0"):
        """Display the main banner."""
        self.refresh_size()
        width = min(65, self.term_width - 4)

        print(f"{C.MAGENTA}")
        print(self.BOX_TL + self.BOX_H * (width - 2) + self.BOX_TR)

        # Title line
        title_line = f"  {self.SHIELD}  {title}  {self.SHIELD}  "
        # Emoji chars (len <= 2) render wider than len() reports; ASCII substitutes don't
        emoji_offset = (4 - len(self.SHIELD)) * 2 if len(self.SHIELD) < 3 else 0
        padding = width - 2 - len(title_line) + emoji_offset
        print(self.BOX_V + title_line + ' ' * padding + self.BOX_V)

        # Version line
        ver_line = f"  Version {version} - Systems Thinking Security  "
        padding = width - 2 - len(ver_line)
        print(self.BOX_V + ver_line + ' ' * padding + self.BOX_V)

        if subtitle:
            print(self.BOX_LT + self.BOX_H * (width - 2) + self.BOX_RT)
            sub_padding = width - 2 - len(subtitle)
            left_pad = sub_padding // 2
            right_pad = sub_padding - left_pad
            print(self.BOX_V + ' ' * left_pad + subtitle + ' ' * right_pad + self.BOX_V)

        print(self.BOX_BL + self.BOX_H * (width - 2) + self.BOX_BR)
        print(f"{C.RESET}")

    def section(self, title: str, color=None):
        """Display a section header."""
        color = color or C.CYAN
        self.refresh_size()
        width = min(60, self.term_width - 4)

        print()
        print(f"{color}{self.LBOX_TL}{self.LBOX_H * 2} {title} {self.LBOX_H * (width - len(title) - 6)}{self.LBOX_TR}{C.RESET}")

    def section_end(self, color=None):
        """End a section."""
        color = color or C.CYAN
        self.refresh_size()
        width = min(60, self.term_width - 4)
        print(f"{color}{self.LBOX_BL}{self.LBOX_H * (width - 2)}{self.LBOX_BR}{C.RESET}")

    def menu(self, title: str, options: list, color=None) -> str:
        """Display a menu and get selection.

        Args:
            title: Menu title
            options: List of (key, label, description) tuples
            color: Optional color override

        Returns:
            Selected key
        """
        color = color or C.CYAN

        self.section(title, color)
        print()

        for key, label, desc in options:
            if key == '---':  # Separator
                print(f"  {C.DIM}{self.LBOX_H * 40}{C.RESET}")
            else:
                key_display = f"{C.BRIGHT_WHITE}[{key}]{C.RESET}"
                if desc:
                    print(f"  {key_display} {label}")
                    print(f"      {C.DIM}{desc}{C.RESET}")
                else:
                    print(f"  {key_display} {label}")

        print()
        self.section_end(color)

        choice = safe_input(f"\n{C.BRIGHT_WHITE}{self.TRIANGLE} Select option: {C.RESET}").strip()
        return choice

    def success(self, message: str):
        """Display success message."""
        print(f"{C.GREEN}{self.CHECK}{C.RESET} {message}")

    def error(self, message: str):
        """Display error message."""
        print(f"{C.RED}{self.CROSS}{C.RESET} {message}")

    def warning(self, message: str):
        """Display warning message."""
        print(f"{C.YELLOW}{self.WARNING}{C.RESET} {message}")

    def info(self, message: str):
        """Display info message."""
        print(f"{C.BLUE}{self.INFO}{C.RESET} {message}")

    def status(self, label: str, value: str, ok: bool = None):
        """Display a status line."""
        if ok is True:
            status = f"{C.GREEN}{self.CHECK}{C.RESET}"
        elif ok is False:
            status = f"{C.RED}{self.CROSS}{C.RESET}"
        else:
            status = f"{C.BLUE}{self.BULLET}{C.RESET}"

        print(f"  {status} {C.DIM}{label}:{C.RESET} {value}")

    def progress_bar(self, current: int, total: int, width: int = 40,
                     label: str = "", show_percent: bool = True):
        """Display a progress bar."""
        if total == 0:
            percent = 100
        else:
            percent = int((current / total) * 100)

        filled = int(width * current / total) if total > 0 else width
        bar = f"{C.GREEN}{self.BAR_FILLED * filled}{C.DIM}{self.BAR_EMPTY * (width - filled)}{C.RESET}"

        if show_percent:
            percent_str = f" {percent:3d}%"
        else:
            percent_str = ""

        if label:
            print(f"\r  {label}: [{bar}]{percent_str}", end='', flush=True)
        else:
            print(f"\r  [{bar}]{percent_str}", end='', flush=True)

    def spinner(self, message: str, duration: float = 0.1):
        """Display a single spinner frame."""
        frames = self.SPINNER_FRAMES
        frame_idx = int(time.time() * 10) % len(frames)
        print(f"\r  {C.CYAN}{frames[frame_idx]}{C.RESET} {message}", end='', flush=True)

    def table(self, headers: list, rows: list, color=None):
        """Display a formatted table."""
        color = color or C.CYAN

        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(str(cell)))

        # Header
        header_line = f" {self.BOX_V} ".join(
            f"{h:<{widths[i]}}" for i, h in enumerate(headers)
        )
        separator = f"{self.LBOX_H}{self.BOX_X}{self.LBOX_H}".join(
            self.LBOX_H * w for w in widths
        )

        print(f"{color}{self.LBOX_H * 2}{separator}{self.LBOX_H * 2}{C.RESET}")
        print(f"{color}{self.BOX_V}{C.RESET} {C.BOLD}{header_line}{C.RESET} {color}{self.BOX_V}{C.RESET}")
        print(f"{color}{self.LBOX_H * 2}{separator}{self.LBOX_H * 2}{C.RESET}")

        # Rows
        for row in rows:
            row_line = f" {self.BOX_V} ".join(
                f"{str(cell):<{widths[i]}}" for i, cell in enumerate(row)
            )
            print(f"{color}{self.BOX_V}{C.RESET} {row_line} {color}{self.BOX_V}{C.RESET}")

        print(f"{color}{self.LBOX_H * 2}{separator}{self.LBOX_H * 2}{C.RESET}")

    def confirm(self, message: str, default: bool = False) -> bool:
        """Ask for confirmation."""
        suffix = "[Y/n]" if default else "[y/N]"
        response = safe_input(f"{C.YELLOW}{self.WARNING}{C.RESET} {message} {suffix}: ").strip().lower()

        if not response:
            return default
        return response in ('y', 'yes')

    def input(self, prompt: str, default: str = None) -> str:
        """Get user input with optional default."""
        if default:
            display = f"{prompt} [{default}]: "
        else:
            display = f"{prompt}: "

        response = safe_input(f"{C.BRIGHT_WHITE}{self.TRIANGLE}{C.RESET} {display}").strip()
        return response or default or ""

    def countdown(self, seconds: int, message: str = "Starting in"):
        """Display a countdown."""
        for i in range(seconds, 0, -1):
            print(f"\r  {C.YELLOW}{message} {i}...{C.RESET}", end='', flush=True)
            time.sleep(1)
        print(f"\r  {C.GREEN}{message.replace('in', 'now!')}    {C.RESET}")

    def divider(self, char: str = None):
        """Print a divider line."""
        char = char or self.LBOX_H
        self.refresh_size()
        width = min(60, self.term_width - 4)
        print(f"{C.DIM}{char * width}{C.RESET}")

    def keyvalue(self, items: dict, color=None):
        """Display key-value pairs."""
        color = color or C.CYAN
        max_key = max(len(k) for k in items.keys())

        for key, value in items.items():
            print(f"  {color}{key:>{max_key}}{C.RESET}: {value}")

    def timestamp(self) -> str:
        """Get formatted timestamp."""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Singleton instance
tui = TUI()


# --- Unicode/ASCII fallback detection (FIX 1) ---
def _can_encode_unicode():
    """Check if stdout can encode Unicode box-drawing and symbol characters."""
    try:
        encoding = getattr(sys.stdout, 'encoding', '') or ''
        if encoding.lower().replace('-', '') in ('utf8', 'utf16', 'utf32'):
            return True
        # Try encoding a representative sample of chars we use
        test = '╔═║✓✗→🛡⠋█░'
        test.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


if not _can_encode_unicode():
    # Override heavy box-drawing with ASCII
    TUI.BOX_TL = '+'
    TUI.BOX_TR = '+'
    TUI.BOX_BL = '+'
    TUI.BOX_BR = '+'
    TUI.BOX_H = '='
    TUI.BOX_V = '|'
    TUI.BOX_LT = '+'
    TUI.BOX_RT = '+'
    TUI.BOX_TT = '+'
    TUI.BOX_BT = '+'
    TUI.BOX_X = '+'

    # Override light box-drawing with ASCII
    TUI.LBOX_TL = '+'
    TUI.LBOX_TR = '+'
    TUI.LBOX_BL = '+'
    TUI.LBOX_BR = '+'
    TUI.LBOX_H = '-'
    TUI.LBOX_V = '|'

    # Override symbols with ASCII equivalents
    TUI.CHECK = '[OK]'
    TUI.CROSS = '[X]'
    TUI.ARROW = '->'
    TUI.BULLET = '*'
    TUI.STAR = '*'
    TUI.DIAMOND = '*'
    TUI.CIRCLE = '(o)'
    TUI.CIRCLE_EMPTY = '( )'
    TUI.SQUARE = '[#]'
    TUI.SQUARE_EMPTY = '[ ]'
    TUI.TRIANGLE = '>'
    TUI.WARNING = '[!]'
    TUI.INFO = '[i]'
    TUI.LOCK = '[L]'
    TUI.UNLOCK = '[U]'
    TUI.SHIELD = '[S]'

    # Override progress bar and spinner
    TUI.BAR_FILLED = '#'
    TUI.BAR_EMPTY = '.'
    TUI.SPINNER_FRAMES = ['|', '/', '-', '\\']


if __name__ == "__main__":
    # Demo
    tui.clear()
    tui.banner("PURPLE TEAM PLATFORM", "GRC & Security Assessment")

    tui.section("System Status")
    tui.status("nmap", "/usr/bin/nmap", ok=True)
    tui.status("nuclei", "/usr/bin/nuclei", ok=True)
    tui.status("caldera", "NOT FOUND", ok=False)
    tui.section_end()

    tui.section("Progress Demo")
    for i in range(101):
        tui.progress_bar(i, 100, label="Scanning")
        time.sleep(0.02)
    print()
    tui.section_end()

    tui.table(
        ["Tool", "Status", "Path"],
        [
            ["nmap", "OK", "/usr/bin/nmap"],
            ["nuclei", "OK", "/usr/bin/nuclei"],
            ["nikto", "OK", "/usr/bin/nikto"],
        ]
    )
