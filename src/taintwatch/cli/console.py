"""Console rendering utilities for terminal Information-Flow inspection."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

from taintwatch.labels import Confidentiality, Integrity
from taintwatch.spans.tstr import TStr


def _supports_color() -> bool:
    """Determine whether the terminal supports ANSI color output."""
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return True
    return True


COLOR_ENABLED = _supports_color()

# ANSI escape codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Foreground colors
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GRAY = "\033[90m"

# Background colors
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"
BG_MAGENTA = "\033[45m"
BG_CYAN = "\033[46m"
BG_DARK = "\033[100m"


def style(
    text: str,
    fg: str | None = None,
    bg: str | None = None,
    bold: bool = False,
    dim: bool = False,
) -> str:
    """Format string with ANSI escape codes if color is enabled."""
    if not COLOR_ENABLED:
        return text
    prefix = ""
    if bold:
        prefix += BOLD
    if dim:
        prefix += DIM
    if fg:
        prefix += fg
    if bg:
        prefix += bg
    return f"{prefix}{text}{RESET}"


def badge(label: str, fg: str = WHITE, bg: str = BG_DARK) -> str:
    """Format a terminal pill badge."""
    return style(f" {label} ", fg=fg, bg=bg, bold=True)


def integrity_badge(integrity: Integrity | int) -> str:
    """Return a color-coded terminal badge for an integrity label."""
    if isinstance(integrity, int):
        integrity = Integrity(integrity)
    if integrity == Integrity.SYSTEM:
        return style(" SYSTEM ", fg=WHITE, bg=BG_GREEN, bold=True)
    if integrity == Integrity.USER:
        return style(" USER ", fg=WHITE, bg=BG_GREEN)
    if integrity == Integrity.TOOL_OUTPUT:
        return style(" TOOL_OUTPUT ", fg=WHITE, bg=BG_YELLOW, bold=True)
    return style(" UNTRUSTED ", fg=WHITE, bg=BG_RED, bold=True)


def confidentiality_badge(confidentiality: Confidentiality | int) -> str:
    """Return a color-coded terminal badge for a confidentiality label."""
    if isinstance(confidentiality, int):
        confidentiality = Confidentiality(confidentiality)
    if confidentiality == Confidentiality.PUBLIC:
        return style(" PUBLIC ", fg=WHITE, bg=BG_CYAN, bold=True)
    if confidentiality == Confidentiality.INTERNAL:
        return style(" INTERNAL ", fg=WHITE, bg=BG_MAGENTA, bold=True)
    return style(" SECRET ", fg=WHITE, bg=BG_RED, bold=True)


def render_span_highlight(tstr: TStr) -> str:
    """Render a TStr with ANSI background highlighting corresponding to taint levels."""
    if not tstr.segments:
        return str(tstr)

    rendered: list[str] = []
    text = tstr.text
    for seg in tstr.segments:
        chunk = text[seg.start : seg.end]
        if not chunk:
            continue
        if seg.label.integrity == Integrity.UNTRUSTED:
            rendered.append(style(chunk, fg=WHITE, bg=BG_RED, bold=True))
        elif seg.label.integrity == Integrity.TOOL_OUTPUT:
            rendered.append(style(chunk, fg=WHITE, bg=BG_YELLOW, bold=True))
        else:
            rendered.append(style(chunk, fg=WHITE, bg=BG_GREEN))

    return "".join(rendered)


def render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    title: str | None = None,
) -> str:
    """Render a clean Unicode/ASCII table with box borders."""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            clean_cell = _strip_ansi(cell)
            if idx < len(col_widths):
                col_widths[idx] = max(col_widths[idx], len(clean_cell))

    lines: list[str] = []

    def make_border(left: str, mid: str, cross: str, right: str) -> str:
        parts = [mid * (w + 2) for w in col_widths]
        return left + cross.join(parts) + right

    if title:
        lines.append(style(f"== {title} ==", fg=CYAN, bold=True))

    # Top border
    lines.append(make_border("┌", "─", "┬", "┐"))

    # Header row
    hdr_cells = []
    for idx, h in enumerate(headers):
        hdr_cells.append(f" {style(h.ljust(col_widths[idx]), bold=True)} ")
    lines.append("│" + "│".join(hdr_cells) + "│")

    # Header divider
    lines.append(make_border("├", "─", "┼", "┤"))

    # Rows
    for row in rows:
        row_cells = []
        for idx, c in enumerate(row):
            clean_len = len(_strip_ansi(c))
            padding = " " * (col_widths[idx] - clean_len)
            row_cells.append(f" {c}{padding} ")
        lines.append("│" + "│".join(row_cells) + "│")

    # Bottom border
    lines.append(make_border("└", "─", "┴", "┘"))
    return "\n".join(lines)


def _strip_ansi(text: str) -> str:
    """Strip ANSI escape sequences from text for accurate column width calculation."""
    import re

    ansi_regex = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_regex.sub("", text)


def render_merkle_tree(proof: list[str], root_hash: str) -> str:
    """Render a clean ASCII tree representation of a Merkle provenance path."""
    lines = [
        style("Merkle Provenance Tree", fg=CYAN, bold=True),
        f"  root: {style(root_hash[:16] + '...', fg=GREEN, bold=True)}",
    ]
    for idx, h in enumerate(proof):
        connector = "  └── " if idx == len(proof) - 1 else "  ├── "
        lines.append(f"{connector}{style(h[:16] + '...', fg=BLUE)} (sibling hash)")
    return "\n".join(lines)
