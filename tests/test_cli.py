"""Unit tests for TaintWatch cross-platform terminal CLI and console utilities."""

import json
from io import StringIO
from unittest.mock import patch

from taintwatch.cli.__main__ import main
from taintwatch.cli.console import (
    render_merkle_tree,
    render_span_highlight,
    render_table,
    style,
)
from taintwatch.labels import Integrity, Label
from taintwatch.spans.tstr import TStr


def test_console_style_and_table() -> None:
    txt = style("hello", bold=True)
    assert "hello" in txt

    headers = ["Col A", "Col B"]
    rows = [["Val 1", "Val 2"], ["Longer value", "Short"]]
    table_str = render_table(headers, rows, title="Test Table")
    assert "Col A" in table_str
    assert "Val 1" in table_str
    assert "Longer value" in table_str


def test_console_render_span_highlight() -> None:
    lbl = Label(integrity=Integrity.UNTRUSTED, sources=frozenset({"test"}))
    tstr = TStr.of("cat /etc/passwd", lbl)
    rendered = render_span_highlight(tstr)
    assert "cat /etc/passwd" in rendered


def test_console_merkle_tree() -> None:
    tree = render_merkle_tree(["abc123456789012345", "def123456789012345"], "root123456789012345")
    assert "Merkle Provenance Tree" in tree
    assert "root12345678" in tree


def test_cli_help() -> None:
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        rc = main(["--help"])
        assert rc == 0
        assert "TaintWatch" in mock_out.getvalue()


def test_cli_inspect_text() -> None:
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        rc = main(["inspect", "safe text query"])
        assert rc == 0
        output = mock_out.getvalue()
        assert "TaintWatch Terminal Inspector" in output
        assert "Span Table" in output


def test_cli_inspect_evasion() -> None:
    payload = "eval(\u200b'malicious')"
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        rc = main(["inspect", payload])
        assert rc == 0
        output = mock_out.getvalue()
        assert "Adversarial Evasion Detected" in output


def test_cli_check_blocked_and_allowed() -> None:
    # Untrusted payload to system sink -> blocked
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        rc = main(["check", "bash", "cat /etc/shadow", "--input-integrity", "untrusted"])
        assert rc == 1
        assert "BLOCKED" in mock_out.getvalue()

    # System payload to system sink -> allowed
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        rc = main(["check", "bash", "echo hello", "--input-integrity", "system"])
        assert rc == 0
        assert "ALLOWED" in mock_out.getvalue()


def test_cli_token_issue_and_verify() -> None:
    # Issue
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        rc = main(
            [
                "token",
                "issue",
                "--payload",
                "user_record_42",
                "--sender",
                "auth-service",
                "--recipient",
                "db-service",
                "--key",
                "test-secret-key-123456",
            ]
        )
        assert rc == 0
        output = mock_out.getvalue()
        assert "Cryptographic Taint Token Issued" in output
        assert "Signed Token Envelope" in output

        # Extract the compact token (last non-empty line)
        lines = [l.strip() for l in output.strip().splitlines() if l.strip()]
        compact_token = lines[-1]

    # Verify valid
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        rc = main(
            [
                "token",
                "verify",
                "--token-json",
                compact_token,
                    "--payload",
                    "user_record_42",
                "--key",
                "test-secret-key-123456",
            ]
        )
        assert rc == 0
        assert "Token Verified" in mock_out.getvalue()

    # Verify corrupted token -> fail (mangle the compact string)
    corrupted = compact_token[:10] + "XXXX" + compact_token[14:]
    with patch("sys.stdout", new_callable=StringIO) as mock_out:
        rc = main(
            [
                "token",
                "verify",
                "--token-json",
                corrupted,
                "--payload",
                    "user_record_42",
                    "--key",
                "test-secret-key-123456",
            ]
        )
        # Either fails to parse or fails verification
        assert rc == 1
