"""Main entry point for `taintwatch` command-line console tool."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from taintwatch.cli.commands import (
    cmd_check,
    cmd_inspect,
    cmd_repl,
    cmd_serve,
    cmd_token,
)


def build_parser() -> argparse.ArgumentParser:
    """Build root CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="taintwatch",
        description=(
            "TaintWatch: Information-Flow Control & Zero-Trust Taint Tracking for LLM Agents"
        ),
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # inspect
    p_inspect = subparsers.add_parser(
        "inspect", help="Inspect text or file with span-level taint analysis"
    )
    p_inspect.add_argument("target", help="Text string or file path to inspect")
    p_inspect.add_argument("--source", default="cli:input", help="Source provenance tag")
    p_inspect.add_argument(
        "--integrity",
        choices=["untrusted", "tool_output", "user", "system"],
        default="untrusted",
        help="Input integrity level",
    )
    p_inspect.add_argument(
        "--confidentiality",
        choices=["public", "internal", "secret"],
        default="public",
        help="Input confidentiality level",
    )

    # check
    p_check = subparsers.add_parser(
        "check", help="Evaluate a tool call against an Information-Flow policy"
    )
    p_check.add_argument("tool", help="Target tool/sink name (e.g. bash, sql_exec, http_post)")
    p_check.add_argument("payload", help="Tool argument payload to evaluate")
    p_check.add_argument(
        "--min-integrity",
        choices=["untrusted", "tool_output", "user", "system"],
        default="system",
    )
    p_check.add_argument(
        "--max-confidentiality",
        choices=["public", "internal", "secret"],
        default="public",
    )
    p_check.add_argument(
        "--input-integrity",
        choices=["untrusted", "tool_output", "user", "system"],
        default="untrusted",
    )

    # token
    p_token = subparsers.add_parser("token", help="Cryptographic inter-agent token commands")
    t_subs = p_token.add_subparsers(dest="token_action", required=True)

    t_issue = t_subs.add_parser("issue", help="Issue a signed HMAC-SHA256 token")
    t_issue.add_argument("--payload", required=True, help="Payload data")
    t_issue.add_argument("--sender", default="agent-alpha")
    t_issue.add_argument("--recipient", default="*")
    t_issue.add_argument(
        "--integrity",
        choices=["untrusted", "tool_output", "user", "system"],
        default="untrusted",
    )
    t_issue.add_argument(
        "--confidentiality",
        choices=["public", "internal", "secret"],
        default="public",
    )
    t_issue.add_argument("--key", default="taintwatch-console-default-key-32b")

    t_verify = t_subs.add_parser("verify", help="Verify token authenticity and Merkle inclusion")
    t_verify.add_argument("--token-json", required=True, help="Serialized token JSON")
    t_verify.add_argument(
        "--payload", required=True, help="Original payload used when issuing the token"
    )
    t_verify.add_argument("--key", default="taintwatch-console-default-key-32b")

    # serve
    p_serve = subparsers.add_parser("serve", help="Start the FastAPI REST server and web UI")
    p_serve.add_argument("--host", default="127.0.0.1", help="Server host")
    p_serve.add_argument("--port", type=int, default=8000, help="Server port")

    # repl
    subparsers.add_parser("console", help="Launch interactive terminal REPL")
    subparsers.add_parser("repl", help="Launch interactive terminal REPL (alias for console)")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run CLI entry point."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 0

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand == "inspect":
        return cmd_inspect(args)
    elif args.subcommand == "check":
        return cmd_check(args)
    elif args.subcommand == "token":
        return cmd_token(args)
    elif args.subcommand == "serve":
        return cmd_serve(args)
    elif args.subcommand in ("console", "repl"):
        return cmd_repl(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
