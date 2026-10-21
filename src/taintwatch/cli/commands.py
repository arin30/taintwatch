"""CLI command handlers for TaintWatch terminal console."""

from __future__ import annotations

import argparse
from pathlib import Path

from taintwatch.cli.console import (
    BLUE,
    CYAN,
    GRAY,
    GREEN,
    RED,
    WHITE,
    YELLOW,
    confidentiality_badge,
    integrity_badge,
    render_merkle_tree,
    render_span_highlight,
    render_table,
    style,
)
from taintwatch.crypto.service import TaintTokenSigner, TaintTokenVerifier
from taintwatch.crypto.tokens import CryptoTaintError, TaintToken
from taintwatch.guard import Guard
from taintwatch.labels import Confidentiality, Integrity, Label
from taintwatch.policy import Action, Policy, Rule
from taintwatch.spans.canonical import detect_evasion
from taintwatch.spans.tstr import TStr


def cmd_inspect(args: argparse.Namespace) -> int:
    """Inspect text or file with span-level taint and anti-evasion analysis."""
    raw_input = args.target
    path = Path(raw_input)
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        src_label = f"file:{path.name}"
    else:
        text = raw_input
        src_label = args.source or "cli:input"

    print(style("\n=== TaintWatch Terminal Inspector ===", fg=CYAN, bold=True))
    print(f"Source: {style(src_label, fg=GRAY)} | Length: {len(text)} chars\n")

    int_level = (
        Integrity[args.integrity.upper()] if hasattr(args, "integrity") else Integrity.UNTRUSTED
    )
    conf_level = (
        Confidentiality[args.confidentiality.upper()]
        if hasattr(args, "confidentiality")
        else Confidentiality.PUBLIC
    )

    lbl = Label(
        integrity=int_level,
        confidentiality=conf_level,
        sources=frozenset({src_label}) if src_label else frozenset(),
    )
    tstr = TStr.of(text, lbl)

    # Anti-evasion check
    evasion_report = detect_evasion(tstr)
    if evasion_report.has_evasion:
        print(style("⚠️  Adversarial Evasion Detected!", fg=YELLOW, bold=True))
        for flag in evasion_report.techniques:
            print(f"   • {style(flag, fg=YELLOW)}")
        print(f"Normalized text: {style(evasion_report.canonical.text, fg=WHITE, bold=True)}\n")
    else:
        print(style("✓ No evasion artifacts detected.", fg=GREEN))

    print(style("Live Span Highlighting:", bold=True))
    print(f"  {render_span_highlight(tstr)}\n")

    headers = ["#", "Range", "Length", "Integrity", "Confidentiality", "Source", "Excerpt"]
    rows = []
    for idx, s in enumerate(tstr.segments):
        excerpt = text[s.start : s.end]
        if len(excerpt) > 30:
            excerpt = excerpt[:27] + "..."
        prov_str = ",".join(s.label.sources) if s.label.sources else "literal"
        rows.append(
            [
                str(idx + 1),
                f"[{s.start}:{s.end}]",
                str(s.end - s.start),
                integrity_badge(s.label.integrity),
                confidentiality_badge(s.label.confidentiality),
                prov_str,
                repr(excerpt),
            ]
        )

    print(render_table(headers, rows, title="Span Table"))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Evaluate a tool call against a policy in the terminal."""
    tool_name = args.tool
    payload_str = args.payload
    sink_min_int = Integrity[args.min_integrity.upper()] if args.min_integrity else Integrity.SYSTEM
    sink_max_conf = (
        Confidentiality[args.max_confidentiality.upper()]
        if args.max_confidentiality
        else Confidentiality.PUBLIC
    )

    rule = Rule(
        name=f"protect-{tool_name}",
        tool=tool_name,
        min_integrity=sink_min_int,
        max_confidentiality=sink_max_conf,
        action=Action.BLOCK,
    )
    guard = Guard(policy=Policy(rules=(rule,)))

    input_int = (
        Integrity[args.input_integrity.upper()] if args.input_integrity else Integrity.UNTRUSTED
    )
    labeled_arg = guard.ingest(
        payload_str,
        source="cli:input",
        integrity=input_int,
        confidentiality=Confidentiality.PUBLIC,
    )

    print(style(f"\n=== Evaluating Tool Call: '{tool_name}' ===", fg=CYAN, bold=True))
    print(f"Payload: {style(payload_str, bold=True)}")
    print(
        f"Sink Requirements: min_integrity={sink_min_int.name}, "
        f"max_confidentiality={sink_max_conf.name}\n"
    )

    verdict = guard.check(tool_name, {"arg": labeled_arg})
    if verdict.allowed:
        print(
            style(
                "✓ ALLOWED: Call complies with Information-Flow Control policy.",
                fg=GREEN,
                bold=True,
            )
        )
        return 0
    else:
        print(style("✗ BLOCKED: Policy Violation Detected!", fg=RED, bold=True))
        print(f"  Reason: {style(verdict.explain(), fg=YELLOW)}")
        return 1


def _ensure_key_bytes(raw_key: str) -> bytes:
    kb = raw_key.encode("utf-8")
    if len(kb) < 16:
        kb = kb.ljust(16, b"0")
    return kb


def cmd_token(args: argparse.Namespace) -> int:
    """Issue or verify cryptographic inter-agent taint tokens."""
    key_bytes = _ensure_key_bytes(args.key or "taintwatch-console-default-key-32b")

    if args.token_action == "issue":
        sender = args.sender or "agent-alpha"
        recipient = args.recipient or "*"
        int_level = Integrity[args.integrity.upper()] if args.integrity else Integrity.UNTRUSTED
        conf_level = (
            Confidentiality[args.confidentiality.upper()]
            if args.confidentiality
            else Confidentiality.PUBLIC
        )

        lbl = Label(
            integrity=int_level,
            confidentiality=conf_level,
            sources=frozenset({sender}),
        )
        signer = TaintTokenSigner(secret_key=key_bytes, agent_id=sender)
        token = signer.issue(content=args.payload, label=lbl, recipient=recipient)

        print(style("\n=== Cryptographic Taint Token Issued ===", fg=CYAN, bold=True))
        print(f"Token ID:      {token.token_id}")
        print(f"Sender:        {token.sender}")
        print(f"Recipient:     {token.recipient}")
        print(f"Integrity:     {integrity_badge(token.integrity)}")
        print(f"Confidential:  {confidentiality_badge(token.confidentiality)}")
        print(f"Signature:     {style(token.signature[:24] + '...', fg=GREEN)}")
        print(f"Merkle Root:   {style(token.merkle_root[:24] + '...', fg=BLUE)}\n")
        print(render_merkle_tree([token.merkle_root], token.merkle_root))
        compact = token.to_compact()
        print(style("\nSigned Token Envelope (compact):", bold=True))
        print(compact)
        return 0

    elif args.token_action == "verify":
        token_input = args.token_json.strip()
        try:
            token = TaintToken.from_compact(token_input)
        except CryptoTaintError as exc:
            print(
                style(
                    f"\n✗ Token Verification FAILED: Invalid token encoding: {exc}",
                    fg=RED,
                    bold=True,
                )
            )
            return 1

        verifier = TaintTokenVerifier(key_ring=key_bytes)
        result = verifier.verify(token, content=args.payload)
        if result.valid:
            print(
                style(
                    "\n✓ Token Verified: Cryptographic signature and Merkle inclusion valid.",
                    fg=GREEN,
                    bold=True,
                )
            )
            return 0
        else:
            print(
                style(
                    f"\n✗ Token Verification FAILED: {result.reason}",
                    fg=RED,
                    bold=True,
                )
            )
            return 1
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the TaintWatch REST server and web UI."""
    import uvicorn

    from taintwatch.server.app import create_app

    host = args.host or "127.0.0.1"
    port = args.port or 8000
    print(style(f"\nStarting TaintWatch server on http://{host}:{port}...", fg=CYAN, bold=True))
    app = create_app()
    uvicorn.run(app, host=host, port=port)
    return 0


def cmd_repl(args: argparse.Namespace) -> int:
    """Interactive terminal console session for live taint analysis."""
    print(style("\n╔═══════════════════════════════════════════════════════╗", fg=CYAN))
    print(style("║        🛡️  TaintWatch Interactive Console REPL        ║", fg=CYAN, bold=True))
    print(style("╚═══════════════════════════════════════════════════════╝", fg=CYAN))
    print("Type any text or adversarial payload to inspect span taint and anti-evasion.")
    print("Commands: ':sink <name>', ':quit' to exit.\n")

    current_sink = "bash"
    guard = Guard(
        policy=Policy(
            rules=(
                Rule(
                    name="protect-bash",
                    tool="bash",
                    min_integrity=Integrity.SYSTEM,
                    action=Action.BLOCK,
                ),
            )
        )
    )

    while True:
        try:
            line = input(f"{style('taintwatch', fg=CYAN)} ({style(current_sink, fg=YELLOW)})> ")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        line = line.strip()
        if not line:
            continue
        if line in (":quit", ":q", "exit"):
            print("Bye!")
            break
        if line.startswith(":sink "):
            current_sink = line.split(" ", 1)[1].strip()
            print(f"Current sink switched to: {style(current_sink, fg=YELLOW)}")
            continue

        lbl = Label(integrity=Integrity.UNTRUSTED, sources=frozenset({"repl:user"}))
        tstr = TStr.of(line, lbl)
        evasion_report = detect_evasion(tstr)
        if evasion_report.has_evasion:
            print(style(f"⚠️  Evasion flags: {', '.join(evasion_report.techniques)}", fg=YELLOW))

        print(f"Highlight: {render_span_highlight(tstr)}")

        labeled_arg = guard.ingest(line, source="repl:user", integrity=Integrity.UNTRUSTED)
        verdict = guard.check(current_sink, {"cmd": labeled_arg})
        if verdict.allowed:
            print(style("Verdict:   ✓ ALLOWED", fg=GREEN, bold=True))
        else:
            print(style(f"Verdict:   ✗ BLOCKED ({verdict.explain()})", fg=RED, bold=True))
        print()

    return 0
