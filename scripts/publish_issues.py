"""Automated script to publish curated contributor tasks to GitHub issues."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPO = "eyadstein/taintwatch"
TASKS_FILE = Path("docs/CONTRIBUTING_TASKS_30.md")

DESIRED_LABELS = {
    "integrations": ("1d76db", "Framework & LLM integrations"),
    "server": ("006b75", "Server, API, and storage features"),
    "frontend": ("e99695", "Web UI and frontend components"),
    "dsl": ("bfdadc", "Policy language and DSL tools"),
    "security": ("b60205", "Security and hardening enhancements"),
    "benchmark": ("d4c5f9", "Benchmarking and evaluation scenarios"),
    "eval": ("c2e0c6", "Evaluation metrics and reporting"),
    "cli": ("5319e7", "Command-line tools and console UI"),
    "tooling": ("fef2c0", "Developer developer tooling and schemas"),
    "ci": ("0e8a16", "Continuous integration and workflows"),
}


def ensure_labels() -> None:
    """Ensure custom labels exist in the GitHub repository."""
    for label, (color, desc) in DESIRED_LABELS.items():
        cmd = [
            "gh",
            "label",
            "create",
            label,
            "--repo",
            REPO,
            "--color",
            color,
            "--description",
            desc,
            "--force",
        ]
        subprocess.run(cmd, capture_output=True, text=True)


def get_existing_issue_titles() -> set[str]:
    """Fetch existing issue titles to avoid duplicate creation."""
    cmd = [
        "gh",
        "issue",
        "list",
        "--repo",
        REPO,
        "--limit",
        "100",
        "--state",
        "all",
        "--json",
        "title",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    items = json.loads(res.stdout) if res.stdout.strip() else []
    return {item["title"] for item in items}


def parse_tasks() -> list[dict[str, str | list[str]]]:
    """Parse tasks from CONTRIBUTING_TASKS_30.md."""
    text = TASKS_FILE.read_text(encoding="utf-8")
    pattern = re.compile(
        r"### (Task \d+:\s*[^\n]+)\n"
        r"- \*\*Labels\*\*:\s*([^\n]+)\n"
        r"- \*\*Difficulty\*\*:\s*([^\n]+)\n"
        r"- \*\*Description\*\*:\s*([^\n]+)\n"
        r"- \*\*Target Files\*\*:\s*([^\n]+)\n"
        r"- \*\*Acceptance Criteria\*\*:\s*([^\n]+)",
        re.MULTILINE,
    )

    tasks = []
    for match in pattern.finditer(text):
        title = match.group(1).strip()
        raw_labels = match.group(2).strip()
        difficulty = match.group(3).strip()
        description = match.group(4).strip()
        target_files = match.group(5).strip()
        acceptance = match.group(6).strip()

        # Parse labels like `good first issue`, `integrations`
        labels = [
            label.strip().strip("`")
            for label in raw_labels.split(",")
            if label.strip()
        ]

        tasks.append(
            {
                "title": title,
                "labels": labels,
                "difficulty": difficulty,
                "description": description,
                "target_files": target_files,
                "acceptance": acceptance,
            }
        )
    return tasks


def main() -> None:
    print(f"Ensuring labels exist for {REPO}...")
    ensure_labels()

    existing_titles = get_existing_issue_titles()
    tasks = parse_tasks()
    print(f"Found {len(tasks)} tasks in {TASKS_FILE}. Existing issues: {len(existing_titles)}")

    for task in tasks:
        title = str(task["title"])
        if title in existing_titles:
            print(f"Skipping already existing issue: {title}")
            continue

        body = (
            f"## Contributor Task: {title}\n\n"
            f"**Difficulty**: {task['difficulty']}\n"
            f"**Target Files**: `{task['target_files']}`\n\n"
            f"### Description\n{task['description']}\n\n"
            f"### Acceptance Criteria\n{task['acceptance']}\n\n"
            f"---\n"
            f"### How to Claim This Task\n"
            f"1. Leave a comment saying `I would like to work on this task!` to be assigned.\n"
            f"2. Read our [Contributing Guide](https://github.com/eyadstein/taintwatch/blob/main/CONTRIBUTING.md).\n"
            f"3. Submit a Pull Request referencing this issue number (`Fixes #<number>`).\n"
            f"4. Need help? Reach out on GitHub discussions or issue comments!"
        )

        labels = list(task["labels"])
        cmd = ["gh", "issue", "create", "--repo", REPO, "--title", title, "--body", body]
        for lbl in labels:
            cmd.extend(["--label", lbl])

        print(f"Creating issue: {title}...")
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"Failed to create {title}: {res.stderr}")
        else:
            print(f"Created: {res.stdout.strip()}")

    print("Finished publishing issues!")


if __name__ == "__main__":
    main()
