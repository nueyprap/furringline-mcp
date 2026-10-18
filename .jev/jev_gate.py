#!/usr/bin/env python3
"""jev-gate: a Jev (TypeSafe System One) pass/fail check for code changes.

One script, three layers: the CI job (--mode ci), the git pre-push hook
(--mode pre-push) and agent Stop hooks (--mode stop). It collects the diff,
runs an exact regex secret scan in code, asks Jev a few narrow yes/no (Noul)
questions about the change, and turns the probabilities into a verdict:

  fail  a BLOCK question >= BLOCK_T, or the regex found a secret
  warn  a WARN question >= WARN_T, or a BLOCK question in [WARN_T, BLOCK_T)
  pass  otherwise

A commit trailer "Jev-Override: <reason>" in the range lets a fail through
(reported as OVERRIDDEN). Jev errors fail open. Python 3.9+, stdlib only.
Source of truth: scripts/jev-gate/ in nueyprap/nuey-skills; repositories carry
a copy in .jev/jev_gate.py that install.py keeps up to date.
"""
from __future__ import annotations

VERSION = "0.1.6"

import argparse
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

MODEL = "jev-1.13.0"
ENDPOINT = "https://api.typesafe.ai/v1/systemone"

BLOCK_T = 0.85          # a BLOCK question at or above this fails the change
WARN_T = 0.50           # a WARN question (or a BLOCK one below BLOCK_T) at or above this warns
STATE_BYTES = 80_000    # keep each request's state under this (Jev: 32k tokens for state + question)
MIN_CHUNK_BYTES = 30_000
MAX_CHUNKS = 12         # diffs past this many chunks are only regex-scanned
RULES_CHARS = 6_000
TASK_CHARS = 4_000
FILES_LIST_CHARS = 12_000
CALL_TIMEOUT_S = 10.0
RETRIES = 1
MAX_WORKERS = 4
MAX_RESPONSE_BYTES = 256 * 1024
BUDGET_S = {"ci": 180.0, "pre-push": 45.0, "stop": 25.0}
MAX_UNTRACKED_FILES = 200
MAX_UNTRACKED_BYTES = 2_000_000
CACHE_ENTRIES = 100

LOCKFILES = {"pnpm-lock.yaml", "package-lock.json", "yarn.lock", "poetry.lock", "uv.lock", "Cargo.lock"}
MINIFIED_SUFFIXES = (".min.js", ".min.mjs", ".min.cjs", ".min.css")
OVERRIDE_RE = re.compile(r"(?mi)^Jev-Override:[ \t]*(\S.*?)\s*$")
NOISE_TRAILER_RE = re.compile(r"(?mi)^(Co-Authored-By|Signed-off-by|Claude-Session):.*$\n?")

MISSING_KEY_CI = ("TYPESAFE_API_KEY secret is not set for this repo. Setup, not a code problem: "
                  "use authorized environment injection and scripts/jev-gate/set-secrets.sh REPO from nuey-skills. "
                  "Do not change code to fix this.")

# ---------------------------------------------------------------------------
# Questions. Each text stands alone: question ids are never shown to Jev.
# State fields: `diff`, `diff_scope`, `changed_files`, `rules`, `task`, `repository`.
# ---------------------------------------------------------------------------

DIFF_HOW_TO_READ = ("`diff` is a unified diff: lines starting with a single + are added, lines "
                    "starting with a single - are removed, other lines are unchanged context. ")

QUESTIONS = {
    "secret_added": {
        "meaning": "added lines contain a real secret (key, token, password, private key)",
        "fix": "remove the secret value and load it from the environment or a secret store",
        "instructions": (
            DIFF_HOW_TO_READ + "Look only at the added lines. Does any added line contain a real "
            "secret value written out in plain text, such as an API key, an access token, a "
            "password, a private key, or a connection string that includes a password?"),
        "criteria": {
            "true": "At least one added line contains what looks like a real, usable secret value in plain text.",
            "false": ("No added line contains a real secret value. Placeholders (such as xxx, <your-key>, "
                      "changeme), environment variable names, references to a secret store (such as "
                      "${{ secrets.NAME }} or process.env.NAME), text marked [REDACTED], and obviously fake "
                      "example values do not count."),
        },
    },
    "task_unmet": {
        "meaning": "the change does not do what the task asks, or only part of it",
        "fix": "finish what the task asks, or say in the commit or PR text what is left for later",
        "instructions": (
            "`task` says what this change is meant to do (a pull request title and description, or "
            "commit messages). " + DIFF_HOW_TO_READ + "`changed_files` lists every changed file with "
            "its added and removed line counts. `diff_scope` says whether `diff` shows the whole change "
            "or only part of it; when it shows only part, work in a listed file that is not shown may "
            "still be done, so do not count work as missing only because it is not shown. Does the "
            "change clearly fail to do what `task` asks?"),
        "criteria": {
            "true": ("The change clearly does not do what `task` asks, or it does only part of what "
                     "`task` asks and `task` does not say that the rest is left for later."),
            "false": ("The change does what `task` asks, or plausibly does and nothing clearly shows "
                      "otherwise. Extra cleanup, small differences in wording, parts that `task` says are "
                      "left for later, and a `task` too vague to check do not count."),
        },
    },
    "breaks_rule": {
        "meaning": "added lines break a written rule of this repository (AGENTS.md / CLAUDE.md)",
        "fix": "re-read the repository rules and change the lines that break them",
        "instructions": (
            "`rules` holds the written rules for this repository. " + DIFF_HOW_TO_READ +
            "Do the added lines clearly break a specific rule written in `rules`?"),
        "criteria": {
            "true": ("An added line clearly does something a specific rule in `rules` forbids, or the "
                     "change clearly leaves out something a rule requires for this kind of change."),
            "false": ("No added line clearly breaks a rule in `rules`. Rules that do not apply to this "
                      "change, rules about how agents should work or talk rather than about file "
                      "contents, and unclear or debatable cases do not count."),
        },
    },
    "missing_test": {
        "meaning": "code behavior changes but no test was added or updated",
        "fix": "add or update a test for the changed behavior",
        "instructions": (
            DIFF_HOW_TO_READ + "`changed_files` lists every changed file. Does this change alter "
            "how the program behaves (a new feature, changed logic, a bug fix) without adding or "
            "updating any automated test?"),
        "criteria": {
            "true": "The change alters program behavior and no file in `changed_files` is a test file that was added or changed.",
            "false": ("At least one test file was added or changed, or the change does not alter program "
                      "behavior (for example it only changes documentation, comments, formatting, text, "
                      "or configuration values)."),
        },
    },
    "sensitive_area": {
        "meaning": "touches sign-in, permissions, secret handling, payments, deploy/CI config or DB migrations",
        "fix": "review these parts by hand before merging",
        "instructions": (
            DIFF_HOW_TO_READ + "`changed_files` lists every changed file. Does this change touch a "
            "sensitive area: sign-in or authentication, permissions or access control, the handling "
            "of secrets or keys, payments or money, deployment or CI configuration (such as GitHub "
            "Actions workflows, Dockerfiles or deploy scripts), or database migrations or schema?"),
        "criteria": {
            "true": "The change edits code or configuration in at least one of those sensitive areas.",
            "false": "The change does not touch any of those areas.",
        },
    },
    "debug_leftover": {
        "meaning": "debug prints, commented-out code or temporary hacks left in",
        "fix": "remove debug output, commented-out code and temporary hacks",
        "instructions": (
            DIFF_HOW_TO_READ + "Look only at the added lines. Do they leave behind debugging or "
            "temporary code, such as debug print or console.log statements left in by mistake, "
            "blocks of commented-out code, or hacks marked as temporary (for example 'TODO remove', "
            "'HACK', 'temporary')?"),
        "criteria": {
            "true": "At least one added line is leftover debug output, commented-out code, or a temporary hack not meant for the final version.",
            "false": ("No added line is leftover debugging or temporary code. Intended logging, output "
                      "that is part of the feature, and normal explanatory comments do not count."),
        },
    },
    "private_data": {
        "meaning": "added lines contain private personal data (bank/card numbers, passwords, codes, ID numbers)",
        "fix": "remove or mask the private data",
        "instructions": (
            DIFF_HOW_TO_READ + "Look only at the added lines. Do they add private personal data "
            "written out in full, such as a full bank account or card number, a password, a one-time "
            "or recovery code, or a person's national ID, passport or tax ID number?"),
        "criteria": {
            "true": "At least one added line contains such private data in full.",
            "false": ("No added line contains such private data. Business email addresses, company names, "
                      "folder paths, links, non-secret IDs, and masked or partial numbers (such as the last "
                      "four digits) do not count."),
        },
    },
    "app_code": {
        "meaning": "adds application code, which belongs in its own product repository",
        "fix": "move application code to its product repository and keep only docs or small agent scripts here",
        "instructions": (
            "This repository is for knowledge documents (Markdown notes, workflows, rules) and small "
            "helper scripts and tooling for AI agents, not for application code. " + DIFF_HOW_TO_READ +
            "Do the added lines add application code, such as a web app, a server, an API service or a "
            "product feature?"),
        "criteria": {
            "true": "The change adds application or product code that belongs in its own code repository.",
            "false": ("The change adds or edits documents, configuration, tests, or helper scripts and "
                      "tooling for agents (such as hooks, checks, installers or setup scripts)."),
        },
    },
    "rewrites_history": {
        "meaning": "rewrites or deletes existing passages instead of adding dated notes",
        "fix": "keep earlier passages and add new material as dated notes",
        "instructions": (
            DIFF_HOW_TO_READ + "Does the change rewrite or delete existing passages of the documents "
            "(removed lines replaced by different text, or removed without replacement), instead of "
            "adding new dated notes at the end of a section?"),
        "criteria": {
            "true": "The change removes or rewrites whole sentences or paragraphs of earlier content, beyond small fixes.",
            "false": ("The change mostly adds new text, or only makes small fixes such as typos, links, "
                      "dates or status lines. Updating a current-state snapshot file such as "
                      "CURRENT_STATE.md does not count."),
        },
    },
}

# profile -> list of (question id, class)
PROFILES = {
    "code": [("secret_added", "block"), ("task_unmet", "block"), ("breaks_rule", "block"),
             ("missing_test", "warn"), ("sensitive_area", "warn"), ("debug_leftover", "warn")],
    "knowledge": [("secret_added", "block"), ("private_data", "block"), ("app_code", "block"),
                  ("rewrites_history", "warn"), ("breaks_rule", "warn")],
}
TASK_QUESTION = "task_unmet"   # asked once per run, not once per chunk

PLACEHOLDER_WORDS = ("xxxx", "example", "placeholder", "your", "dummy", "changeme", "redacted", "sample",
                     "fake", "test", "mock", "stub", "fixture", "synthetic", "generated", "not-a", "not_a",
                     "notreal", "0000000000", "aaaaaaaaaa")
GENERIC_KIND = "hard-coded credential"
TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?)/|(^|/)test_[^/]*$|[._-](test|spec)\.[^/]+$")

# Exact checks stay in code. Group `v` is the secret value (redacted before Jev sees the diff).
SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\b(?P<v>AKIA[0-9A-Z]{16})\b")),
    ("GitHub token", re.compile(r"\b(?P<v>gh[pousr]_[A-Za-z0-9]{30,})")),
    ("GitHub token", re.compile(r"\b(?P<v>github_pat_[A-Za-z0-9_]{30,})")),
    ("sk- API key", re.compile(r"(?<![A-Za-z0-9_-])(?P<v>sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,})")),
    ("Slack token", re.compile(r"\b(?P<v>xox[bp]-[A-Za-z0-9-]{10,})")),
    # a header alone is not a key: it must end the line or be followed by key data
    ("private key", re.compile(r"(?P<v>-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)(?:\s*$|(?:\\n|\s)+[A-Za-z0-9+/=]{20,})")),
    (GENERIC_KIND, re.compile(
        r"(?i)(?:api[_-]?key|secret|token|password)[\"']?\s*[:=]\s*[\"'](?P<v>[A-Za-z0-9_\-]{16,})[\"']")),
]


class JevError(Exception):
    """A Jev call failed. Messages never contain the key or request text."""


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def git(repo, *args, check=True):
    proc = subprocess.run(["git", "-C", str(repo), "-c", "core.quotepath=off", *args],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {proc.stderr.strip()[:200]}")
    return proc.stdout


def git_try(repo, *args):
    """Run git; return stdout, or None on a non-zero exit."""
    proc = subprocess.run(["git", "-C", str(repo), "-c", "core.quotepath=off", *args],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    return proc.stdout if proc.returncode == 0 else None


def is_commit(repo, ref):
    return bool(ref) and git_try(repo, "rev-parse", "--verify", "-q", f"{ref}^{{commit}}") is not None


def default_remote_ref(repo):
    out = git_try(repo, "symbolic-ref", "-q", "refs/remotes/origin/HEAD")
    if out and out.strip():
        return out.strip().replace("refs/remotes/", "", 1)
    for candidate in ("origin/main", "origin/master"):
        if is_commit(repo, candidate):
            return candidate
    return None


def merge_base(repo, a, b):
    out = git_try(repo, "merge-base", a, b)
    return out.strip() if out else None


def repo_name(repo):
    url = (git_try(repo, "remote", "get-url", "origin") or "").strip()
    name = url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1] if url else Path(repo).name
    return name[:-4] if name.endswith(".git") else name


DIFF_FLAGS = ("diff", "--no-color", "--no-ext-diff", "--no-textconv", "-M")


def untracked_diff(repo, strict=False):
    out = git_try(repo, "ls-files", "--others", "--exclude-standard", "-z")
    if out is None and strict:
        raise RuntimeError("cannot enumerate untracked changes")
    paths = [p for p in (out or "").split("\0") if p]
    if strict and any(exclusion_reason(p) is None for p in paths[MAX_UNTRACKED_FILES:]):
        raise RuntimeError("untracked change count exceeds review limit")
    parts = []
    for path in paths[:MAX_UNTRACKED_FILES]:
        full = Path(repo) / path
        try:
            if not full.is_file() or full.stat().st_size > MAX_UNTRACKED_BYTES:
                if strict and exclusion_reason(path) is None:
                    raise RuntimeError("untracked change cannot be fully collected")
                continue
        except OSError:
            if strict:
                raise RuntimeError("untracked change cannot be read") from None
            continue
        proc = subprocess.run(["git", "-C", str(repo), "-c", "core.quotepath=off", *DIFF_FLAGS,
                               "--no-index", "--", "/dev/null", path],
                              capture_output=True, text=True, encoding="utf-8", errors="replace")
        if strict and proc.returncode not in (0, 1):
            raise RuntimeError("untracked diff collection failed")
        parts.append(proc.stdout)
    return "".join(parts)


# ---------------------------------------------------------------------------
# Collecting the change: returns (diff text, commit log text, base ref or None)
# ---------------------------------------------------------------------------

def collect_ci(repo, base):
    if not is_commit(repo, base):
        raise RuntimeError(f"base ref {base!r} not found (fetch-depth 0 needed)")
    diff = git(repo, *DIFF_FLAGS, f"{base}...HEAD")
    log = git(repo, "log", "--format=%B%n", f"{base}..HEAD")
    return diff, log, base


def is_ancestor(repo, a, b):
    return git_try(repo, "merge-base", "--is-ancestor", a, b) is not None


def push_base(repo, remote_sha, local_sha):
    """Diff base and log exclusions for one pushed ref.

    Starts from the remote tip, but leaves out commits already reachable from the
    default branch (origin/main): a tool branch that merged main is not re-reviewed
    for other agents' merged work. When the remote tip and main diverge, the base is
    their clean merge tree; a conflicted merge falls back to the remote tip (stricter).
    """
    remote = remote_sha if set(remote_sha) != {"0"} and is_commit(repo, remote_sha) else None
    if remote:
        remote = merge_base(repo, remote, local_sha)   # same base as `remote...local`
    default = default_remote_ref(repo)
    main = merge_base(repo, default, local_sha) if default else None
    if not remote or not main:
        base = remote or main
        return base, base, [base] if base else []
    if is_ancestor(repo, remote, main):
        return main, main, [main]
    if is_ancestor(repo, main, remote):
        return remote, remote, [remote]
    tree = git_try(repo, "merge-tree", "--write-tree", "--no-messages", remote, main)
    if tree and tree.strip():
        return tree.split()[0], remote, [remote, main]
    return remote, remote, [remote]


def collect_pre_push(repo, stdin_text, base_override=None, strict=False):
    ranges = []   # (diff base, head, rules base, log exclusions)
    for line in stdin_text.splitlines():
        parts = line.split()
        if len(parts) != 4:
            if strict and line.strip():
                raise RuntimeError("invalid pre-push ref input")
            continue
        local_ref, local_sha, _remote_ref, remote_sha = parts
        if set(local_sha) == {"0"} or local_ref.startswith("refs/tags/"):
            continue  # branch deletion or tag
        if base_override:
            base = merge_base(repo, base_override, local_sha)
            diff_base, rules_base, exclude = base, base, [base]
        else:
            diff_base, rules_base, exclude = push_base(repo, remote_sha, local_sha)
        entry = (diff_base, local_sha, rules_base, tuple(exclude))
        if diff_base and entry not in ranges:
            ranges.append(entry)
        elif strict and not diff_base:
            raise RuntimeError("cannot establish pushed change base")
    diff = "".join(git(repo, *DIFF_FLAGS, b, h) for b, h, _r, _x in ranges)
    log = "".join(git(repo, "log", "--format=%B%n", h, "--not", *x) for _b, h, _r, x in ranges)
    return diff, log, (ranges[0][2] if ranges else None)


def collect_stop(repo, base_override=None, strict=False):
    if not is_commit(repo, "HEAD"):
        if strict:
            raise RuntimeError("cannot establish Stop change base")
        return untracked_diff(repo), "", None
    ref = base_override or default_remote_ref(repo)
    mb = merge_base(repo, ref, "HEAD") if ref else None
    if strict and not mb:
        raise RuntimeError("cannot establish Stop change base")
    if mb:
        diff = git(repo, *DIFF_FLAGS, mb)          # merge-base -> working tree (committed + uncommitted)
        log = git(repo, "log", "--format=%B%n", f"{mb}..HEAD")
    else:
        diff, log = git(repo, *DIFF_FLAGS, "HEAD"), ""
    return diff + untracked_diff(repo, strict=strict), log, mb


# ---------------------------------------------------------------------------
# Diff parsing, filtering, secret scan, chunking
# ---------------------------------------------------------------------------

class FileDiff:
    def __init__(self, text):
        self.text = text
        self.path = _diff_path(text)
        self.binary = bool(re.search(r"(?m)^(Binary files .* differ|GIT binary patch)$", text))
        self.added, self.removed = 0, 0
        self.added_lines = []   # (new line number, content)
        in_hunk, new_line = False, 0
        for line in text.splitlines():
            if line.startswith("@@"):
                m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
                new_line = int(m.group(1)) if m else 0
                in_hunk = True
            elif not in_hunk:
                continue
            elif line.startswith("+"):
                self.added += 1
                self.added_lines.append((new_line, line[1:]))
                new_line += 1
            elif line.startswith("-"):
                self.removed += 1
            elif not line.startswith("\\"):
                new_line += 1

    @property
    def excluded(self):
        return exclusion_reason(self.path) is not None


def _unquote(path):
    path = path.strip()
    if len(path) >= 2 and path[0] == path[-1] == '"':
        path = path[1:-1]
    return path


def _diff_path(text):
    new = re.search(r"(?m)^\+\+\+ (.+)$", text)
    if new and _unquote(new.group(1)) != "/dev/null":
        return re.sub(r"^b/", "", _unquote(new.group(1)))
    old = re.search(r"(?m)^--- (.+)$", text)
    if old and _unquote(old.group(1)) != "/dev/null":
        return re.sub(r"^a/", "", _unquote(old.group(1)))
    renamed = re.search(r"(?m)^rename to (.+)$", text)
    if renamed:
        return _unquote(renamed.group(1))
    header = text.splitlines()[0] if text else ""
    return _unquote(header.rsplit(" b/", 1)[-1]) if " b/" in header else header


def exclusion_reason(path):
    name = path.rsplit("/", 1)[-1]
    if name in LOCKFILES:
        return "lockfile"
    if path.startswith("dist/") or "/dist/" in path:
        return "build output"
    if name.endswith(MINIFIED_SUFFIXES):
        return "minified"
    if path.startswith(".jev/"):
        return "jev-gate itself"
    return None


def split_diff(text):
    return [FileDiff(part) for part in re.split(r"(?m)^(?=diff --git )", text) if part.strip()]


def _real_secret(kind, value, path):
    """Filter obvious non-secrets. Format-specific patterns stay strict; the generic one is looser."""
    if any(word in value.lower() for word in PLACEHOLDER_WORDS):
        return False
    if kind == GENERIC_KIND:
        if TEST_PATH_RE.search(path):
            return False  # test fixtures; Jev's secret_added question still reads them
        if not (re.search(r"[0-9]", value) and re.search(r"[A-Za-z]", value)):
            return False  # words like "dropbox-access-token", not a random value
        if re.fullmatch(r"[A-Z0-9_]+", value) and "_" in value:
            return False  # an environment variable name
    return True


def scan_secrets(files):
    hits = []
    for f in files:
        if f.binary:
            continue
        for line_no, content in f.added_lines:
            for kind, pattern in SECRET_PATTERNS:
                for m in pattern.finditer(content):
                    if _real_secret(kind, m.group("v"), f.path):
                        hits.append({"file": f.path, "line": line_no, "kind": kind,
                                     "hint": m.group("v")[:4] + "..."})
    return hits


def redact(text):
    for kind, pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: m.group(0).replace(m.group("v"), f"[REDACTED {kind}]"), text)
    return text


def files_summary(files):
    lines, size = [], 0
    for f in files:
        if f.binary:
            note = " (binary, not shown)"
        elif f.excluded:
            note = f" ({exclusion_reason(f.path)}, not shown)"
        else:
            note = ""
        entry = f"{f.path} (+{f.added} -{f.removed}){note}"
        if size + len(entry) > FILES_LIST_CHARS:
            lines.append(f"... and {len(files) - len(lines)} more files")
            break
        lines.append(entry)
        size += len(entry) + 1
    return lines


def _truncate_utf8(text, limit):
    return text.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


def make_chunks(texts, limit):
    """Pack per-file diff texts into chunks of at most `limit` bytes, in order."""
    chunks, current, size = [], [], 0
    for text in texts:
        n = len(text.encode("utf-8"))
        if n > limit:
            text = (_truncate_utf8(text, limit - 200) +
                    f"\n[jev-gate: the rest of this file's diff ({n - limit + 200} bytes) was cut to fit the size limit]\n")
            n = len(text.encode("utf-8"))
        if current and size + n > limit:
            chunks.append("".join(current))
            current, size = [], 0
        current.append(text)
        size += n
    if current:
        chunks.append("".join(current))
    return chunks


# ---------------------------------------------------------------------------
# Jev API
# ---------------------------------------------------------------------------

def valid_key(key):
    """Accept resolved HTTP-header credentials only; never echo a rejected value."""
    return (isinstance(key, str) and bool(key) and not key.lower().startswith("op://")
            and key.isascii() and all(32 < ord(c) < 127 for c in key))


KEYCHAIN_SERVICE = "TypeSafe API Key"

STOP_ALERT = " Tell Narathip by iMessage once (critical-blocker workflow) and stop; do not push."
# Claude Code cloud adds the Authorization header for api.typesafe.ai itself (a "network
# secret"); the session never sees the value. This marker means "send no header of our own".
NETWORK_SECRET = "claude-cloud-network-secret"


def claude_cloud():
    return os.environ.get("CLAUDE_CODE_REMOTE", "").lower() == "true"


def is_macos():
    """The Macs keep the key in the Keychain; cloud agent sessions run on Linux."""
    return sys.platform == "darwin"


def key_setup_message(credential_source, failure_kind):
    """One line naming where the key is missing or rejected and the fix. Never the value.

    A missing or rejected key blocks everywhere (Narathip, 2026-10-18), so a key that
    silently stops working cannot hide behind autonomous work."""
    rejected = failure_kind in ("credential_rejected", "legacy_source_revoked")
    if credential_source == NETWORK_SECRET:
        return ("jev-gate: Jev key missing or rejected in this Claude Code cloud environment: add or "
                "update the api.typesafe.ai network secret (header Authorization) in its settings.")
    if is_macos():
        return ("jev-gate: Jev key rejected on this Mac: save the new key in 1Password, then run "
                "jev-key update-all." if rejected else
                "jev-gate: Jev key missing in this Mac's Keychain: run jev-key refresh.")
    return ("jev-gate: Jev key rejected in this environment: replace TYPESAFE_API_KEY in its secrets "
            "settings." if rejected else
            "jev-gate: Jev key missing in this environment: add TYPESAFE_API_KEY to its secrets settings "
            "(Cursor cloud agent secrets, Codex cloud environment secrets, Hermes Cloud).")


def keychain_key():
    """Fast local copy kept by jev-key in the login Keychain; never printed.

    When the copy is missing, ask jev-key to restore it from 1Password once."""
    if os.environ.get("TYPESAFE_KEYCHAIN", "on") == "off" or sys.platform != "darwin":
        return ""
    helper = Path.home() / ".local/bin/jev-key"
    for attempt in (0, 1):
        try:
            found = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", KEYCHAIN_SERVICE,
                                    "-a", "TYPESAFE_API_KEY", "-w"], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return ""
        if found.returncode == 0:
            key = found.stdout.strip()
            return key if valid_key(key) else ""
        if attempt or not os.access(helper, os.X_OK):
            return ""
        try:
            subprocess.run([str(helper), "heal"], capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return ""
    return ""


def load_credential():
    """Environment wins, including explicit invalid/empty values; no silent fallback.
    Then the Keychain copy (jev-key); then the legacy file unless marked revoked."""
    policy = os.environ.get("TYPESAFE_KEY_SOURCE", "auto")
    if policy not in ("auto", "environment"):
        return "", "invalid-policy"
    if "TYPESAFE_API_KEY" in os.environ:
        key = os.environ["TYPESAFE_API_KEY"]
        return (key, "environment") if valid_key(key) else ("", "invalid-environment")
    if policy == "environment":
        return "", "missing-environment"
    key = keychain_key()
    if key:
        return key, "keychain"
    if (Path.home() / ".config/typesafe/legacy-source-revoked.json").exists():
        return "", "revoked-legacy-file"
    env_file = Path.home() / ".config/typesafe/.env"
    try:
        text = env_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "", "missing-file"
    values = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[7:].strip()
        name, sep, value = line.partition("=")
        if sep and name.strip() == "TYPESAFE_API_KEY":
            value = value.strip()
            if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
                value = value[1:-1]
            values.append(value)
    if len(values) == 1 and valid_key(values[0]):
        return values[0], "legacy-file"
    return "", "invalid-file"


def load_key():
    return load_credential()[0]


def question_payload(qid):
    q = QUESTIONS[qid]
    return {"type": "noul", "instructions": q["instructions"], "criteria": dict(q["criteria"])}


def ask_jev(key, state, qids, deadline):
    """One request. Returns {"answers": {qid: p}, "model", "input_tokens", "output_tokens"}."""
    body = json.dumps({"model": MODEL, "state": state,
                       "questions": {q: question_payload(q) for q in qids}},
                      ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": f"jev-gate/{VERSION}"}
    if key != NETWORK_SECRET:  # network secret: the platform proxy adds the header
        headers["Authorization"] = f"Bearer {key}"
    last = "no attempt made"
    for _attempt in range(1 + RETRIES):
        remaining = deadline - time.monotonic()
        if remaining < 1.0:
            raise JevError(f"time budget used up ({last})")
        try:
            with urlopen(Request(ENDPOINT, data=body, headers=headers, method="POST"),
                         timeout=min(CALL_TIMEOUT_S, remaining)) as resp:
                data = json.loads(resp.read(MAX_RESPONSE_BYTES).decode("utf-8"))
            return _parse_answers(data, qids)
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            if exc.code < 500 and exc.code != 429:
                raise JevError(last) from None
        except JevError:
            raise
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = type(exc).__name__
    raise JevError(last)


def _parse_answers(data, qids):
    try:
        if data.get("model") != MODEL:
            raise ValueError
        answers = {}
        for q in qids:
            p = data["answers"][q]["noul"]
            if isinstance(p, bool) or not isinstance(p, (int, float)) or not 0 <= p <= 1:
                raise ValueError
            answers[q] = float(p)
        usage = data.get("usage") or {}
        return {"answers": answers, "model": str(data.get("model", "")),
                "input_tokens": int(usage.get("input_tokens", 0) or 0),
                "output_tokens": int(usage.get("output_tokens", 0) or 0)}
    except (KeyError, TypeError, ValueError, AttributeError):
        raise JevError("unexpected response shape") from None


# ---------------------------------------------------------------------------
# Cache (local modes): unchanged diff + task + rules -> reuse Jev answers
# ---------------------------------------------------------------------------

def cache_path(repo):
    out = git_try(repo, "rev-parse", "--git-common-dir")
    if not out:
        return None
    path = Path(out.strip())
    return (path if path.is_absolute() else Path(repo) / path) / "jev-gate-cache"


def _cache_load(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _cache_store(path, key, value):
    data = _cache_load(path)
    data[key] = value
    if len(data) > CACHE_ENTRIES:
        data = dict(list(data.items())[-CACHE_ENTRIES:])
    try:
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(diff_text, *, task, rules, profile, key, deadline, cache_file=None, repository=""):
    """Run the regex scan and the Jev questions. Returns a result dict (no diff or task text)."""
    files = split_diff(diff_text)
    shown = [f for f in files if not f.binary and not f.excluded]
    hits = scan_secrets(files)
    result = {"profile": profile, "model": "", "checks": [], "regex_hits": hits,
              "jev_status": "ok", "error": "", "calls": 0, "chunks": 0, "unchecked_chunks": 0,
              "input_tokens": 0, "output_tokens": 0, "files": len(files),
              "diff_bytes": len(diff_text.encode("utf-8"))}
    classes = [(q, c) for q, c in PROFILES[profile]
               if not (q == TASK_QUESTION and not task) and not (q == "breaks_rule" and not rules)]
    if not shown and not hits:
        result["jev_status"] = "empty"
        return _finish(result, {}, classes)
    if not key:
        result["jev_status"] = "no-key"
        return _finish(result, {}, classes)
    if not shown:
        result["jev_status"] = "nothing to ask"
        return _finish(result, {}, classes)

    base_state = {"repository": repository, "changed_files": files_summary(files)}
    if rules:
        base_state["rules"] = rules
    if task:
        base_state["task"] = task
    overhead = len(json.dumps(base_state, ensure_ascii=False).encode("utf-8"))
    limit = max(MIN_CHUNK_BYTES, STATE_BYTES - overhead)
    result["truncated_files"] = sum(len(f.text.encode("utf-8")) > limit for f in shown)
    chunks = make_chunks([redact(f.text) for f in shown], limit)
    result["unchecked_chunks"] = max(0, len(chunks) - MAX_CHUNKS)
    chunks = chunks[:MAX_CHUNKS]
    result["chunks"] = len(chunks)

    diff_qids = [q for q, _ in classes if q != TASK_QUESTION]
    requests = []
    for i, chunk in enumerate(chunks):
        state = dict(base_state, diff=chunk, diff_scope=(
            "whole change" if len(chunks) == 1 and not result["unchecked_chunks"] else
            f"part {i + 1} of {len(chunks) + result['unchecked_chunks']}: `diff` shows only some files "
            "of the change; `changed_files` lists all of them"))
        qids = list(diff_qids)
        if i == 0 and any(q == TASK_QUESTION for q, _ in classes):
            qids.append(TASK_QUESTION)
        if i > 0:
            state.pop("task", None)  # only the task question needs it
        requests.append((state, qids))

    # Bind cache entries to the resolved credential without persisting its value or
    # a reusable standalone credential fingerprint. Rotation cannot reuse an old PASS.
    cache_key = hmac.new(key.encode("utf-8"),
                         json.dumps([VERSION, MODEL, requests]).encode("utf-8"),
                         hashlib.sha256).hexdigest()
    if cache_file:
        cached = _cache_load(cache_file).get(cache_key)
        if isinstance(cached, dict) and isinstance(cached.get("answers"), dict):
            result.update(model=cached.get("model", ""), jev_status="cached")
            return _finish(result, cached["answers"], classes)

    answers, models, errors = {}, set(), []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(ask_jev, key, state, qids, deadline) for state, qids in requests]
        for fut in futures:
            try:
                got = fut.result()
            except JevError as exc:
                errors.append(str(exc))
                continue
            result["calls"] += 1
            result["input_tokens"] += got["input_tokens"]
            result["output_tokens"] += got["output_tokens"]
            models.add(got["model"])
            for q, p in got["answers"].items():
                answers[q] = max(p, answers.get(q, 0.0))
    result["model"] = ",".join(sorted(m for m in models if m))
    if errors:
        result["jev_status"] = "unavailable"
        result["error"] = "; ".join(sorted(set(errors)))
    elif cache_file:
        _cache_store(cache_file, cache_key, {"answers": answers, "model": result["model"],
                                             "time": int(time.time())})
    return _finish(result, answers, classes)


def _finish(result, answers, classes):
    checks, verdict = [], "pass"
    jev_ok = result["jev_status"] in ("ok", "cached")
    for qid, cls in classes:
        p = answers.get(qid)
        if p is None:
            status = "not asked"
        elif cls == "block" and p >= BLOCK_T:
            status = "fail" if jev_ok else "warn"   # Jev partly unavailable: never block on it
        elif p >= WARN_T:
            status = "warn"
        else:
            status = "ok"
        checks.append({"id": qid, "class": cls, "p": None if p is None else round(p, 4),
                       "status": status, "meaning": QUESTIONS[qid]["meaning"]})
        if status == "fail":
            verdict = "fail"
        elif status == "warn" and verdict == "pass":
            verdict = "warn"
    if result["regex_hits"]:
        verdict = "fail"
    result["model_verified"] = (result["jev_status"] == "ok" and result["calls"] > 0
                                and result["calls"] == result["chunks"]
                                and result["unchecked_chunks"] == 0
                                and result.get("truncated_files", 0) == 0)
    result["failure_kind"] = ("credential_rejected" if any(code in result.get("error", "")
                              for code in ("HTTP 401", "HTTP 403")) else
                              "no_credentials" if result["jev_status"] == "no-key" else
                              "provider_unavailable" if result["jev_status"] == "unavailable" else "")
    result["replacement_needed"] = result["failure_kind"] == "credential_rejected"
    result["review_status"] = ("verified" if result["model_verified"] else
                               "cached" if result["jev_status"] == "cached" else
                               "no-change" if result["jev_status"] == "empty" else "incomplete")
    result["checks"] = checks
    result["verdict"] = verdict
    return result


# ---------------------------------------------------------------------------
# Inputs: task text, rules, profile, override
# ---------------------------------------------------------------------------

def task_text(explicit, commit_log):
    if explicit:
        text = explicit
    else:
        title, body = os.environ.get("PR_TITLE", "").strip(), os.environ.get("PR_BODY", "").strip()
        text = f"{title}\n\n{body}".strip() if (title or body) else NOISE_TRAILER_RE.sub("", commit_log)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:TASK_CHARS]


def read_rules(repo, base=None):
    for name in ("AGENTS.md", "CLAUDE.md"):
        text = git_try(repo, "show", f"{base}:{name}") if base else None   # rules as they were before the change
        if text is None:
            try:
                text = (Path(repo) / name).read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = None
        if text and text.strip():
            return text[:RULES_CHARS]
    return ""


def default_profile(repo):
    try:
        data = json.loads((Path(repo) / ".jev/config.json").read_text(encoding="utf-8"))
        if data.get("profile") in PROFILES:
            return data["profile"]
    except (OSError, ValueError, AttributeError):
        pass
    return "code"


def find_override(commit_log):
    m = OVERRIDE_RE.search(commit_log or "")
    return m.group(1)[:300] if m else ""


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _fmt_p(p):
    return "  -  " if p is None else f"{p:.2f}"


def human_report(rec, full=True):
    """Verdict first, then each question. full=False lists only questions that flagged."""
    head = f"Jev gate: {rec['verdict'].upper()}"
    if rec.get("review_status") == "incomplete":
        head = f"Jev gate: INCOMPLETE (available checks: {rec['verdict'].upper()})"
    elif rec.get("review_status") == "cached":
        head += " (CACHED; authentication not rechecked)"
    if rec.get("overridden"):
        head += f"  (OVERRIDDEN: {rec['override_reason']})"
    lines = [f"{head}   [profile {rec['profile']}, model {rec['model'] or '-'}, "
             f"{rec['latency_ms'] / 1000:.1f} s, jev-gate {VERSION}]"]
    status = rec["jev_status"]
    if rec.get("replacement_needed"):
        lines.append("  ACTION REQUIRED: credential rejected or legacy source revoked; replacement activation needed. Required check blocked.")
    if status == "unavailable":
        lines.append(f"  WARNING: Jev unavailable ({rec['error']}); model review is incomplete.")
    elif status == "no-key":
        lines.append("  WARNING: no resolved credential; model authentication was not verified.")
    elif status == "empty":
        lines.append("  No reviewable changes.")
    elif status == "cached":
        lines.append("  (answers reused from cache: diff and credential unchanged; not a fresh authentication test)")
    for c in rec["checks"]:
        if not full and c["status"] in ("ok", "not asked"):
            continue
        label = {"fail": "FAIL", "warn": "warn", "ok": "ok", "not asked": "-"}[c["status"]]
        lines.append(f"  {label:<5} {c['id']:<17} {_fmt_p(c['p'])}  {c['meaning']}")
    for h in rec["regex_hits"]:
        lines.append(f"  FAIL  regex secret scan   {h['file']}:{h['line']} looks like a {h['kind']} ({h['hint']})")
    if rec.get("unchecked_chunks"):
        lines.append(f"  Note: diff too large; {rec['unchecked_chunks']} part(s) were only regex-scanned.")
    if rec.get("truncated_files"):
        lines.append(f"  Note: diff too large; {rec['truncated_files']} file(s) were only partly reviewed.")
    if rec["verdict"] == "fail" and not rec.get("overridden"):
        lines.append("  If Jev is wrong, add a trailer line 'Jev-Override: <reason>' to a commit in this change.")
    return "\n".join(lines)


def failing_reason(rec):
    parts = [f"{c['id']} {c['p']:.2f} ({c['meaning']}: {QUESTIONS[c['id']]['fix']})"
             for c in rec["checks"] if c["status"] == "fail"]
    parts += [f"possible {h['kind']} in {h['file']}:{h['line']} (remove the secret value)"
              for h in rec["regex_hits"]]
    return ("Jev gate: " + "; ".join(parts) +
            ". Fix it, or add a 'Jev-Override: <reason>' trailer if Jev is wrong.")


def github_outputs(rec):
    for h in rec["regex_hits"]:
        print(f"::error file={h['file']},line={h['line']},title=Jev gate::Possible {h['kind']} added")
    for c in rec["checks"]:
        if c["status"] == "fail":
            print(f"::error title=Jev gate::{c['id']} {c['p']:.2f}: {c['meaning']}")
        elif c["status"] == "warn":
            print(f"::warning title=Jev gate::{c['id']} {c['p']:.2f}: {c['meaning']}")
    if rec.get("review_enforcement") == "blocked" and not rec.get("model_verified"):
        print("::error title=Jev gate::Required model review is incomplete; blocked")
    elif rec["jev_status"] == "unavailable":
        print(f"::warning title=Jev gate::Jev unavailable ({rec['error']}); advisory review incomplete")
    if rec.get("overridden"):
        print(f"::warning title=Jev gate::fail OVERRIDDEN: {rec['override_reason']}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary:
        return
    heading = "INCOMPLETE" if rec.get("review_status") == "incomplete" else rec['verdict'].upper()
    md = [f"### Jev gate: {heading}" + (" (OVERRIDDEN)" if rec.get("overridden") else ""), "",
          "| Check | Class | P(yes) | Result | Meaning |", "|---|---|---|---|---|"]
    for c in rec["checks"]:
        md.append(f"| `{c['id']}` | {c['class']} | {_fmt_p(c['p'])} | {c['status']} | {c['meaning']} |")
    for h in rec["regex_hits"]:
        md.append(f"| regex | block | - | fail | possible {h['kind']} in `{h['file']}:{h['line']}` |")
    md += ["", f"Enforcement: {rec.get('review_enforcement', 'not-required')}; "
           f"model verified: {str(rec.get('model_verified', False)).lower()}.", "",
           f"Model `{rec['model'] or '-'}`, jev-gate {VERSION}, Jev status: {rec['jev_status']}, "
           f"{rec['latency_ms']} ms, {rec['input_tokens']} input tokens.", ""]
    if rec.get("overridden"):
        md.insert(1, f"\nOverride reason: {rec['override_reason']}\n")
    try:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("\n".join(md) + "\n")
    except OSError:
        pass


def write_log(rec, mode):
    entry = {
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "version": VERSION,
        "repo": rec["repo"], "head": rec["head"], "mode": mode, "profile": rec["profile"],
        "model": rec["model"], "p": {c["id"]: c["p"] for c in rec["checks"]},
        "regex_hits": len(rec["regex_hits"]), "verdict": rec["verdict"],
        "override": bool(rec.get("overridden")), "jev_status": rec["jev_status"],
        "latency_ms": rec["latency_ms"], "input_tokens": rec["input_tokens"],
        "output_tokens": rec["output_tokens"], "diff_bytes": rec["diff_bytes"], "chunks": rec["chunks"],
        "model_verified": rec["model_verified"], "review_status": rec["review_status"],
        "review_requirement": rec["review_requirement"], "review_enforcement": rec["review_enforcement"],
        "unchecked_chunks": rec["unchecked_chunks"], "truncated_files": rec.get("truncated_files", 0),
    }
    if mode == "ci":
        path = Path(os.environ.get("GITHUB_WORKSPACE") or os.getcwd()) / "jev-gate-log.jsonl"
    else:
        path = Path.home() / ".local/share/jev-gate/log.jsonl"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def record_model_health(rec, repo):
    """Local alert state contains metadata only; cached/fallback results never clear it."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return  # Cloud alert ownership belongs to the remote integration.
    failure = rec.get("failure_kind", "")
    if not failure and not rec.get("model_verified"):
        return
    module_path = Path.home() / ".local/share/typesafe/typesafe-health.py"
    if not is_macos() and not module_path.exists():
        return  # cloud hosts have no health record; the setup message already says what to fix
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("_typesafe_health", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.record_model(owner=os.environ.get("TYPESAFE_RUNTIME_OWNER", "unassigned"),
                            consumer=os.environ.get("TYPESAFE_RUNTIME_CONSUMER", "gate/" + rec["mode"] + "/" + str(repo)),
                            status="healthy" if rec.get("model_verified") else "degraded",
                            failure_kind=failure,
                            generation=os.environ.get("TYPESAFE_CREDENTIAL_GENERATION", rec.get("credential_source", "unknown")),
                            model_verified=rec.get("model_verified", False))
    except Exception:
        if failure:
            print("TypeSafe health record unavailable; required check is degraded. Notify the user in the current task; external alert delivery is not configured.", file=sys.stderr)


def parse_args(argv):
    ap = argparse.ArgumentParser(description="Jev pass/fail check for code changes.")
    ap.add_argument("--mode", choices=["ci", "pre-push", "stop"], required=True)
    ap.add_argument("--base", help="base ref (ci: required; others: override the default)")
    ap.add_argument("--task", help="what the change is meant to do")
    ap.add_argument("--profile", choices=sorted(PROFILES), help="default: .jev/config.json, else code")
    ap.add_argument("--json", action="store_true", help="print a machine-readable record")
    ap.add_argument("--no-cache", action="store_true", help="make fresh model calls")
    ap.add_argument("--require-model", action="store_true",
                    help="require fresh complete model evaluation; implies --no-cache")
    ap.add_argument("--require-review", action="store_true",
                    help="require fresh complete review of applicable changes; empty/excluded-only changes are not applicable; implies --no-cache")
    ap.add_argument("--cursor", action="store_true", help="stop mode: Cursor hook output format")
    ap.add_argument("--repo", help="repository directory (default: current directory)")
    ap.add_argument("hook_args", nargs="*", help=argparse.SUPPRESS)  # pre-push passes remote name/url
    return ap.parse_args(argv)


def _read_stdin():
    try:
        return "" if sys.stdin is None or sys.stdin.isatty() else sys.stdin.read()
    except (OSError, ValueError):
        return ""


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return run(args)
    except Exception as exc:  # required review must not turn a crash into permission
        print(f"jev-gate: internal error ({type(exc).__name__}); model evaluation not verified.",
              file=sys.stderr)
        if args.mode == "stop":
            print(json.dumps({"followup_message": "Fresh Jev evaluation required."} if args.cursor else
                             {"decision": "block", "reason": "Fresh Jev evaluation required."})
                  if args.require_model or args.require_review else "{}")
            return 0  # Hook decision is JSON; a Unix failure can discard it in clients.
        return 1 if args.require_model or args.require_review else 0


def run(args):
    started = time.monotonic()
    mode = args.mode
    deadline = started + BUDGET_S[mode]
    stdin_text = _read_stdin() if mode in ("pre-push", "stop") else ""
    out = sys.stdout if mode == "ci" else sys.stderr   # stop: stdout is for hook JSON only

    hook = {}
    loop = False
    if mode == "stop":
        try:
            hook = json.loads(stdin_text) if stdin_text.strip() else {}
            hook = hook if isinstance(hook, dict) else {}
        except ValueError:
            hook = {}
        loop = hook.get("stop_hook_active") or (args.cursor and (hook.get("loop_count") or 0) >= 1)
        if (loop or (args.cursor and hook.get("status") in ("aborted", "error"))) and not args.require_review:
            if args.require_model:
                print(json.dumps({"followup_message": "Fresh Jev evaluation required."} if args.cursor else
                                 {"decision": "block", "reason": "Fresh Jev evaluation required."}))
                return 0
            print("{}")
            return 0

    repo = args.repo or hook.get("cwd") or os.getcwd()
    top = git_try(repo, "rev-parse", "--show-toplevel")
    if not top:
        print("jev-gate: not inside a git repository; skipped.", file=out)
        if mode == "stop":
            # Setup problem: block once at most, never again on a repeat Stop.
            print(json.dumps({"followup_message": "Fresh Jev evaluation required."} if args.cursor else
                             {"decision": "block", "reason": "Fresh Jev evaluation required."})
                  if (args.require_model or args.require_review) and not loop else "{}")
            return 0
        return 1 if args.require_model or args.require_review else 0
    repo = top.strip()

    key, credential_source = load_credential()
    network_secret = not key and mode != "ci" and claude_cloud()
    if network_secret:
        key, credential_source = NETWORK_SECRET, NETWORK_SECRET
    if not key and mode == "ci":
        print(f"::error title=Jev gate::{MISSING_KEY_CI}")
        print(MISSING_KEY_CI)
        return 1
    if not key and not (args.require_model or args.require_review):
        print("jev-gate: no TYPESAFE_API_KEY; Jev check skipped (regex secret scan still runs).", file=out)

    if mode == "ci":
        if not args.base:
            print("jev-gate: --base is required in ci mode", file=out)
            return 1
        diff, log, base = collect_ci(repo, args.base)
    elif mode == "pre-push":
        diff, log, base = collect_pre_push(repo, stdin_text, args.base, strict=args.require_review)
    else:
        diff, log, base = collect_stop(repo, args.base, strict=args.require_review)

    profile = args.profile or default_profile(repo)
    name = repo_name(repo)
    rec = evaluate(diff, task=task_text(args.task, log), rules=read_rules(repo, base),
                   profile=profile, key=key, deadline=deadline, repository=name,
                   cache_file=cache_path(repo) if mode != "ci" and not (network_secret or args.no_cache or args.require_model or args.require_review) else None)
    override = find_override(log)
    rec.update(credential_source=credential_source, repo=name, head=(git_try(repo, "rev-parse", "HEAD") or "").strip(), mode=mode,
               version=VERSION, latency_ms=int((time.monotonic() - started) * 1000),
               overridden=bool(override and rec["verdict"] == "fail"),
               override_reason=override if rec["verdict"] == "fail" else "")

    if credential_source == "revoked-legacy-file":
        rec.update(failure_kind="legacy_source_revoked", replacement_needed=True)
    model_required = ((args.require_model or (args.require_review and rec["jev_status"] != "empty"))
                      and not rec["model_verified"])
    replacement = rec["replacement_needed"]
    real_fail = rec["verdict"] == "fail" and not rec["overridden"]
    setup_block = replacement or (model_required and rec["failure_kind"] in
                                  ("no_credentials", "credential_rejected"))
    setup_msg = key_setup_message(credential_source, rec["failure_kind"]) if setup_block else ""
    # Stop blocks once for a setup problem; a repeat Stop cannot fix the key, so let it end.
    loop_release = bool(loop and setup_block and not real_fail)
    if loop_release:
        print(setup_msg + " Not blocking this Stop again.", file=out)
    blocked = not loop_release and (replacement or model_required or real_fail)
    rec["review_requirement"] = ("fresh-probe" if args.require_model else
                                 "fresh-for-change" if args.require_review else "advisory")
    rec["review_enforcement"] = ("blocked" if blocked else "not-applicable" if rec["jev_status"] == "empty" else
                                 "released-repeat-stop" if loop_release else
                                 "satisfied" if args.require_model or args.require_review else "not-required")
    if not network_secret:  # the health record lives on the Macs
        record_model_health(rec, repo)
    write_log(rec, mode)
    if model_required and not loop_release and not setup_block:
        print("jev-gate: fresh complete model evaluation required; readiness not verified.", file=out)

    if mode == "stop":
        if (rec["verdict"] != "pass" or rec["jev_status"] == "unavailable") and not loop_release:
            print(human_report(rec, full=False), file=sys.stderr)
        if blocked:
            reason = (setup_msg + STOP_ALERT if setup_block and not real_fail else
                      "TypeSafe credential replacement is required; Jev review is incomplete."
                      if replacement else
                      "Fresh complete Jev evaluation required; readiness not verified."
                      if model_required else failing_reason(rec))
            print(json.dumps({"followup_message": reason} if args.cursor else
                             {"decision": "block", "reason": reason}))
        else:
            print("{}")
        return 0

    print(human_report(rec, full=(mode == "ci")), file=out)
    if blocked and setup_msg:
        print(setup_msg, file=out)  # last line: where the key is missing and the fix
    if mode == "ci":
        github_outputs(rec)
    if args.json:
        print(json.dumps(rec, indent=2))
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
