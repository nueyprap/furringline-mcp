#!/usr/bin/env python3
"""plan-login-check: use a Claude plan login only through Claude Code (Narathip, 2026-10-28: "ok add it").

A Claude plan login (a subscription OAuth token such as CLAUDE_CODE_OAUTH_TOKEN*, or Claude Code's own saved login)
may only be handed to the `claude` program (its environment, or the claude-code-action input). This check fails when
code sends one itself. Plain text rules; no model, no network.

  check.py                       every code file in the repository (tracked and new, not ignored)
  check.py FILE ...              these files
  check.py --base REF            only lines that the change from REF (REF...HEAD) adds: the CI mode
  options: --repo DIR (default: the current repo), --github (error annotations), --list-rules

Flags, in code files (not Markdown, not test files or fixtures); `--list-rules` prints them:
  oauth-beta         the plan-login beta header (oauth- and a date)
  sessions-beta      the Claude Code cloud betas (ccr-b..., and dated ccr- betas such as the routines one)
  oauth-endpoint     a claude.ai account endpoint under /api/oauth (usage, profile, account, ...)
  keychain-login     Claude Code's Keychain item ("Claude Code-cred...")
  saved-login        the plan login entry of Claude Code's saved login (claudeAi...)
  credentials-file   reading Claude Code's credentials file (an existence check alone does not count)
  bearer-plan-token  a CLAUDE_CODE_OAUTH_TOKEN* value put into a Bearer header by hand, on the same line or through
                     a variable assigned from it in the 25 lines before
Allowed: API keys (x-api-key, ANTHROPIC_API_KEY*), CLAUDE_CODE_OAUTH_TOKEN* in an environment for `claude` or as the
claude_code_oauth_token input, and Bearer headers built from other keys.

A real exception carries a marker on the same line: `plan-login-ok: <reason of 3+ words>` (for example a script that
only reads the login's expiry times and never sends the token). Exit 0 clean, 1 on a finding, 2 when it could not
run. Findings name the file, line and rule, never the line's text. Python 3.9+, standard library only.
"""
import argparse
import os
import re
import subprocess
import sys

# The patterns are written so this file never matches itself (it is also skipped by name).
RULES = {
    'oauth-beta': (re.compile(r'\boauth-20\d\d-\d\d-\d\d\b'),
                   'the plan-login beta header: send a plan login only through the claude program'),
    # ccr-byoc (cloud sessions) and the dated cloud betas of the same family, such as ccr-triggers (routines)
    'sessions-beta': (re.compile(r'\bccr-(?:by[o]c\b|[a-z]+-20\d\d-\d\d-\d\d\b)'),
                      'a Claude Code cloud beta (sessions, routines): it is called with a plan login; use the claude '
                      'program'),
    # Claude's own account endpoints only; other services' OAuth paths (for example /api/oauth/token) pass.
    'oauth-endpoint': (re.compile(r'/api/oaut[h]/(?:usage|profile|account|claude_cli|organi[sz]ations?)\b'),
                       'a claude.ai account endpoint: it is called with a plan login; use the claude program'),
    'keychain-login': (re.compile(r'Claude Code-cre[d]entials'),
                       "reads Claude Code's saved login from the Keychain; only the claude program may use it"),
    'saved-login': (re.compile(r'claudeAiOaut[h]'),
                    "reads the plan login in Claude Code's saved login; only the claude program may use it"),
}
CRED_FILE = re.compile(r'\.cre[d]entials\.json\b')
CRED_MSG = "reads Claude Code's credentials file; only the claude program may use it (an existence check is fine)"
# What reading (or copying) a file looks like on a line. Existence checks (isfile, exists, test -f) are not reads.
READ = re.compile(r'\bopen\s*\(|\.read_(?:text|bytes)\s*\(|\bjson\.loads?\s*\(|\breadFile(?:Sync)?\b|\bfs\.read'
                  r'|\b(?:cat|jq|cp|scp|rsync|base64)\s|\$\(\s*<|<\s*["\'$~/]')
PLAN_VAR = r'CLAUDE_CODE_OAUTH_TOKEN\w*'
# The header word as it is written in a header value ("Bearer " + x, Bearer $X, f"Bearer {x}", Bearer ${{ ... }}),
# not a name such as a variable called bearer or a rule called bearer-plan-token.
BEARER = r'(?i)\bbearer(?:\s*["\'`]|\s+[$%{<#])'
BEARER_SAME = re.compile(BEARER + r'.{0,120}?' + PLAN_VAR)
BEARER_MSG = 'a plan token put into a Bearer header by hand; pass it to the claude program instead'
# `name = ...CLAUDE_CODE_OAUTH_TOKEN...` (Python, JS, shell) or `name: ...CLAUDE_CODE_OAUTH_TOKEN...` (YAML, JS).
ASSIGN = re.compile(r'^\s*(?:export\s+|local\s+|const\s+|let\s+|var\s+|readonly\s+)?["\']?([A-Za-z_]\w*)["\']?\s*'
                    r'(?::=|=(?!=)|:)\s*(.*)$')
WINDOW = 25
MARKER = re.compile(r'plan-login-ok:(.*)$')
MIN_REASON_WORDS = 3

CODE_EXT = {'.py', '.sh', '.bash', '.zsh', '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.tsx', '.jsx', '.yml',
            '.yaml', '.toml', '.rb', '.go', '.rs', '.swift', '.ps1', '.php', '.java', '.kt', '.command', '.vue',
            '.svelte'}
SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'site-packages',
             'tests', 'test', '__tests__', 'fixtures', 'testdata', '__fixtures__', 'plan-login-check'}
# Build output and vendored code only at the top: a folder named build deeper down (scripts/build, a build skill)
# is our own code.
ROOT_SKIP_DIRS = {'dist', 'build', 'vendor'}
SELF_NAMES = {'plan_login_check.py'}
COMMENT = re.compile(r'^\s*(?:#(?!!)|//|/\*|\*(?:\s|$)|<!--)')


def is_test_file(path):
    name = os.path.basename(path)
    return (name.startswith(('test_', 'test-')) or name == 'conftest.py'
            or re.search(r'_test\.\w+$|\.(?:test|spec)\.\w+$', name) is not None)


def is_code(path, head=None):
    """A code file by extension, or an extensionless script with a shebang (head = its first bytes)."""
    parts = path.replace('\\', '/').split('/')
    if (any(p in SKIP_DIRS for p in parts[:-1]) or (len(parts) > 1 and parts[0] in ROOT_SKIP_DIRS)
            or parts[-1] in SELF_NAMES or is_test_file(path)):
        return False
    ext = os.path.splitext(parts[-1])[1].lower()
    if ext:
        return ext in CODE_EXT
    return head is not None and head.startswith(b'#!')


def marker_ok(line):
    """(has marker, reason long enough)."""
    m = MARKER.search(line)
    if not m:
        return False, False
    reason = re.sub(r'[*/#>\-]+\s*$', '', m.group(1)).strip()
    return True, len(reason.split()) >= MIN_REASON_WORDS


def findings(text, path=''):
    """[(line number, rule, message)] for one file's text."""
    lines = text.splitlines()
    out = []
    plan_vars = {}  # name -> last line number it was assigned a plan token
    cred_vars = {}  # name -> last line number it was assigned the credentials file path

    def add(n, rule, msg):
        has, ok = marker_ok(lines[n - 1])
        if ok:
            return
        if has:
            msg += f' (the plan-login-ok marker needs a reason of {MIN_REASON_WORDS}+ words)'
        out.append((n, rule, msg))

    for n, line in enumerate(lines, 1):
        if COMMENT.match(line):
            continue
        for rule, (rx, msg) in RULES.items():
            if rx.search(line):
                add(n, rule, msg)
        a = ASSIGN.match(line)
        if CRED_FILE.search(line):
            if READ.search(line):
                add(n, 'credentials-file', CRED_MSG)
            elif a:
                cred_vars[a.group(1)] = n
        if BEARER_SAME.search(line):
            add(n, 'bearer-plan-token', BEARER_MSG)
        else:
            for name, at in plan_vars.items():
                if n - at <= WINDOW and re.search(BEARER + r'.{0,120}?(?<![\w.])\$?\{?' + re.escape(name) + r'\b',
                                                  line):
                    add(n, 'bearer-plan-token', f'{BEARER_MSG} (via {name}, set on line {at})')
                    break
        for name, at in cred_vars.items():
            if at != n and n - at <= WINDOW and READ.search(line) and re.search(r'\b' + re.escape(name) + r'\b', line):
                add(n, 'credentials-file', f'{CRED_MSG} (via {name}, set on line {at})')
                break
        if a and re.search(PLAN_VAR, a.group(2)) and not re.fullmatch(PLAN_VAR, a.group(1), re.I):
            plan_vars[a.group(1)] = n
    return out


def git(repo, *args):
    p = subprocess.run(['git', '-C', repo, *args], capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f'git {" ".join(args[:3])}: {p.stderr.strip()[:300]}')
    return p.stdout


def all_files(repo):
    return [f for f in git(repo, 'ls-files', '-z', '-co', '--exclude-standard').split('\0') if f]


def diff_path(header):
    """The new path from a `+++ ` header line: git ends a name holding a space with a tab, and quotes a name with
    special characters in C style (\\t, \\", octal bytes)."""
    name = header[4:].rstrip('\t')
    if name.startswith('"') and name.endswith('"'):
        name = name[1:-1].encode('latin-1', 'backslashreplace').decode('unicode_escape').encode('latin-1').decode(
            'utf-8', 'replace')
    return name[2:] if name.startswith('b/') else None


def added_lines(repo, base):
    """{path: {added line numbers}} for the change from base (base...HEAD), files that still exist only."""
    out = {}
    path = None
    for line in git(repo, '-c', 'core.quotePath=false', 'diff', '-U0', '--no-color', '--no-ext-diff',
                    '--diff-filter=ACMR', f'{base}...HEAD').splitlines():
        if line.startswith('+++ '):
            path = diff_path(line)
            if path is not None:
                out.setdefault(path, set())
        elif line.startswith('@@') and path is not None:
            m = re.match(r'@@ -\S+ \+(\d+)(?:,(\d+))? @@', line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
                out[path].update(range(start, start + count))
    return out


def read(repo, path, rev=None):
    """(first 2 bytes, text) of a file on disk, or at a revision (the --base mode reads HEAD, so the lines match the
    diff even when the working copy has edits); (None, None) when missing or binary."""
    if rev:
        p = subprocess.run(['git', '-C', repo, 'show', f'{rev}:{path}'], capture_output=True)
        if p.returncode:
            return None, None
        data = p.stdout
    else:
        try:
            with open(os.path.join(repo, path), 'rb') as f:
                data = f.read()
        except OSError:
            return None, None
    if b'\0' in data[:8192]:
        return None, None
    return data[:2], data.decode('utf-8', 'replace')


def scan(repo, paths, only=None):
    """[(path, line, rule, message)]; only = {path: lines} keeps the findings on those lines."""
    out = []
    for path in paths:
        if only is not None and path not in only:
            continue
        if not is_code(path, b'#!'):  # cheap name test first; the shebang is checked after reading
            continue
        head, text = read(repo, path, 'HEAD' if only is not None else None)
        if text is None or not is_code(path, head):
            continue
        for n, rule, msg in findings(text, path):
            if only is None or n in only[path]:
                out.append((path, n, rule, msg))
    return out


def markers(repo, only):
    """[(path, line, reason)] for every plan-login-ok marker on an added line of a code file, so each exception
    shows in the check's output for the reviewer."""
    out = []
    for path in sorted(only):
        if not is_code(path, b'#!'):
            continue
        head, text = read(repo, path, 'HEAD')
        if text is None or not is_code(path, head):
            continue
        lines = text.splitlines()
        for n in sorted(only[path]):
            m = MARKER.search(lines[n - 1]) if 0 < n <= len(lines) else None
            if m:
                out.append((path, n, re.sub(r'[*/#>\-]+\s*$', '', m.group(1)).strip()[:200]))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog='plan-login-check', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='*')
    ap.add_argument('--repo', default='.')
    ap.add_argument('--base', default='', help='only lines added since this ref (REF...HEAD)')
    ap.add_argument('--github', action='store_true')
    ap.add_argument('--list-rules', action='store_true')
    a = ap.parse_args(argv)
    if a.list_rules:
        for rule, (_, msg) in RULES.items():
            print(f'{rule}: {msg}')
        print(f'credentials-file: {CRED_MSG}\nbearer-plan-token: {BEARER_MSG}')
        return 0
    try:
        repo = git(os.path.abspath(a.repo), 'rev-parse', '--show-toplevel').strip()
        only = added_lines(repo, a.base) if a.base else None
        paths = a.files or (sorted(only) if only is not None else all_files(repo))
        hits = scan(repo, paths, only)
        marks = markers(repo, only) if only is not None else []
    except (RuntimeError, OSError) as e:
        print(f'plan-login-check: could not run: {e}', file=sys.stderr)
        return 2
    for path, n, rule, msg in hits:
        print(f'{path}:{n}: [{rule}] {msg}')
        if a.github:
            print(f'::error file={path},line={n},title=Plan login outside Claude Code ({rule})::{msg}')
    for path, n, reason in marks:
        print(f'{path}:{n}: plan-login-ok marker added: {reason}')
        if a.github:
            print(f'::notice file={path},line={n},title=plan-login-ok exception added::{reason}')
    if hits:
        print(f'\nplan-login-check: {len(hits)} finding(s). Rule: use a plan login only through Claude Code '
              '(the claude program, or claude-code-action). For a real exception put '
              f'`plan-login-ok: <reason, {MIN_REASON_WORDS}+ words>` on that line. scripts/plan-login-check/README.md '
              'in nuey-skills.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
