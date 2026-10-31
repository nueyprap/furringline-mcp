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
    # Claude's own routes that are not a documented API: claude.ai's /api/ routes and Claude Code's /v1/code/
    # routes (routines, sessions). Called with a login, they act as the Claude app. A path written alone
    # ('/api/...') next to an Anthropic host is caught by API_PATH below.
    'internal-route': (re.compile(r'\bclaude\.ai/ap[i]/|/v1/cod[e]/[a-z]'),
                       "a Claude internal route (claude.ai /api/, Claude Code /v1/code/): not a documented API; use "
                       "the claude program, the documented API with an API key, or a link"),
    # Claude Code's or the Claude app's identity copied: its User-Agent (claude-cli/<v>, claude-code/<v>, the
    # desktop app's Claude/<v> ... Electron), its x-app header, its identity beta or its OAuth client id.
    'app-identity': (re.compile(r'["\'`]claude-(?:cl[i]|cod[e])/\d|\bClaud[e]/\d+\.\d+\.\d+'
                                r'|\bclaude-cod[e]-20\d{6}\b|["\']x-ap[p]["\']\s*:\s*["\']cli\b'
                                r'|9d1c250[a]-e61b-44d9-88ed-5944d1962f5e'),
                     'pretends to be Claude Code or the Claude app (its User-Agent, headers or client id), for '
                     'example to get past a bot check; send our own identity, or use the claude program'),
}
# A whole quoted path under /api/ ('/api/artifacts/mcp') in a file that names an Anthropic host and reads a plan
# login: the internal route written as API + '/api/...'. (A file without a login, or for another host, passes.)
API_PATH = re.compile(r'(["\'])/ap[i]/[\w./{}-]*\1')
CLAUDE_HOST = re.compile(r'https?://(?:api\.anthropi[c]\.com|(?:www\.)?claud[e]\.ai)\b')
LOGIN_READ = {'keychain-login', 'saved-login', 'oauth-beta', 'credentials-file', 'bearer-plan-token'}
# GitHub workflows: a job that runs on pull_request_target or workflow_run (base-repo secrets, started by a
# fork's PR) and gets secrets must check the PR comes from this repository (furringline-mcp PR #21).
WF_TRIGGER = re.compile(r'\b(?:pull_request_targe[t]|workflow_ru[n])\b')
WF_SECRET = re.compile(r'\bsecrets\s*:\s*inherit\b|\$\{\{[^}]*?\bsecrets(?:\.(?!GITHUB_TOKEN\b)\w|\s*\[|\s*\))')
WF_GUARD = re.compile(r'(?:head\.repo|head_repository)\.full_name\s*==\s*github\.repository\b'
                      r'|\bgithub\.repository\s*==\s*github\.event\.(?:pull_request\.head\.repo|workflow_run\.head_repository)'
                      r'\.full_name\b|head\.repo\.fork\s*==\s*false\b|!\s*github\.event\.pull_request\.head\.repo\.fork\b')
WF_MSG = ('a pull_request_target or workflow_run job gets secrets without checking the PR comes from this repository; '
          "add `github.event.pull_request.head.repo.full_name == github.repository` (workflow_run: "
          '`github.event.workflow_run.head_repository.full_name`) to the if of the job or of that step')
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


def is_workflow(path):
    return re.search(r'(?:^|/)\.github/workflows/[^/]+\.ya?ml$', path.replace('\\', '/')) is not None


def _indent(line):
    return len(line) - len(line.lstrip(' '))


def _block(lines, start):
    """The index after the block that starts at lines[start]: the lines indented deeper (or blank) below it."""
    base, i = _indent(lines[start]), start + 1
    while i < len(lines) and (not lines[i].strip() or COMMENT.match(lines[i]) or _indent(lines[i]) > base):
        i += 1
    return i


def _if_text(lines, start, end, indent):
    """The text of the `if:` key written at this indent between start and end (with its folded lines)."""
    for i in range(start, end):
        m = re.match(r'^(\s*)(-\s+)?if\s*:(.*)$', _strip_comment(lines[i]))
        if m and len(m.group(1)) + (2 if m.group(2) else 0) == indent:
            return ' '.join([m.group(3)] + [_strip_comment(ln).strip() for ln in lines[i + 1:_block(lines, i)]])
    return ''


def _strip_comment(line):
    """The line without a trailing YAML comment (a # after a space, outside quotes)."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            quote = None if ch == quote else quote
        elif ch in '"\'':
            quote = ch
        elif ch == '#' and (i == 0 or line[i - 1] in ' \t'):
            return line[:i].rstrip()
    return line


def _atom_for_fork(atom):
    """An atom's value for a fork's PR: False, True, or None (not known)."""
    a = atom.strip()
    if WF_GUARD.search(a):
        return False
    if re.fullmatch(r'github\.event\.pull_request\.head\.repo\.fork', a):
        return True
    m = re.fullmatch(r'github\.event_name\s*(==|!=)\s*["\']([\w-]+)["\']', a)
    if m:
        same = m.group(2) in ('pull_request_target', 'workflow_run')
        return same if m.group(1) == '==' else not same
    return None


def _fork_value(expr):
    """Three-valued value of a GitHub `if` expression for a fork's PR: the guard is False there, and so is an
    event-name test for workflow_dispatch; everything else is unknown. A guard holds only when the whole
    expression is surely False (so `!(guard)` and `x || guard` do not count)."""
    s = expr.strip()
    s = re.sub(r'^(?:[>|][-+]?\s*)', '', s).strip()
    if s.startswith('${{') and s.endswith('}}'):
        s = s[3:-2]
    pos = [0]

    def skip():
        while pos[0] < len(s) and s[pos[0]] in ' \t':
            pos[0] += 1

    def atom():
        start, depth, quote = pos[0], 0, None
        while pos[0] < len(s):
            ch = s[pos[0]]
            if quote:
                quote = None if ch == quote else quote
            elif ch in '"\'':
                quote = ch
            elif ch == '(':
                depth += 1
            elif ch == ')':
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and s.startswith(('&&', '||'), pos[0]):
                break
            pos[0] += 1
        return _atom_for_fork(s[start:pos[0]])

    def unary():
        skip()
        if s.startswith('!', pos[0]) and not s.startswith('!=', pos[0]):
            pos[0] += 1
            v = unary()
            return None if v is None else not v
        if s.startswith('(', pos[0]):
            pos[0] += 1
            v = disj()
            skip()
            pos[0] += s.startswith(')', pos[0])
            return v
        return atom()

    def conj():
        vals = [unary()]
        skip()
        while s.startswith('&&', pos[0]):
            pos[0] += 2
            vals.append(unary())
            skip()
        return False if False in vals else (True if all(v is True for v in vals) else None)

    def disj():
        vals = [conj()]
        skip()
        while s.startswith('||', pos[0]):
            pos[0] += 2
            vals.append(conj())
            skip()
        return True if True in vals else (False if all(v is False for v in vals) else None)

    try:
        return disj()
    except (IndexError, RecursionError):
        return None


def _guarded(if_text):
    return bool(if_text.strip()) and _fork_value(if_text) is False


def workflow_findings(text):
    """[(line, rule, message, (first, last line of the job))] for a GitHub workflow: each line of a job that runs on
    pull_request_target or workflow_run and uses secrets (in `${{ }}`, or `secrets: inherit`) with no same-repository
    guard in the job's `if` or in the `if` of the step that uses them. A workflow-level `env:` secret counts unless
    every job is guarded. The job's lines go with it, so --base mode sees a removed guard too."""
    lines = [_strip_comment(ln) if not COMMENT.match(ln) else '' for ln in text.splitlines()]
    on_at = next((i for i, ln in enumerate(lines) if re.match(r'^["\']?(?:on|true)["\']?\s*:', ln)), None)
    if on_at is None or not any(WF_TRIGGER.search(ln) for ln in lines[on_at:_block(lines, on_at)]):
        return []
    jobs_at = next((i for i, ln in enumerate(lines) if re.match(r'^jobs\s*:\s*$', ln)), None)
    jobs_end = _block(lines, jobs_at) if jobs_at is not None else 0
    keys = [i for i in range(jobs_at + 1, jobs_end) if re.match(r'^\s+["\']?[\w-]+["\']?\s*:\s*$', lines[i])] \
        if jobs_at is not None else []
    job_indent = min((_indent(lines[i]) for i in keys), default=0)
    out, all_guarded = [], True
    for k in (i for i in keys if _indent(lines[i]) == job_indent):
        end = _block(lines, k)
        child = next((_indent(lines[i]) for i in range(k + 1, end) if lines[i].strip()), job_indent + 2)
        if _guarded(_if_text(lines, k + 1, end, child)):
            continue
        all_guarded = False
        for i in range(k + 1, end):
            if not WF_SECRET.search(lines[i]):
                continue
            # The step holding this line: the nearest `- ` item above it at a shallower indent.
            step = next((j for j in range(i, k, -1) if re.match(r'^\s*-\s', lines[j])
                         and (j == i and re.match(r'^\s*-\s+\w[\w-]*\s*:', lines[j])
                              or _indent(lines[j]) < _indent(lines[i]))), None)
            if step is not None and _guarded(_if_text(lines, step, _block(lines, step), _indent(lines[step]) + 2)):
                continue
            out.append((i + 1, 'untrusted-secrets', WF_MSG, (k + 1, end)))
    env_at = next((i for i, ln in enumerate(lines) if re.match(r'^env\s*:\s*$', ln)), None)
    if env_at is not None and not (keys and all_guarded):
        env_end = _block(lines, env_at)
        out += [(i + 1, 'untrusted-secrets', WF_MSG, (env_at + 1, env_end))
                for i in range(env_at + 1, env_end) if WF_SECRET.search(lines[i])]
    return out


def findings(text, path=''):
    """[(line number, rule, message)] for one file's text."""
    return [f[:3] for f in findings_spans(text, path)]


def findings_spans(text, path=''):
    """[(line number, rule, message, (first, last) or None)]: a workflow finding carries its job's lines."""
    lines = text.splitlines()
    out = []
    reads_login = []  # a login-reading rule matched (even under a marker): the file holds a plan login
    plan_vars = {}  # name -> last line number it was assigned a plan token
    cred_vars = {}  # name -> last line number it was assigned the credentials file path

    def add(n, rule, msg, span=None):
        if rule in LOGIN_READ:
            reads_login.append(n)
        has, ok = marker_ok(lines[n - 1])
        if ok:
            return
        if has:
            msg += f' (the plan-login-ok marker needs a reason of {MIN_REASON_WORDS}+ words)'
        out.append((n, rule, msg, span))

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
    if reads_login and any(CLAUDE_HOST.search(ln) for ln in lines if not COMMENT.match(ln)):
        for n, line in enumerate(lines, 1):
            if not COMMENT.match(line) and API_PATH.search(line) and not RULES['internal-route'][0].search(line):
                add(n, 'internal-route', RULES['internal-route'][1])
    if is_workflow(path):
        for n, rule, msg, span in workflow_findings(text):
            add(n, rule, msg, span)
    return sorted(out, key=lambda f: f[0])


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


def added_lines(repo, base, near=None):
    """{path: {added line numbers}} for the change from base (base...HEAD), files that still exist only. A dict
    given as `near` also gets, per path, the lines next to each place lines were only deleted (a removed guard)."""
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
                if near is not None and count == 0:  # git puts the line before the deletion in `start`
                    near.setdefault(path, set()).update((start, start + 1))
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


def scan(repo, paths, only=None, near=None):
    """[(path, line, rule, message)]; only = {path: lines} keeps the findings on those lines (a workflow finding:
    on any line of its job, or next to lines deleted from it, near = {path: lines})."""
    out = []
    near = near or {}
    for path in paths:
        if only is not None and path not in only and path not in near:
            continue
        if not is_code(path, b'#!'):  # cheap name test first; the shebang is checked after reading
            continue
        head, text = read(repo, path, 'HEAD' if only is not None else None)
        if text is None or not is_code(path, head):
            continue
        for n, rule, msg, span in findings_spans(text, path):
            touched = only.get(path, set()) | near.get(path, set()) if only is not None else set()
            if only is None or n in touched and n in only.get(path, ()) or (
                    span and any(i in touched for i in range(span[0], span[1] + 1))):
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
        print(f'credentials-file: {CRED_MSG}\nbearer-plan-token: {BEARER_MSG}\nuntrusted-secrets: {WF_MSG}')
        return 0
    try:
        repo = git(os.path.abspath(a.repo), 'rev-parse', '--show-toplevel').strip()
        near = {}
        only = added_lines(repo, a.base, near) if a.base else None
        paths = a.files or (sorted(set(only) | set(near)) if only is not None else all_files(repo))
        hits = scan(repo, paths, only, near)
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
