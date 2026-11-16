#!/usr/bin/env python3
"""key-save check: code that writes a key to a file also saves it to 1Password (Narathip, 2026-11-16).

A file on a machine is only a cache; the key lives in the 1Password AI Agents vault. So a code file that writes a
token, secret, password or key file must also call the shared save step in the same file: `op-<agent> save` or
`key_save.save` (scripts/key-save in nuey-skills). Plain text rules; no model, no network.

  check.py                       every code file in the repository (tracked and new, not ignored)
  check.py FILE ...              these files
  check.py --base REF            only lines that the change from REF (REF...HEAD) adds: the CI mode
  options: --repo DIR (default: the current repo), --github (error annotations), --list-rules

A write counts when its target looks like a key store: the path or the name on the line (or a variable set to such a
path in the 25 lines before, or a top-level constant), or the write sits in a function whose name says it writes a
key (write_secret, save_token), or it goes through the file's own write helper with such a path. Whatever the file
name, it also counts when the data is Google credentials JSON (creds.to_json()) or names a key field
({"refresh_token": ...}). `--list-rules` prints the rules; scripts/key-save/README.md has the exact lists.

The file passes when it calls the save step (`the save step` below). A pure cache write carries a marker on its line
or the line above: `key-save: <reason of 3+ words>`. Exit 0 clean, 1 on a finding, 2 when it could not run.
Findings name the file, line and rule, never the line's text. Python 3.9+, standard library only.
"""
import argparse
import os
import re
import subprocess
import sys

# ---------- what looks like a key store ----------
SECRET = re.compile(
    # token, but not a model's vocabulary (tokens.txt, tokenizer.json); secret, but not the secret scan's own files
    # (secret-scan.XXXX, secret-scan-allow.json); cred as a whole name part (cred_file, credPath), not credit
    r'(?i)token(?!s\.txt|iz)|secret(?![-_ ]?scan)|credential|cred(?=s|_|-|\.|\b|(?-i:[A-Z]))'
    # password, but not a 1password folder
    r'|api[_-]?key|private[_-]?key|(?<!1)passw(?:or)?d|auth\.json'
    # .env as a file name (after a quote, slash or space), not process.env or self.env, and not .env.example
    r'|(?:^|(?<=[/\\\'"`\s{]))\.env\b(?![\w.-]*\.(?:example|sample|template|dist)\b)'
    # server.key and cert.pem end a file name ('a.key' as an attribute does not)
    r'|\.(?:pem|key)(?=["\'`]|$)|\.netrc|\.npmrc|\.pypirc|git-credentials')
# A quoted file name of a kind that never holds a key (code, logs, tables, locks): gh_app_token_shim.py,
# tokens.jsonl, .env.lock. It is taken out of a target before SECRET looks at it.
NOT_KEY_FILE = re.compile(r'''(["'`])[^"'`]*\.(?:py|js|mjs|cjs|ts|tsx|sh|bash|zsh|rb|go|rs|php|md|html?|css|log|jsonl'''
                          r'''|csv|tsv|lock|pid|sock)\1''')
# A function whose name says it writes a key (write_secret, save_token, refresh_creds): every write in it counts.
KEY_FUNC_VERB = re.compile(r'(?i)write|save|store|persist|dump|cache|install|mint|rotate|refresh|issue|exchange|put')
# Google credentials written as JSON (creds.to_json(), flow.credentials.to_json()): a key whatever the file name.
CREDS_JSON = re.compile(r'\b\w*cred\w*\.to_json\s*\(\s*\)')
# A key field written as data, whatever the file name: {"refresh_token": ...}, bearerToken: x, password=...
KEY_FIELD = re.compile(r'''(?i)(?<![\w.])["']?(?:(?:access|refresh|bearer|id|auth|session)_?token|client_?secret'''
                       r'''|private_?key|api_?key|password)["']?\s*(?::|=(?!=))''')
WINDOW = 25
CONSTANT = re.compile(r'[A-Z][A-Z0-9_]*')  # a top-level NAME = ... counts in the whole file, not only 25 lines
MARKER = re.compile(r'key-sav[e]:(.*)$')
MIN_REASON_WORDS = 3

# ---------- write constructs ----------
WRITE_MODE = re.compile(r'''^[rbuf]*["']([rwxabtU+]*[wax+][rwxabtU+]*)["']$''')
OPEN_FLAGS = re.compile(r'\bO_(?:CREAT|CREATE|WRONLY|RDWR|APPEND|TRUNC)\b')


def _mode_at(i):
    def cond(args):
        if len(args) > i and WRITE_MODE.match(args[i].strip()):
            return True
        return any(WRITE_MODE.match(re.sub(r'^mode\s*=\s*', '', a.strip()))
                   for a in args if a.strip().startswith('mode'))
    return cond


def _flags(args):
    return any(OPEN_FLAGS.search(a) for a in args[1:])


def _single(args):
    """Path.replace(target) / Path.rename(target): one plain argument (str.replace has two, kwargs are not paths)."""
    return (len(args) == 1 and re.match(r'^(?:\w+\s*=|[rbf]?["\'`/])', args[0].strip()) is None
            and '=>' not in args[0])


# (rule, call regex ending at its '(', target: arg index or 'recv' (the object before the dot), condition)
CALLS = [
    ('py-open', re.compile(r'(?:\b(?:io|codecs)\.|(?<![\w.]))open\s*\('), 0, _mode_at(1)),
    ('py-open', re.compile(r'(?<!\bos)(?<!\bio)(?<!\bcodecs)(?<!\bFile)\.open\s*\('), 'recv', _mode_at(0)),
    ('py-write-text', re.compile(r'\.write_(?:text|bytes)\s*\('), 'recv', None),
    ('os-open', re.compile(r'\bos\.open\s*\('), 0, _flags),
    ('copy-move', re.compile(r'\bshutil\.(?:copy|copyfile|copy2|move)\s*\('), 1, None),
    ('copy-move', re.compile(r'\bos\.(?:replace|rename)\s*\('), 1, None),
    ('copy-move', re.compile(r'(?<!\bos)\.(?:replace|rename)\s*\('), 0, _single),  # Path.replace(target)
    ('copy-move', re.compile(r'\bfs\w*\.(?:promises\.)?(?:copyFile|rename)(?:Sync)?\s*\('), 1, None),
    # fs.writeFile(path, ...) or an imported writeFile(path, ...); handle.writeFile(data) is a handle write
    ('js-write', re.compile(r'(?:(?<![\w$.])|\b(?i:\w*fs\w*|promises)\.)(?:writeFile|writeFileSync|appendFile'
                            r'|appendFileSync|createWriteStream)\s*\('), 0, None),
    ('js-write', re.compile(r'\bBun\.write\s*\(|\bDeno\.write(?:Text)?File(?:Sync)?\s*\('), 0, None),
    ('go-write', re.compile(r'\b(?:os|ioutil)\.WriteFile\s*\(|\bos\.Create\s*\('), 0, None),
    ('go-write', re.compile(r'\bos\.OpenFile\s*\('), 0, _flags),
    ('rb-write', re.compile(r'\b(?:File|IO)\.write\s*\('), 0, None),
    ('rb-write', re.compile(r'\bFile\.open\s*\('), 0, _mode_at(1)),
    ('php-write', re.compile(r'\bfile_put_contents\s*\('), 0, None),
    ('rs-write', re.compile(r'\b(?:std::)?fs::write\s*\(|\bFile::create\s*\('), 0, None),
]
# A cheap first look: a line that has none of these words cannot hold a write construct.
TRIGGER = re.compile(r'(?i)open|write|replace|rename|copy|move|create|file_put_contents|>|\btee\b'
                     r'|\b(?:cp|mv|install)\b')
# Writes through a handle opened for writing: f.write(...), json.dump(x, f), print(x, file=f).
HANDLE_WRITE = re.compile(r'\b(\w+)\.(?:write|writelines|Write|WriteString|puts|writeFile|appendFile)\s*\(')
DUMP = re.compile(r'\b(?:json|pickle|yaml|toml|tomli_w|tomlkit|marshal|plistlib)\.(?:safe_)?dump\s*\(|\bprint\s*\('
                  r'|\bshutil\.copyfileobj\s*\(')
FDOPEN = re.compile(r'\b(?:os\.)?fdopen\s*\(')
# Shell (shell scripts and YAML run blocks): > X, >> X, tee [-a] X, cp/mv/install ... X.
SH_TARGET = r'("[^"]*"|\'[^\']*\'|[^\s;&|<>()]+)'
SH_REDIRECT = re.compile(r'(?:^|(?<=[\s;&|)]))\d?&?>>?\|?(?![&(>])\s*' + SH_TARGET)
SH_TEE = re.compile(r'(?:^|[|;&(]|\$\()\s*(?:sudo\s+)?tee\s+((?:-\w+\s+)*)' + SH_TARGET)
SH_CMD = re.compile(r'(?:^|[;&|(]|\$\(|\b(?:then|do|else|sudo|exec)\s)\s*(cp|mv|install)\s+([^;&|)]*)')

RULE_TEXT = {
    'py-open': "Python open(X, 'w'/'a'/'x'/'+') or X.open('w') on a key path",
    'py-write-text': 'Python X.write_text(...) or X.write_bytes(...) on a key path',
    'os-open': 'os.open(X, O_CREAT/O_WRONLY/O_RDWR/O_APPEND/O_TRUNC) on a key path',
    'copy-move': 'shutil.copy/copyfile/copy2/move(..., X), os.replace/rename(tmp, X), Path.replace(X), '
                 'fs.copyFile/rename(..., X) onto a key path',
    'js-write': 'fs.writeFile(Sync), appendFile(Sync), fs.promises.writeFile, createWriteStream, Bun.write, '
                'Deno.writeTextFile/writeFile on a key path',
    'go-write': 'Go os.WriteFile, ioutil.WriteFile, os.Create, os.OpenFile(X, O_CREATE|...) on a key path',
    'rb-write': "Ruby File.write(X), IO.write(X), File.open(X, 'w') on a key path",
    'php-write': 'PHP file_put_contents(X) on a key path',
    'rs-write': 'Rust fs::write(X), File::create(X) on a key path',
    'file-handle': 'f.write(...), json.dump(..., f), print(..., file=f) where f was opened for writing on a key '
                   'path in the 25 lines before',
    'sh-redirect': 'shell > X or >> X onto a key path (shell scripts and YAML)',
    'sh-tee': 'shell tee [-a] X onto a key path',
    'sh-copy': 'shell cp/mv/install ... X onto a key path',
    'helper-write': "a call to this file's own write helper (a function that writes to its parameter) with a key "
                    'path as that argument',
    'google-creds-json': 'Google credentials JSON (creds.to_json()) written to any file',
    'key-field': 'a key field in the data written to any file: {"refresh_token": ...}, bearerToken: x, '
                 'password=..., client_secret, private_key, api_key',
}
MSG = ('writes a key to a file but this file never saves it to 1Password. Call the shared save step (op-<agent> '
       'save, or key_save.save in Python) right after the write, or mark a pure cache write with '
       '`key-save: <reason>`.')

# ---------- the save step (the file passes when it calls one, on a line that is not a comment) ----------
# Python module: `from key_save import save` (or `from x.key_save import ..., save`), `key_save.save(`, or
# `import key_save as ks` and `ks.save(`.
KS_FROM = re.compile(r'^\s*from\s+(?:[\w.]+\.)?key_sav[e]\s+import\s+(.*)$')
KS_IMPORT_AS = re.compile(r'^\s*import\s+(?:[\w.]+\.)?key_sav[e]\s+as\s+(\w+)')
KS_CALL = re.compile(r'\bkey_sav[e]\.save\s*\(')
# The CLI (key_save.py save, key-save save) and the helper (op-claude save, op-$AGENT save): the reference is followed
# right away by the save action, as the next shell word or the next item of an argv list.
KS_REF = r'(?i:\bkey[_-]sav[e]\w*(?:\.py)?)'
OP_REF = r'(?:(?<![\w-])op-(?:[a-z][a-z0-9]*(?:-[a-z0-9]+)*|\$\{?\w+\}?|\{\w+\}))'
OP_CONCAT = r'''(?:["']op-["']\s*\+\s*[\w.]+)'''
ARGV_SAVE = r'''(?:["'`]|\))*\s*,\s*\[?\s*["'`]sav[e]["'`]'''
WORD_SAVE = r'''["'`]?\s+sav[e](?![\w-])'''
SH_START = r'(?:^|[|;&(]|\$\(|\b(?:then|do|else|exec|command|sudo|xargs|env)\s)\s*(?:\w+=\S*\s+)*'

MAX_LINE = 5000  # a longer line is minified code or data: not read
COMMENT = re.compile(r'^\s*(?:#(?!!)|//|/\*|\*(?:\s|$)|<!--)')
ASSIGN = re.compile(r'^\s*(?:export\s+|local\s+|const\s+|let\s+|var\s+|readonly\s+|declare\s+(?:-\w+\s+)?)?'
                    r'(?:self\.|this\.)?([A-Za-z_]\w*)(?:\s*,\s*\w+)*\s*(?::\s*[\w\[\], .|]+?)?\s*'
                    r'(?::=|=(?!=)|:(?!:))\s*(.*)$')
DEF = {
    'py': re.compile(r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\((.*)'),
    'rb': re.compile(r'^(\s*)def\s+(?:self\.)?(\w+[?!]?)\s*\(?(.*)'),
    'js': re.compile(r'^(\s*)(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\s*\*?\s*(\w+)\s*\((.*)'
                     r'|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?'
                     r'(?:function\b[^(]*\((.*)|\(([^)]*)\)\s*=>|(\w+)\s*=>)'
                     r'|(?:static\s+|private\s+|public\s+|protected\s+)*(?!(?:if|for|while|switch|catch|return)\b)'
                     r'(\w+)\s*\(([^)]*)\)\s*(?::\s*[^{]+)?\{\s*$)'),
    'go': re.compile(r'^(\s*)func\s+(?:\([^)]*\)\s*)?(\w+)\s*\((.*)'),
    'sh': re.compile(r'^(\s*)(?:function\s+([\w-]+)\s*(?:\(\s*\))?|([\w-]+)\s*\(\s*\))\s*\{?'),
}

CODE_EXT = {'.py', '.sh', '.bash', '.zsh', '.ksh', '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.tsx', '.jsx',
            '.yml', '.yaml', '.rb', '.go', '.rs', '.swift', '.ps1', '.php', '.java', '.kt', '.command', '.vue',
            '.svelte'}
LANG_EXT = {'.py': 'py', '.sh': 'sh', '.bash': 'sh', '.zsh': 'sh', '.ksh': 'sh', '.command': 'sh', '.yml': 'yaml',
            '.yaml': 'yaml', '.rb': 'rb', '.go': 'go', '.rs': 'rs', '.php': 'php', '.ps1': 'ps1'}
HASH_COMMENT = {'py', 'sh', 'yaml', 'rb', 'ps1'}
SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'site-packages',
             'tests', 'test', '__tests__', 'fixtures', 'testdata', '__fixtures__', 'key-save'}
# Build output and vendored code only at the top: a folder named build deeper down is our own code.
ROOT_SKIP_DIRS = {'dist', 'build', 'vendor'}
# This check's own copy, and the save step itself (key_save.py writes the caches it restores from 1Password).
SELF_NAMES = {'key_save_check.py', 'key_save.py'}


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


def language(path, text=''):
    ext = os.path.splitext(path)[1].lower()
    if ext:
        return LANG_EXT.get(ext, 'js')
    first = text.split('\n', 1)[0]
    if re.search(r'python', first):
        return 'py'
    if re.search(r'\b(?:node|deno|bun)\b', first):
        return 'js'
    if re.search(r'ruby', first):
        return 'rb'
    return 'sh'


def marker_ok(line):
    """(has marker, reason long enough)."""
    m = MARKER.search(line)
    if not m:
        return False, False
    reason = re.sub(r'(?:\*/|-->|[*/#>\-])+\s*$', '', m.group(1)).strip()
    return True, len(reason.split()) >= MIN_REASON_WORDS


def strip_comment(line, lang):
    """The line without a trailing comment (# or //, after a space, outside quotes)."""
    quote, i = None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == '\\':
                i += 1
            elif ch == quote:
                quote = None
        elif ch in '"\'`':
            quote = ch
        elif i and line[i - 1] in ' \t':
            if lang in HASH_COMMENT and ch == '#':
                return line[:i].rstrip()
            if lang not in HASH_COMMENT and line.startswith('//', i):
                return line[:i].rstrip()
        i += 1
    return line


def code_lines(text, lang):
    """The file's lines with comment lines blanked, trailing comments cut and Python docstrings blanked."""
    out, doc = [], None
    for line in text.splitlines():
        s = line.strip()
        if doc:
            out.append('')
            if doc in s:
                doc = None
            continue
        if lang == 'py':
            m = re.match(r'^[rRuUbB]?("""|\'\'\')', s)
            if m and s.count(m.group(1)) == 1:
                doc = m.group(1)
                out.append('')
                continue
            if m and s.endswith(m.group(1)):
                out.append('')
                continue
        out.append('' if COMMENT.match(line) or len(line) > MAX_LINE else strip_comment(line, lang))
    return out


def _depth(s):
    """Open brackets minus closed ones, outside quotes."""
    d, quote, i = 0, None, 0
    while i < len(s):
        ch = s[i]
        if quote:
            if ch == '\\':
                i += 1
            elif ch == quote:
                quote = None
        elif ch in '"\'`':
            quote = ch
        elif ch in '([{':
            d += 1
        elif ch in ')]}':
            d -= 1
        i += 1
    return d


def statement(lines, i, most=8):
    """Line i joined with the lines after it until its brackets close (at most `most` lines)."""
    text, j = lines[i], i
    while _depth(text) > 0 and j + 1 < len(lines) and j - i < most:
        j += 1
        text += ' ' + lines[j].strip()
    return text


def split_args(s, start):
    """The top-level arguments of the call whose '(' is at s[start]."""
    args, cur, depth, quote, i = [], [], 0, None, start + 1
    while i < len(s):
        ch = s[i]
        if quote:
            cur.append(ch)
            if ch == '\\' and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in '"\'`':
            quote = ch
            cur.append(ch)
        elif ch in '([{':
            depth += 1
            cur.append(ch)
        elif ch in ')]}':
            if depth == 0:
                break
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            args.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    last = ''.join(cur).strip()
    if last:
        args.append(last)
    return args


def receiver(s, dot):
    """The expression before s[dot] ('.'): a name, attribute chain or call, such as TOKEN_PATH, self.p, f(x)."""
    i = dot - 1
    while i >= 0:
        ch = s[i]
        if ch in ')]':
            depth = 0
            while i >= 0:
                if s[i] in ')]':
                    depth += 1
                elif s[i] in '([':
                    depth -= 1
                    if depth == 0:
                        break
                i -= 1
            i -= 1
        elif ch.isalnum() or ch in '_.$':
            i -= 1
        else:
            break
    return s[i + 1:dot]


def writes(stmt, lang, first=None):
    """[(rule, target text, data text)] for each write construct that starts in the first `first` characters of a
    statement (its own line; the arguments may go on over the next lines)."""
    first = len(stmt) if first is None else first
    out = []
    for rule, rx, where, cond in CALLS:
        if cond is _single and lang not in ('py', 'yaml'):
            continue  # Path.replace(target) is Python; a one-argument .replace() elsewhere is not a file move
        for m in rx.finditer(stmt):
            if m.start() >= first:
                continue
            args = split_args(stmt, m.end() - 1)
            if cond and not cond(args):
                continue
            if where == 'recv':
                target, data = receiver(stmt, stmt.rfind('.', m.start(), m.end())), args
            else:
                target = args[where] if len(args) > where else ''
                data = args[:where] + args[where + 1:]
            if target:
                out.append((rule, target, ' '.join(data)))
    if lang in ('sh', 'yaml'):
        line = stmt[:first]
        for m in SH_REDIRECT.finditer(line):
            out.append(('sh-redirect', m.group(1), line[:m.start()]))
        for m in SH_TEE.finditer(line):
            out.append(('sh-tee', m.group(2), line[:m.start()]))
        for m in SH_CMD.finditer(line):
            words = [w for w in re.findall(r'"[^"]*"|\'[^\']*\'|[^\s>]+', m.group(2)) if not w.startswith('-')]
            if len(words) >= 2:
                out.append(('sh-copy', words[-1], ''))
    return out


def mask_strings(text):
    """The text with each string literal blanked, but a quoted name kept ("refresh_token"): a key field written as
    data is code ({"refresh_token": x}, bearerToken: x), not words inside a string (a script's 'password=...')."""
    def keep(m):
        return m.group(0) if re.fullmatch(r'[\w-]+', m.group(2)) else m.group(1) + ' ' * len(m.group(2)) + m.group(1)
    return re.sub(r'(["\'`])((?:\\.|(?!\1).)*)\1', keep, text)


def looks_key(text):
    """True when a target or an assigned value names a key store (file names that never hold a key taken out)."""
    return SECRET.search(text) is not None and SECRET.search(NOT_KEY_FILE.sub('', text)) is not None


def key_function(name):
    return bool(name) and looks_key(name) and KEY_FUNC_VERB.search(name) is not None


def _names_in(text, names):
    """The first name from `names` used as a whole word in text, or None."""
    for name in names:
        if name in text and re.search(r'(?<![\w.])\$?\{?' + re.escape(name) + r'\b', text):
            return name
    return None


def _params(text):
    """Parameter names from the text after a function's '('."""
    inner = split_args('(' + text, 0)
    names = []
    for a in inner:
        m = re.match(r'^\s*\*{0,2}&?\s*(?:(?:const|let|var|mut)\s+)?([A-Za-z_]\w*)', a)
        if m and m.group(1) not in ('self', 'cls'):
            names.append(m.group(1))
    return names


def functions(lines, lang):
    """{line index: (name, params, last line index)} for each function header."""
    rx = DEF.get('js' if lang in ('js', 'php', 'rs') else 'py' if lang == 'yaml' else lang, DEF['js'])
    out = {}
    for i, line in enumerate(lines):
        m = rx.match(line)
        if not m:
            continue
        groups = [g for g in m.groups()[1:] if g is not None]
        if not groups:
            continue
        name = groups[0]
        if name in ('if', 'for', 'while', 'switch', 'catch', 'return', 'function'):
            continue
        stmt = statement(lines, i)
        params = _params(stmt.split('(', 1)[1]) if '(' in stmt else []
        indent = len(m.group(1))
        if lang == 'py':
            end = i + 1
            while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) > indent):
                end += 1
            end -= 1
        else:
            end = min(len(lines) - 1, i + 60)
        out[i] = (name, params, end)
    return out


def findings(text, path=''):
    """[(line number, rule, message)] for one file's text; [] when the file calls the save step."""
    lang = language(path, text)
    lines = code_lines(text, lang)
    if saves(lines):
        return []
    return raw_findings(text, path, lines, lang)


def raw_findings(text, path='', lines=None, lang=None):
    """Every write of a key in the file, whether or not it saves (markers applied)."""
    lang = lang or language(path, text)
    lines = lines if lines is not None else code_lines(text, lang)
    raw = text.splitlines()
    funcs = functions(lines, lang)
    stmts, cache = {}, {}

    def stmt_at(k):
        if k not in stmts:
            stmts[k] = statement(lines, k)
        return stmts[k]

    def writes_at(k):
        if k not in cache:
            cache[k] = writes(stmt_at(k), lang, len(lines[k])) if TRIGGER.search(lines[k]) else []
        return cache[k]

    # The function each line sits in (Python: by indentation; other languages: the nearest header, 60 lines).
    owner = {}
    for i, (name, _params_, end) in sorted(funcs.items()):
        for k in range(i + 1, end + 1):
            owner[k] = name
    # This file's own write helpers: functions that write to one of their parameters (or a name set from it).
    helpers = {}
    for i, (name, params, end) in funcs.items():
        derived = {p: n for n, p in enumerate(params)}
        for k in range(i, end + 1):  # the header line too: a one-line helper (const w = (p, d) => writeFile(p, d))
            a = ASSIGN.match(lines[k])
            if a and a.group(1) not in derived:
                src = _names_in(a.group(2), list(derived))
                if src:
                    derived[a.group(1)] = derived[src]
            for _rule, target, _data in writes_at(k):
                hit = _names_in(target, list(derived))
                if hit:
                    helpers.setdefault(name, derived[hit])
    key_vars, content_vars, handles, constants, out = {}, {}, {}, set(), []
    helper_rx = re.compile(r'\b(?:' + '|'.join(re.escape(h) for h in helpers) + r')\s*\(') if helpers else None

    def key_target(target, n):
        """Why the target is a key store: '' (it is not), 'name', or 'via NAME, set on line N'."""
        if looks_key(target):
            return 'name'
        for name, at in key_vars.items():
            if (name in constants or n - at <= WINDOW) and _names_in(target, [name]):
                return f'via {name}, set on line {at}'
        return ''

    def key_data(data, n):
        """Why the data written is a key whatever the file: Google credentials JSON, or a key field."""
        if CREDS_JSON.search(data) or _names_in(data, [v for v, at in content_vars.items() if n - at <= WINDOW]):
            return 'google-creds-json', 'Google credentials JSON'
        if KEY_FIELD.search(mask_strings(data)):
            return 'key-field', 'a key field in the data'
        return None

    def add(n, rule, why):
        has, ok = marker_ok(raw[n - 1] if n - 1 < len(raw) else '')
        has_above, ok_above = marker_ok(raw[n - 2] if n >= 2 else '')
        if ok or ok_above:
            return
        msg = MSG + (f' ({why})' if why != 'name' else '')
        if has or has_above:
            msg += f' (the key-save marker needs a reason of {MIN_REASON_WORDS}+ words)'
        out.append((n, rule, msg))

    for i, line in enumerate(lines):
        n = i + 1
        if not line.strip():
            continue
        a = ASSIGN.match(line)
        in_key_func = key_function(owner.get(i))
        found = None
        here = writes_at(i)
        for rule, target, data in here:
            why = key_target(target, n) or (in_key_func and f'in function {owner[i]}')
            if why:
                found = (rule, why)
            else:
                found = key_data(data, n)
            if found:
                break
        # A handle opened for writing: remember it (key store or not) for f.write / json.dump below.
        fd = FDOPEN.search(line) if 'fdopen' in line else None
        opens = fd or any(r in ('py-open', 'os-open', 'go-write', 'rb-write', 'js-write') for r, _t, _d in here)
        stmt = stmt_at(i) if opens else line
        hm = opens and (re.search(r'\bas\s+(\w+)\s*[:,)]|\|\s*(\w+)\s*\|', stmt)
                        or (a and re.match(r'(\w+)', a.group(1))))
        if hm:
            is_key = bool(found and found[0] not in ('google-creds-json', 'key-field'))
            src = split_args(stmt, fd.end() - 1) if fd else []
            if src and src[0] in handles and handles[src[0]][1]:
                is_key = True
            handles[next(g for g in hm.groups() if g)] = (n, is_key)
        live = {h: v for h, v in handles.items() if 0 < n - v[0] <= WINDOW} if handles and not found else {}
        if live:
            stmt = stmt_at(i)
            used, data = None, ''
            m = HANDLE_WRITE.search(line)
            if m and m.group(1) in live:
                used, data = m.group(1), ' '.join(split_args(stmt, m.end() - 1))
            else:
                for d in (d for d in DUMP.finditer(stmt) if d.start() < len(line)):
                    args = split_args(stmt, d.end() - 1)
                    is_print = d.group(0).startswith('print')
                    for arg in args if is_print else args[1:]:
                        name = re.sub(r'^(?:file|fp|stream)\s*=\s*', '', arg.strip())
                        if name in live and (not is_print or arg.strip().startswith('file')):
                            used, data = name, ' '.join(args)
            if used:
                if live[used][1]:
                    found = ('file-handle', f'via {used}, opened on line {live[used][0]}')
                elif in_key_func:
                    found = ('file-handle', f'in function {owner[i]}')
                else:
                    found = key_data(data, n)
        if not found and helper_rx and helper_rx.search(line):
            stmt = stmt_at(i)
            for name, index in helpers.items():
                if funcs.get(i) and funcs[i][0] == name:
                    continue
                for m in re.finditer(r'(?:(?<![\w.])|\b(?:self|this|cls)\.)' + re.escape(name) + r'\s*\(', stmt):
                    args = split_args(stmt, m.end() - 1)
                    if len(args) > index and not args[index].startswith(('{', '[')) and key_target(args[index], n):
                        found = ('helper-write', f'through {name}()')
                        break
                if found:
                    break
        if found:
            add(n, found[0], found[1])
        if a:
            if looks_key(a.group(2)):
                key_vars[a.group(1)] = n
                if not line[:1].isspace() and CONSTANT.fullmatch(a.group(1)):
                    constants.add(a.group(1))
            if 'to_json' in ' '.join(lines[i:i + 8]):
                if CREDS_JSON.search(stmt_at(i)):
                    content_vars[a.group(1)] = n
    return sorted(out, key=lambda f: f[0])


def saves(lines):
    """True when the file calls the shared save step on a line that is not a comment."""
    low = [ln.lower() for ln in lines]
    near = [i for i, ln in enumerate(low) if 'save' in ln]
    if not near:
        return False
    op_vars, ks_vars, aliases = set(), set(), set()
    for line, lo in zip(lines, low):
        if 'op-' not in lo and 'key' not in lo:
            continue
        a = ASSIGN.match(line)
        if a:
            if re.search(OP_REF, a.group(2)) or re.search(OP_CONCAT, a.group(2)):
                op_vars.add(a.group(1))
            if re.search(KS_REF, a.group(2)):
                ks_vars.add(a.group(1))
        m = KS_IMPORT_AS.match(line)
        if m:
            aliases.add(m.group(1))
    op_names = '|'.join(re.escape(v) for v in sorted(op_vars)) or r'(?!)'
    ks_names = '|'.join(re.escape(v) for v in sorted(ks_vars)) or r'(?!)'
    op_any = rf'(?:{OP_REF}|{OP_CONCAT}|(?<![\w.]){op_names}\b|(?i:\bop_?helper\w*))'
    ks_any = rf'(?:{KS_REF}|(?<![\w.]){ks_names}\b)'
    argv = re.compile(rf'(?:{op_any}|{ks_any}){ARGV_SAVE}')
    shell = re.compile(rf'{SH_START}["\']?(?:[\w./~${{}}-]*/)?(?:{OP_REF}|\$\{{?(?:{op_names})\}}?){WORD_SAVE}')
    string_cmd = re.compile(rf'(?:[(=,\[]|\brun\s)\s*f?["\'`](?:[\w./~${{}}-]*/)?{OP_REF}\s+sav[e](?![\w-])')
    ks_word = re.compile(rf'{KS_REF}{WORD_SAVE}')
    alias_call = re.compile(r'(?<![\w.])(?:' + '|'.join(re.escape(x) for x in aliases) + r')\.save\s*\(') \
        if aliases else None
    # Only lines with "save" on them or in the next few lines (an argv list may put 'save' on the next line).
    todo = sorted({k for i in near for k in range(max(0, i - 8), i + 1)})
    for i in todo:
        line = lines[i]
        if not line.strip():
            continue
        stmt = statement(lines, i)
        if 'save' not in stmt.lower():
            continue
        m = KS_FROM.match(line)
        if m and re.search(r'(?<![\w.])save\b(?!\s*\.)', stmt.split('import', 1)[1]):
            return True
        if KS_CALL.search(line) or (alias_call and alias_call.search(line)):
            return True
        if argv.search(stmt) or shell.search(line) or string_cmd.search(line) or ks_word.search(line):
            return True
    return False


# ---------- files, git and the command line (the same shape as plan-login-check) ----------

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
    """{path: {added line numbers}} for the change from base (base...HEAD), files that still exist only. A file the
    change only deletes lines from is listed with no lines (so a removed save step is seen)."""
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
    """(first 2 bytes, text) of a file on disk or at a revision; (None, None) when missing or binary."""
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


def file_saves(path, text):
    lang = language(path, text)
    return saves(code_lines(text, lang))


def scan(repo, paths, only=None, base_rev=None):
    """[(path, line, rule, message)]; only = {path: lines} keeps the findings on those lines, plus every finding in
    a file whose save step the change removed (it saved at base_rev and no longer does)."""
    out = []
    for path in paths:
        if only is not None and path not in only:
            continue
        if not is_code(path, b'#!'):  # cheap name test first; the shebang is checked after reading
            continue
        head, text = read(repo, path, 'HEAD' if only is not None else None)
        if text is None or not is_code(path, head):
            continue
        hits = findings(text, path)
        if not hits:
            continue
        old = read(repo, path, base_rev)[1] if only is not None and base_rev else None
        removed = old is not None and file_saves(path, old)
        for n, rule, msg in hits:
            if only is None or removed or n in only.get(path, ()):
                out.append((path, n, rule, msg + (' (this change removed its save step)' if removed else '')))
    return out


def markers(repo, only):
    """[(path, line, reason)] for every key-save marker on an added line of a code file, so each exception shows
    in the check's output for the reviewer."""
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
                out.append((path, n, re.sub(r'(?:\*/|-->|[*/#>\-])+\s*$', '', m.group(1)).strip()[:200]))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog='key-save-check', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='*')
    ap.add_argument('--repo', default='.')
    ap.add_argument('--base', default='', help='only lines added since this ref (REF...HEAD)')
    ap.add_argument('--github', action='store_true')
    ap.add_argument('--list-rules', action='store_true')
    a = ap.parse_args(argv)
    if a.list_rules:
        for rule, text in RULE_TEXT.items():
            print(f'{rule}: {text}')
        print('A key path: a path or name matching token, secret, credential, cred(s), api key, private key, password, '
              'auth.json, .env, .pem, .key, .netrc, .npmrc, .pypirc or git-credentials (on the line, through a '
              f'variable set in the {WINDOW} lines before or a top-level constant), or any write inside a function '
              'whose name says it writes a key (write_secret, save_token).')
        return 0
    try:
        repo = git(os.path.abspath(a.repo), 'rev-parse', '--show-toplevel').strip()
        only = added_lines(repo, a.base) if a.base else None
        base_rev = git(repo, 'merge-base', a.base, 'HEAD').strip() if a.base else None
        paths = a.files or (sorted(only) if only is not None else all_files(repo))
        hits = scan(repo, paths, only, base_rev)
        marks = markers(repo, only) if only is not None else []
    except (RuntimeError, OSError) as e:
        print(f'key-save-check: could not run: {e}', file=sys.stderr)
        return 2
    for path, n, rule, msg in hits:
        print(f'{path}:{n} {msg} [{rule}]')
        if a.github:
            print(f'::error file={path},line={n},title=Key not saved to 1Password ({rule})::{msg}')
    for path, n, reason in marks:
        print(f'{path}:{n}: key-save marker added: {reason}')
        if a.github:
            print(f'::notice file={path},line={n},title=key-save exception added::{reason}')
    if hits:
        print(f'\nkey-save-check: {len(hits)} finding(s). Rule: a key written to a file is also saved to 1Password '
              'with the shared save step (op-<agent> save, or key_save.save). For a pure cache write put '
              f'`key-save: <reason, {MIN_REASON_WORDS}+ words>` on that line or the line above. scripts/key-save/'
              'README.md in nuey-skills.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
