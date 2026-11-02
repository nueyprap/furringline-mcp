#!/usr/bin/env python3
"""Secret scan: TruffleHog OSS on what a commit, push or pull request adds (Narathip, 2026-11-01).

Decision: record topic security, c9b4d14b. TruffleHog checks whether a found key is live. On a push or
pull request a verified (live) or unknown (could not confirm) result fails; an unverified one (a pattern
the provider says is dead) passes. On a commit (record security-13ee2b, 2026-11-02) every hit fails,
verified or not, so no key enters even local history. It runs inside the shared checks every change
already passes: the pre-commit and pre-push hook blocks in `.githooks/` and a step of the required `jev`
job in `jev-gate.yml`. Installed into each repo as `.jev/secret_scan.py` by `scripts/jev-gate/install.py`
in nuey-skills (source: `scripts/secret-scan/`).

  python3 .jev/secret_scan.py --staged                              # git pre-commit: the staged files
  python3 .jev/secret_scan.py --pre-push [--remote origin] < refs   # git pre-push: what the push adds
  python3 .jev/secret_scan.py --base origin/main [--github]         # CI: what the pull request adds
  python3 .jev/secret_scan.py --full [--report out.json]            # every commit on every branch
  python3 .jev/secret_scan.py --install                             # put the pinned binary in place
  python3 .jev/secret_scan.py --version                             # the pinned version

Never prints a secret: a finding shows the detector, verified or unknown, file, line, commit and a
fingerprint (a short hash of the detector and the value, for the allow list). TruffleHog's own
`trufflehog:ignore` comments are switched off (`--no-ignore-tag`); the only exception path is the
reviewed allow list `.jev/secret-scan-allow.json`:

  {"allow": [{"fingerprint": "<16 hex>", "reason": "test fixture, not a real key"},
             {"path": "^tests/fixtures/", "reason": "fake keys used by the parser tests"}]}

An entry needs a reason of 3 or more words. An entry covers unknown results only; a verified (live) key
is a real leak to rotate, so it needs `"live_public": true` as well (a key that is public on purpose,
such as a browser key locked to one site). A change to the list is a change under `.jev/`, so main's
second reviewer reads it (checks-from-main). Every entry used is printed. The commit scan reads the list
from the index (the version being committed), the push and CI scans from the commit they test.

`--staged` copies the staged version of each added or changed file (its blob, so no filter or LFS
download runs) into a private temp folder and runs `trufflehog filesystem` on it: `trufflehog git` has
no staged option. The temp folder is removed afterwards.

Exit 0 clean (or nothing to scan), 1 a finding, 2 the scan could not run (the caller refuses).
Standard library only; Python 3.9+.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

PIN_VERSION = "3.99.7"
# sha256 of each release tarball, from trufflehog_3.99.7_checksums.txt (release v3.99.7, 2026-10-24).
PIN_SHA256 = {
    "darwin_arm64": "5540ef352fc88b1f580e91603689782c0107ca7d4a96c1aeb2714b3a98c766ce",
    "darwin_amd64": "6bdbc7b0aaeefcb50275036b49be1a3561b3c2e5902879300339abf9c64914c0",
    "linux_amd64": "bdbea0508e439b144f49de14e775908de5f902f3d14ea7ae8354bae72b0b72ef",
    "linux_arm64": "3060f7c9f18c70afdc432984cacabdd1e9103729b5d5fee7fb6755a90d1c59d4",
}
URL = "https://github.com/trufflesecurity/trufflehog/releases/download/v{v}/trufflehog_{v}_{plat}.tar.gz"
ALLOW_FILE = ".jev/secret-scan-allow.json"
ZERO = "0" * 40
SCAN_TIMEOUT = 600
FAIL_EXIT = 183  # trufflehog --fail exit code when results are found
NAME = "secret-scan"
VERSION_STAMP = ".version-checked"  # next to our pinned binary: "<size> <mtime_ns> <version>" of the last check


def say(msg):
    print(f"{NAME}: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- binary


def platform_key():
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    key = f"{system}_{arch}"
    return key if key in PIN_SHA256 else None


def install_dir():
    base = os.environ.get("SECRET_SCAN_HOME")
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".local", "share", "secret-scan")
    return Path(base) / f"trufflehog-{PIN_VERSION}"


def binary_version(path):
    try:
        out = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"trufflehog\s+v?(\d+\.\d+\.\d+)", (out.stdout or "") + (out.stderr or ""))
    return m.group(1) if m else None


def _stat_key(path):
    st = os.stat(path)
    return f"{st.st_size} {st.st_mtime_ns}"


def pinned_version_ok(path):
    """binary_version(path) == PIN_VERSION, remembered for our own install path while the file is unchanged.

    `trufflehog --version` costs about half a second, and the commit scan runs on every commit (target under
    2 s). The stamp holds the binary's size and mtime, so a replaced or touched binary is checked again."""
    stamp = Path(path).parent / VERSION_STAMP
    ours = Path(path).parent == install_dir()
    try:
        key = _stat_key(path)
        if ours and stamp.read_text(encoding="utf-8").strip() == f"{key} {PIN_VERSION}":
            return True
    except OSError:
        pass
    if binary_version(path) != PIN_VERSION:
        return False
    if ours:
        try:
            stamp.write_text(f"{key} {PIN_VERSION}\n", encoding="utf-8")
        except OSError:
            pass
    return True


def find_binary():
    """The pinned trufflehog, or None. $TRUFFLEHOG_BIN wins (tests, CI); any other must match the pin."""
    env = os.environ.get("TRUFFLEHOG_BIN")
    if env:
        return env if os.access(env, os.X_OK) else None
    candidates = [install_dir() / "trufflehog"]
    on_path = shutil.which("trufflehog")
    if on_path:
        candidates.append(Path(on_path))
    for cand in candidates:
        if cand.is_file() and os.access(cand, os.X_OK) and pinned_version_ok(cand):
            return str(cand)
    return None


def download(url, dest, timeout=300):
    req = urllib.request.Request(url, headers={"User-Agent": f"nuey-secret-scan/{PIN_VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as out:  # noqa: S310 (fixed https URL)
        shutil.copyfileobj(resp, out)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def install_binary(fetch=download):
    """Download the pinned release, check its sha256, unpack only `trufflehog`. Returns the path."""
    plat = platform_key()
    if not plat:
        raise RuntimeError(f"no pinned TruffleHog build for {platform.system()} {platform.machine()}")
    target_dir = install_dir()
    target = target_dir / "trufflehog"
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(target_dir.parent), prefix=".dl-") as tmp:
        tarball = os.path.join(tmp, "th.tar.gz")
        fetch(URL.format(v=PIN_VERSION, plat=plat), tarball)
        got = sha256_file(tarball)
        if got != PIN_SHA256[plat]:
            raise RuntimeError(f"TruffleHog download checksum mismatch for {plat} (got {got[:12]}...); not installed")
        with tarfile.open(tarball, "r:gz") as tar:
            member = next((m for m in tar.getmembers() if m.name in ("trufflehog", "./trufflehog")), None)
            if member is None or not member.isfile():
                raise RuntimeError("TruffleHog tarball has no trufflehog binary")
            src = tar.extractfile(member)
            staged = os.path.join(tmp, "trufflehog")
            with open(staged, "wb") as out:
                shutil.copyfileobj(src, out)
        os.chmod(staged, 0o755)
        target_dir.mkdir(parents=True, exist_ok=True)
        os.replace(staged, target)
    return str(target)


def ensure_binary():
    found = find_binary()
    if found:
        return found
    if os.environ.get("TRUFFLEHOG_BIN"):
        raise RuntimeError(f"TRUFFLEHOG_BIN={os.environ['TRUFFLEHOG_BIN']} is not an executable file")
    say(f"installing pinned TruffleHog {PIN_VERSION} (one time, checksum-checked) ...")
    path = install_binary()
    if binary_version(path) != PIN_VERSION:
        raise RuntimeError(f"installed TruffleHog at {path} does not report version {PIN_VERSION}")
    return path


# --------------------------------------------------------------------------- git


def git(repo, *args, check=True):
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {out.stderr.strip()[:300]}")
    return out.stdout.strip() if out.returncode == 0 else None


def is_commit(repo, sha):
    return bool(sha) and git(repo, "cat-file", "-e", f"{sha}^{{commit}}", check=False) is not None


def default_branch_ref(repo, remote):
    head = git(repo, "symbolic-ref", "-q", f"refs/remotes/{remote}/HEAD", check=False)
    if head:
        return head
    for name in ("main", "master"):
        ref = f"refs/remotes/{remote}/{name}"
        if git(repo, "rev-parse", "-q", "--verify", ref, check=False):
            return ref
    return None


def rev_list(repo, head, exclude):
    out = git(repo, "rev-list", head, "--not", *exclude) if exclude else git(repo, "rev-list", head)
    return [line for line in (out or "").splitlines() if line]


def push_ranges(repo, refs_text, remote="origin"):
    """[(since or None, head sha, set of added commits)] for a pre-push stdin. Only commits on no remote ref."""
    ranges = []
    default = default_branch_ref(repo, remote)
    for line in refs_text.splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        _lref, lsha, _rref, rsha = parts
        if not lsha.strip("0") or not is_commit(repo, lsha):
            continue  # a delete, or a tag to a non-commit
        added = set(rev_list(repo, lsha, ["--remotes"]))
        if not added:
            continue
        since = None
        if rsha.strip("0") and is_commit(repo, rsha):
            since = rsha
        elif default:
            since = git(repo, "merge-base", lsha, default, check=False)
        ranges.append((since, lsha, added))
    return ranges


def ci_range(repo, base):
    if not git(repo, "rev-parse", "-q", "--verify", f"{base}^{{commit}}", check=False):
        raise RuntimeError(f"unknown base {base!r} (fetch it, or use actions/checkout with fetch-depth: 0)")
    head = git(repo, "rev-parse", "HEAD")
    since = git(repo, "merge-base", base, head, check=False)
    added = set(rev_list(repo, head, [base]))
    return since, head, added


# --------------------------------------------------------------------------- scan


def fingerprint(detector, raw):
    return hashlib.sha256(f"{detector}\0{raw}".encode("utf-8", "replace")).hexdigest()[:16]


def parse_findings(stdout, base_dir=None, all_results=False):
    """Safe finding dicts from TruffleHog JSON lines. The raw value is used only for the fingerprint.

    Status: verified (live), unknown (the live check failed, VerificationError) or unverified (the provider
    says it is not live). git mode asks only for verified and unknown, so there anything not verified is
    unknown; the commit scan asks for all three (all_results). base_dir: filesystem mode's scanned folder, cut from each file path (staged files are copied there)."""
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict) or "DetectorName" not in d:
            continue
        data = ((d.get("SourceMetadata") or {}).get("Data") or {})
        meta = data.get("Git") or data.get("Filesystem") or {}
        detector = str(d.get("DetectorName") or "unknown-detector")
        raw = d.get("RawV2") or d.get("Raw") or ""
        file = str(meta.get("file") or "")
        if base_dir and file:
            file = os.path.relpath(os.path.realpath(file), os.path.realpath(base_dir))
        findings.append({
            "detector": detector,
            "status": ("verified" if d.get("Verified") else
                       "unknown" if d.get("VerificationError") or not all_results else "unverified"),
            "file": file,
            "line": int(meta.get("line") or 0),
            "commit": str(meta.get("commit") or ""),
            "fingerprint": fingerprint(detector, raw),
        })
    return findings


def scan_cmd(binary, repo, since=None, head=None):
    cmd = [binary, "git", f"file://{Path(repo).resolve()}", "--json", "--no-update", "--no-ignore-tag",
           "--results=verified,unknown", "--fail", "--fail-on-scan-errors"]
    if since:
        cmd.append(f"--since-commit={since}")
    if head:
        cmd.append(f"--branch={head}")
    return cmd


def logged_errors(stderr, skip_paths=None):
    """TruffleHog's error-level log messages (its log never holds a found value; cut to 200 characters).

    skip_paths(path) -> True drops an error about a file the scanned range does not change. On a ref whose
    history shares nothing with the clone's default branch (the agent-locks ref), TruffleHog also tries the
    binary files of that branch with no commit and logs an error for each (2026-11-02); those files are not
    part of what the push adds. An error with no path is always kept."""
    msgs = []
    for line in (stderr or "").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and str(rec.get("level", "")).startswith("error"):
            path = rec.get("path")
            if path and skip_paths and skip_paths(str(path)):
                continue
            msgs.append(str(rec.get("msg", "error"))[:200])
    return msgs


def changed_paths(repo, since, head):
    """Files touched by any commit between since and head (not only the net diff, so a file added and then
    removed in the range still counts), or None when that cannot be read (then nothing is skipped)."""
    try:
        # -z: raw names, so a non-ASCII or quoted name matches the plain path TruffleHog logs.
        out = git(repo, "log", "-z", "--format=", "--name-only", "--no-renames", "-m", f"{since}..{head}")
    except Exception:
        return None
    return set(x.strip("\n") for x in (out or "").split("\0") if x.strip("\n"))


def scanned_bytes(stderr):
    """Bytes TruffleHog says it read (its "finished scanning" log line), or None when it did not say."""
    for line in (stderr or "").splitlines()[::-1]:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("msg") == "finished scanning" and "bytes" in rec:
            try:
                return int(rec["bytes"])
            except (TypeError, ValueError):
                return None
    return None


def added_lines(repo, since, head):
    """Text lines added between since and head (binary files count 0)."""
    out = git(repo, "diff", "--numstat", since, head, check=False) if since else None
    total = 0
    for line in (out or "").splitlines():
        first = line.split("\t", 1)[0]
        if first.isdigit():
            total += int(first)
    return total


def run_trufflehog(binary, repo, since=None, head=None, timeout=SCAN_TIMEOUT):
    try:
        out = subprocess.run(scan_cmd(binary, repo, since, head), capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"TruffleHog timed out after {timeout}s")
    except OSError as exc:
        raise RuntimeError(f"TruffleHog could not start: {exc}")
    findings = parse_findings(out.stdout)
    changed = changed_paths(repo, since, head) if since and head else None
    errors = logged_errors(out.stderr, (lambda path: path not in changed) if changed is not None else None)
    if out.returncode not in (0, FAIL_EXIT):
        # stderr is TruffleHog's own log; show only its last error message, never stdout (results).
        raise RuntimeError(f"TruffleHog exited {out.returncode}{': ' + errors[-1] if errors else ''}")
    if errors:
        # A file or archive it could not read is content it did not scan: never a pass (a live check that
        # failed is not logged as an error; it is an `unknown` result instead).
        raise RuntimeError(f"TruffleHog logged {len(errors)} scan error(s), so part of the range was not read: "
                           f"{errors[-1]}")
    if out.returncode == FAIL_EXIT and not findings:
        raise RuntimeError("TruffleHog reported results that could not be read")
    # TruffleHog scans a fresh clone of the repo, so a commit no ref reaches would be read as nothing at all.
    # Reading 0 bytes of a range that adds lines is a scan that did not happen, never a pass.
    if since and head and scanned_bytes(out.stderr) == 0 and added_lines(repo, since, head) > 0:
        raise RuntimeError("TruffleHog read nothing although the commits add lines (is the commit on a branch?)")
    return findings


# --------------------------------------------------------------------------- staged (pre-commit)

STAGED_FILE_MODES = ("100644", "100755", "120000")  # files and symlinks; a submodule (160000) has no content


def staged_entries(repo):
    """[(path, blob sha)] the commit adds or changes, from the index (GIT_INDEX_FILE when git sets one, as for
    `git commit -a` or `git commit <paths>`). Deletions are skipped; a rename counts as its new path."""
    out = subprocess.run(["git", "-C", str(repo), "diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames",
                          "--diff-filter=ACMT"], capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(f"git diff --cached failed: {out.stderr.decode('utf-8', 'replace').strip()[:300]}")
    parts = out.stdout.split(b"\0")
    entries = []
    for i in range(0, len(parts) - 1, 2):
        meta, path = parts[i].decode("ascii", "replace").split(), parts[i + 1].decode("utf-8", "surrogateescape")
        if len(meta) >= 5 and meta[1] in STAGED_FILE_MODES:
            entries.append((path, meta[3]))
    return entries


def export_blobs(repo, entries, dest):
    """Write each staged blob to dest/<n>/<file name> (raw blob: no smudge filter, no LFS download, no symlink
    made). One folder per entry, so no two staged paths can meet on the Mac's case- and accent-insensitive disk
    (README.md and readme.md, Fixtures/ and fixtures/), and the name keeps its extension. Streams from one
    `git cat-file --batch`, so a large staged file is never held in memory.
    Returns (bytes written, {path under dest: repo path})."""
    root = os.path.realpath(dest)
    where = {}
    proc = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    total = 0
    try:
        for n, (path, sha) in enumerate(entries):
            proc.stdin.write(f"{sha}\n".encode())
            proc.stdin.flush()
            head = proc.stdout.readline().split()
            if len(head) != 3 or head[1] != b"blob":
                raise RuntimeError(f"staged file {path} could not be read from the index")
            size = int(head[2])
            name = os.path.basename(path) or "file"
            rel = os.path.join(str(n), name)
            os.mkdir(os.path.join(root, str(n)))
            where[rel] = path
            left = size
            with open(os.path.join(root, rel), "wb") as fh:
                while left:
                    chunk = proc.stdout.read(min(left, 1 << 20))
                    if not chunk:
                        raise RuntimeError(f"staged file {path} was cut short while reading it")
                    fh.write(chunk)
                    left -= len(chunk)
            proc.stdout.read(1)  # the newline after each object
            total += size
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        proc.stdout.close()
        proc.wait()
        proc.stderr.close()
    return total, where


def fs_scan_cmd(binary, folder):
    return [binary, "filesystem", str(folder), "--json", "--no-update", "--no-ignore-tag",
            "--results=verified,unknown,unverified", "--fail", "--fail-on-scan-errors"]


def scan_staged(binary, repo, entries, timeout=SCAN_TIMEOUT):
    """TruffleHog filesystem mode on a private copy of the staged files. Every result counts (all_results)."""
    with tempfile.TemporaryDirectory(prefix="secret-scan-staged-") as tmp:
        folder = os.path.join(tmp, "staged")
        os.mkdir(folder, 0o700)
        total, where = export_blobs(repo, entries, folder)
        try:
            out = subprocess.run(fs_scan_cmd(binary, folder), capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"TruffleHog timed out after {timeout}s")
        except OSError as exc:
            raise RuntimeError(f"TruffleHog could not start: {exc}")
        findings = parse_findings(out.stdout, base_dir=folder, all_results=True)
    errors = logged_errors(out.stderr)
    if out.returncode not in (0, FAIL_EXIT):
        raise RuntimeError(f"TruffleHog exited {out.returncode}{': ' + errors[-1] if errors else ''}")
    if errors:
        raise RuntimeError(f"TruffleHog logged {len(errors)} scan error(s), so part of the staged files was not "
                           f"read: {errors[-1]}")
    if out.returncode == FAIL_EXIT and not findings:
        raise RuntimeError("TruffleHog reported results that could not be read")
    if total > 0 and scanned_bytes(out.stderr) == 0:
        raise RuntimeError("TruffleHog read nothing although the staged files hold data")
    for f in findings:
        f["commit"] = ""
        if f["file"] not in where:
            raise RuntimeError("TruffleHog named a file that was not staged")
        f["file"] = where[f["file"]]
    return findings


# --------------------------------------------------------------------------- allow list


def load_allow(text):
    """(valid entries, problems). Text is the file content or None."""
    if not text:
        return [], []
    try:
        data = json.loads(text)
    except ValueError:
        return [], [f"{ALLOW_FILE} is not valid JSON; no entries used"]
    entries = data.get("allow") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return [], [f"{ALLOW_FILE} needs an \"allow\" list; no entries used"]
    valid, problems = [], []
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            problems.append(f"entry {i}: not an object")
            continue
        reason = str(e.get("reason") or "").strip()
        if len(reason.split()) < 3:
            problems.append(f"entry {i}: reason needs 3 or more words; ignored")
            continue
        fp, path = e.get("fingerprint"), e.get("path")
        if fp and not re.fullmatch(r"[0-9a-f]{16}", str(fp)):
            problems.append(f"entry {i}: fingerprint must be 16 lowercase hex characters; ignored")
            continue
        if path:
            try:
                re.compile(str(path))
            except re.error:
                problems.append(f"entry {i}: path is not a valid regular expression; ignored")
                continue
            if "|" in str(path) or not re.match(r"\^[A-Za-z0-9_][A-Za-z0-9_./-]{2,}", str(path)):
                problems.append(f"entry {i}: path must start with ^ and a literal folder or file name "
                                "(such as ^tests/fixtures/) and hold no |; ignored")
                continue
        if not fp and not path:
            problems.append(f"entry {i}: needs a fingerprint or a path; ignored")
            continue
        valid.append({"i": i, "fingerprint": fp, "path": path, "reason": reason,
                      "live_public": e.get("live_public") is True})
    return valid, problems


def allowed_by(finding, entries):
    for e in entries:
        if e["fingerprint"] and e["fingerprint"] != finding["fingerprint"]:
            continue
        if e["path"] and not re.search(e["path"], finding["file"]):
            continue
        if finding["status"] == "verified" and not e["live_public"]:
            continue
        return e
    return None


def read_allow_text(repo, rev=None):
    """The allow list in commit rev, in the index (rev ":", what is being committed), or in the work tree."""
    if rev == ":":
        return git(repo, "show", f":{ALLOW_FILE}", check=False)
    if rev:
        return git(repo, "show", f"{rev}:{ALLOW_FILE}", check=False)
    path = Path(repo) / ALLOW_FILE
    return path.read_text(encoding="utf-8") if path.is_file() else None


# --------------------------------------------------------------------------- report


def describe(f):
    where = f"{f['file']}:{f['line']}" if f["file"] else "(no file)"
    when = f"commit {f['commit'][:12]}" if f["commit"] else "staged"
    return f"{f['status']} {f['detector']} secret in {where}, {when}, fingerprint {f['fingerprint']}"


def gh_escape(text):
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def gh_prop(text):
    """A workflow-command property value (file=...): also escape ':' and ','."""
    return gh_escape(text).replace(":", "%3A").replace(",", "%2C")


def report(findings, entries, problems, github=False):
    """Print results; return the findings that still fail after the allow list."""
    for p in problems:
        say(f"allow list: {p}")
        if github:
            print(f"::warning file={ALLOW_FILE}::{gh_escape(p)}")
    failing = []
    seen = set()
    for f in findings:
        key = (f["fingerprint"], f["file"], f["commit"])
        if key in seen:
            continue
        seen.add(key)
        entry = allowed_by(f, entries)
        if entry:
            say(f"allowed by {ALLOW_FILE} entry {entry['i']} ({entry['reason']}): {describe(f)}")
            if github:
                print(f"::notice file={ALLOW_FILE}::{gh_escape('allow-list entry used: ' + entry['reason'])}")
            continue
        failing.append(f)
        say(f"FAIL {describe(f)}")
        if github:
            loc = f"file={gh_prop(f['file'])},line={max(f['line'], 1)}," if f["file"] else ""
            print(f"::error {loc}title=Secret scan::{gh_escape(describe(f))}")
    return failing


def advice(failing, staged=False):
    live = any(f["status"] == "verified" for f in failing)
    if staged:
        say("the commit was refused, so the value is not in Git. Take it out of the file, keep it in 1Password "
            "(vault AI Agents) and read it at run time, then stage and commit again."
            + (" A LIVE key: rotate it if it was ever pushed, pasted or shared." if live else ""))
        say(f"If a finding is truly not a secret (a test fixture, an example), add its fingerprint with a reason to "
            f"{ALLOW_FILE} and stage that too (reviewed with the change). Rule: scripts/secret-scan/README.md in "
            "nuey-skills. Never --no-verify; an unattended job stops here and reports it, it does not retry.")
        return
    if live:
        say("a LIVE key is in these commits: rotate it now (it may already be copied), then remove it from the "
            "commits (reset or amend before pushing; once pushed, rotating is what protects you).")
    say("Remove the value and keep it in 1Password (vault AI Agents). If a finding is truly not a secret, add its "
        f"fingerprint with a reason to {ALLOW_FILE} (reviewed with the change). Rule: scripts/secret-scan/README.md "
        "in nuey-skills. Never --no-verify.")


# --------------------------------------------------------------------------- modes


def scan_ranges(repo, ranges, binary):
    """[(findings, allow text)] per range; each pushed ref is judged by the allow list in its own commit."""
    out = []
    for since, head, added in ranges:
        found = [f for f in run_trufflehog(binary, repo, since, head) if added is None or f["commit"] in added]
        out.append((found, read_allow_text(repo, head)))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="TruffleHog secret scan of what a push or pull request adds.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true", help="git pre-commit: scan the staged files (every hit fails)")
    mode.add_argument("--pre-push", action="store_true", help="read git pre-push refs on stdin")
    mode.add_argument("--base", help="CI: scan commits on HEAD that are not on this base ref")
    mode.add_argument("--full", action="store_true", help="scan every commit on every branch")
    mode.add_argument("--install", action="store_true", help="install the pinned binary and exit")
    mode.add_argument("--version", action="store_true", help="print the pinned version")
    ap.add_argument("--repo", default=".", help="repository (default: current directory)")
    ap.add_argument("--remote", default="origin", help="pre-push: the remote being pushed to")
    ap.add_argument("--github", action="store_true", help="also print GitHub annotations")
    ap.add_argument("--report", help="--full: write the safe findings (no secrets) to this JSON file")
    args = ap.parse_args(argv)

    if args.version:
        print(PIN_VERSION)
        return 0
    try:
        if args.install:
            print(ensure_binary())
            return 0
        repo = Path(args.repo).resolve()
        if args.staged:
            entries = staged_entries(repo)
            if not entries:
                return 0
            binary = ensure_binary()
            results = [(scan_staged(binary, repo, entries), read_allow_text(repo, ":"))]
            ranges = []
        elif args.pre_push:
            refs_text = sys.stdin.read()
            ranges = push_ranges(repo, refs_text, args.remote)
            if not ranges:
                return 0
        elif args.base:
            since, head, added = ci_range(repo, args.base)
            if not added:
                say(f"no commits to scan beyond {args.base}.")
                return 0
            ranges = [(since, head, added)]
        else:
            ranges = [(None, None, None)]
        if not args.staged:
            binary = ensure_binary()
            results = scan_ranges(repo, ranges, binary)
    except (RuntimeError, OSError, ValueError) as exc:
        say(f"could not run: {exc}")
        say("the scan is required; fix the cause and run again. Never --no-verify.")
        if args.github:
            print(f"::error title=Secret scan::{gh_escape('could not run: ' + str(exc))}")
        return 2

    findings, failing = [], []
    for found, allow_text in results:
        entries, problems = load_allow(allow_text)
        findings += found
        failing += report(found, entries, problems, args.github)
    if args.report:
        Path(args.report).write_text(json.dumps({"version": PIN_VERSION, "findings": findings,
                                                 "failing": failing}, indent=1) + "\n", encoding="utf-8")
    if failing:
        say(f"{len(failing)} secret finding(s); refused.")
        advice(failing, staged=args.staged)
        return 1
    if args.staged:
        return 0  # a clean commit stays quiet
    commits = sum(len(a) for _s, _h, a in ranges if a is not None)
    say(f"clean (TruffleHog {PIN_VERSION}{f', {commits} commit(s)' if commits else ''}).")
    return 0


def run(argv=None):
    """main(), but an unexpected error is "could not run" (exit 2), never "a secret was found" (exit 1)."""
    try:
        return main(argv)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001  a bug must refuse, and must not read as a finding
        say(f"could not run: internal error ({type(exc).__name__})")
        return 2


if __name__ == "__main__":
    sys.exit(run())
