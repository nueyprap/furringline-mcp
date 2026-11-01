#!/usr/bin/env python3
"""Secret scan: TruffleHog OSS on the commits a push or pull request adds (Narathip, 2026-11-01).

Decision: record topic security, c9b4d14b. TruffleHog checks whether a found key is live. A verified
(live) or unknown (could not confirm) result fails; an unverified one (a pattern the provider says is
dead) passes. It runs inside the shared checks every change already passes: the pre-push hook block in
`.githooks/pre-push` and a step of the required `jev` job in `jev-gate.yml`. Installed into each repo as
`.jev/secret_scan.py` by `scripts/jev-gate/install.py` in nuey-skills (source: `scripts/secret-scan/`).

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
second reviewer reads it (checks-from-main). Every entry used is printed.

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
        if cand.is_file() and os.access(cand, os.X_OK) and binary_version(cand) == PIN_VERSION:
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


def parse_findings(stdout):
    """Safe finding dicts from TruffleHog JSON lines. The raw value is used only for the fingerprint."""
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
        meta = (((d.get("SourceMetadata") or {}).get("Data") or {}).get("Git")) or {}
        detector = str(d.get("DetectorName") or "unknown-detector")
        raw = d.get("RawV2") or d.get("Raw") or ""
        findings.append({
            "detector": detector,
            "status": "verified" if d.get("Verified") else "unknown",
            "file": str(meta.get("file") or ""),
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


def logged_errors(stderr):
    """TruffleHog's error-level log messages (its log never holds a found value; cut to 200 characters)."""
    msgs = []
    for line in (stderr or "").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and str(rec.get("level", "")).startswith("error"):
            msgs.append(str(rec.get("msg", "error"))[:200])
    return msgs


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
    errors = logged_errors(out.stderr)
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
    if rev:
        return git(repo, "show", f"{rev}:{ALLOW_FILE}", check=False)
    path = Path(repo) / ALLOW_FILE
    return path.read_text(encoding="utf-8") if path.is_file() else None


# --------------------------------------------------------------------------- report


def describe(f):
    where = f"{f['file']}:{f['line']}" if f["file"] else "(no file)"
    return f"{f['status']} {f['detector']} secret in {where}, commit {f['commit'][:12]}, fingerprint {f['fingerprint']}"


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


def advice(failing):
    live = any(f["status"] == "verified" for f in failing)
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
        if args.pre_push:
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
        binary = ensure_binary()
        results = scan_ranges(repo, ranges, binary)
    except RuntimeError as exc:
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
        advice(failing)
        return 1
    commits = sum(len(a) for _s, _h, a in ranges if a is not None)
    say(f"clean (TruffleHog {PIN_VERSION}{f', {commits} commit(s)' if commits else ''}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
