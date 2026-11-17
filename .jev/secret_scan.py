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
import http.client
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
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
# Second source when GitHub release downloads fail (504s for 20+ minutes on 2026-11-08 failed every jev check):
# TruffleHog's own Docker Hub image of the same release. The image layer that holds usr/bin/trufflehog is
# fetched by digest over plain HTTPS (no docker needed; blob fetches do not count toward Docker Hub's pull
# limit) and checked against that digest, which fixes every byte of the binary inside. mirror_pins.py (nuey-skills)
# checks, when it prints the pins, that this binary is byte-identical to the GitHub tarball's (true for 3.99.7). Linux only (CI, cloud sessions);
# the Macs keep their installed binary. No Actions cache: a cache archive can write anywhere on the runner,
# so gate workflows stay cache-free (scripts/repo-standard/README.md, checks-from-main).
MIRROR_REPO = "trufflesecurity/trufflehog"
MIRROR_TOKEN_URL = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
MIRROR_BLOB_URL = "https://registry-1.docker.io/v2/{repo}/blobs/{digest}"
MIRROR_MEMBER = "usr/bin/trufflehog"
MIRROR_LAYER = {  # per TruffleHog version; print a new entry with scripts/secret-scan/mirror_pins.py (nuey-skills)
    "3.99.7": {
        "linux_amd64": "sha256:da63fb77679376e6062134efe8747801ff5fc1d4523698ad716716a11788d803",
        "linux_arm64": "sha256:1a3d035c57c4ba5e0e9ec0bda46c30e38817ef1ae73bbf3b41d1a42d7b0754e3",
    },
}
RETRY_DELAYS = (3, 10, 20)  # seconds before each retry of a failed download (4 tries)
TRY_TIMEOUT = 30  # seconds a socket may wait for data (per read, not the whole transfer)
# Time for each download, tries and transfer included, so a GitHub that hangs or trickles still leaves the Docker
# Hub fallback its turn inside the 10-minute jev job. Worst case all told: 60 + 30 + 90 = 180 s (plus one socket
# timeout at most, for a read already waiting when the budget ends).
BUDGET_RELEASE, BUDGET_TOKEN, BUDGET_LAYER = 60, 30, 90
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


class DownloadError(RuntimeError):
    """A download that failed for network reasons (the next source may work). A checksum mismatch is not one."""


def _fetch_once(url, dest, timeout, headers, deadline=None, clock=time.monotonic):
    """One try. A body shorter than its Content-Length, or a transfer still running at `deadline`, is a failure."""
    req = urllib.request.Request(url, headers={"User-Agent": f"nuey-secret-scan/{PIN_VERSION}"})
    for key, value in (headers or {}).items():
        req.add_unredirected_header(key, value)  # never forwarded to the CDN a registry redirects to
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as out:  # noqa: S310 (fixed https URL)
        want = resp.headers.get("Content-Length") if getattr(resp, "headers", None) else None
        got = 0
        while True:
            if deadline is not None and clock() > deadline:
                raise TimeoutError("transfer ran past its time budget")
            # read1: at most one network read, so the deadline is checked at least once per socket timeout
            # (read(n) would wait for all n bytes from a server that trickles).
            block = resp.read1(1 << 16)
            if not block:
                break
            out.write(block)
            got += len(block)
    if want and want.isdigit() and got != int(want):
        raise http.client.IncompleteRead(b"", int(want) - got)


def download(url, dest, headers=None, timeout=None, delays=None, sleep=time.sleep, budget=None,
             clock=time.monotonic):
    """Fetch url into dest, retrying a server error (5xx, 408, 429) or a network failure with backoff.

    No new try starts once `budget` seconds have passed. Raises DownloadError when every try failed or the budget
    ran out, or at once on a client error such as 404."""
    delays = RETRY_DELAYS if delays is None else delays
    timeout = TRY_TIMEOUT if timeout is None else timeout
    start, last, tries = clock(), "", 0
    deadline = start + budget if budget is not None else None
    for attempt in range(len(delays) + 1):
        if attempt:
            if budget is not None and clock() - start + delays[attempt - 1] > budget:
                raise DownloadError(f"{last} after {tries} tries ({budget} s budget) for {url.split('?')[0]}")
            say(f"download failed ({last}); retrying in {delays[attempt - 1]} s ...")
            sleep(delays[attempt - 1])
        tries += 1
        try:
            _fetch_once(url, dest, timeout, headers, deadline, clock)
            return
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            if exc.code < 500 and exc.code not in (408, 429):
                raise DownloadError(f"{last} for {url.split('?')[0]}") from None
        except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException) as exc:  # a cut-off body too
            last = str(getattr(exc, "reason", "") or exc or type(exc).__name__)[:120]
    raise DownloadError(f"{last} after {tries} tries for {url.split('?')[0]}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _binary_from_release(fetch, plat, tmp):
    """The pinned GitHub release tarball, sha256-checked; returns the unpacked binary's path in tmp."""
    tarball = os.path.join(tmp, "th.tar.gz")
    fetch(URL.format(v=PIN_VERSION, plat=plat), tarball, budget=BUDGET_RELEASE)
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
    return staged


def _binary_from_mirror(fetch, plat, tmp):
    """The same binary from TruffleHog's Docker Hub image layer, fetched by pinned digest; both hashes checked."""
    token_file = os.path.join(tmp, "token.json")
    fetch(MIRROR_TOKEN_URL.format(repo=MIRROR_REPO), token_file, budget=BUDGET_TOKEN)
    try:
        with open(token_file, encoding="utf-8") as fh:
            token = json.load(fh)["token"]
    except (OSError, ValueError, KeyError, TypeError):
        raise DownloadError("Docker Hub gave no pull token") from None
    digest = MIRROR_LAYER[PIN_VERSION][plat]
    layer = os.path.join(tmp, "layer.tar.gz")
    fetch(MIRROR_BLOB_URL.format(repo=MIRROR_REPO, digest=digest), layer, headers={"Authorization": f"Bearer {token}"},
          budget=BUDGET_LAYER)
    got = sha256_file(layer)
    if f"sha256:{got}" != digest:  # fixes every byte of the binary inside
        raise RuntimeError(f"Docker Hub layer checksum mismatch for {plat} (got {got[:12]}...); not installed")
    with tarfile.open(layer, "r:*") as tar:
        member = next((m for m in tar if m.name.lstrip("./") == MIRROR_MEMBER), None)
        if member is None or not member.isfile():
            raise RuntimeError(f"Docker Hub layer has no {MIRROR_MEMBER}")
        staged = os.path.join(tmp, "trufflehog")
        with open(staged, "wb") as out:
            shutil.copyfileobj(tar.extractfile(member), out)
    return staged


def install_binary(fetch=download):
    """Install the pinned TruffleHog: the GitHub release (sha256-checked), or, when that download fails on a
    platform with a pinned mirror layer, the same binary from Docker Hub. Unpacks only `trufflehog`; a
    checksum mismatch never falls back. Raises when no verified binary could be had. Returns the path."""
    plat = platform_key()
    if not plat:
        raise RuntimeError(f"no pinned TruffleHog build for {platform.system()} {platform.machine()}")
    target_dir = install_dir()
    target = target_dir / "trufflehog"
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=str(target_dir.parent), prefix=".dl-") as tmp:
        try:
            staged = _binary_from_release(fetch, plat, tmp)
        except DownloadError as exc:
            if plat not in MIRROR_LAYER.get(PIN_VERSION, {}):  # pins for another version never apply
                raise
            say(f"GitHub release download failed ({exc}); trying TruffleHog's Docker Hub copy of the same build ...")
            try:
                staged = _binary_from_mirror(fetch, plat, tmp)
            except DownloadError as exc2:
                raise DownloadError(f"GitHub release: {exc}; Docker Hub: {exc2}") from None
            say(f"installed TruffleHog {PIN_VERSION} from Docker Hub (layer sha256 checked against the pin).")
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


# --------------------------------------------------------------------------- sensitive files (2026-11-17)
# Spreadsheets, PDFs, office files and payroll or HR data never go into Git (Narathip, 2026-11-17: an agent's
# rescue of unplaced files must send them to Dropbox Agent Backups, never to a Git branch). The commit, push and
# CI scans refuse (a) a spreadsheet (.xlsx .xls .csv ...) with HR, payroll or ID-like content, always, and (b) any
# binary office file or PDF outside the allow list's "files" entries. stay-current's rescue
# (scripts/stay-current/stuck.py) uses the same sensitive_reason() to pick what goes to Dropbox: for tracked files
# the gate's own answer, for untracked ones a wider net. Only the path and the reason are printed, never a value.

SHEET_EXT = {".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb", ".xls", ".ods", ".numbers", ".csv", ".tsv"}
OFFICE_EXT = SHEET_EXT - {".csv", ".tsv"} | {".docx", ".docm", ".dotx", ".dotm", ".doc", ".odt", ".pages", ".rtf",
                                            ".pptx", ".pptm", ".potx", ".ppsx", ".ppt", ".odp", ".key", ".pdf"}
ZIP_TEXT_EXT = {".xlsx", ".xlsm", ".xltx", ".xltm", ".ods", ".docx", ".docm", ".dotx", ".dotm", ".odt", ".pptx",
                ".pptm", ".potx", ".ppsx", ".odp"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".heic", ".heif", ".tif", ".tiff", ".webp", ".bmp", ".gif"}
# Text kinds where a payroll word is normal prose (docs and code about the HR work); only ID-like numbers count.
PROSE_EXT = {".md", ".py", ".sh", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".yml", ".yaml", ".toml", ".html",
             ".css", ".swift", ".go", ".rs", ".rb", ".sql", ".ini", ".cfg"}
# The payroll words of outside_change_check._PAYROLL_MARKERS (nuey-skills scripts/outside-change-check; a test keeps
# them equal): this file is copied alone into every repo, so it cannot import that one. The HR sheet's ID is there
# too; here it is only a sha256, since some repos that carry this file are public.
PAYROLL_WORDS = re.compile(r"ฐานเงินเดือน|เงินเดือน|เลขบัญชี|รหัสพนักงาน|เลขประจำตัวประชาชน|ค่าแรง|พนักงาน|"
                           r"คนงาน|ธนาคาร|\bsalary\b|\bpayroll\b|bank account|\bbytehr\b|hr[ -]sheet", re.I)
HR_SHEET_SHA256 = {"88df777bedd66e526906986dd27c73278ecc0862d74796ff3f19b63426679373"}
HR_SHEET_LEN = 44   # a Google Sheet ID
_ID_RUN = re.compile(r"[A-Za-z0-9_-]{%d,}" % HR_SHEET_LEN)


def hr_sheet_id(text):
    """True when text holds the HR sheet's ID anywhere, even glued to other ID characters (matched by hash)."""
    for m in _ID_RUN.finditer(text):
        run = m.group()
        if len(run) > 3 * HR_SHEET_LEN:   # a long token or base64 run, not an ID in a link or name
            continue
        for i in range(len(run) - HR_SHEET_LEN + 1):
            if hashlib.sha256(run[i:i + HR_SHEET_LEN].encode()).hexdigest() in HR_SHEET_SHA256:
                return True
    return False


def payroll_marker(text):
    """True when text holds a payroll word or the HR sheet's ID (matched by its hash)."""
    return bool(PAYROLL_WORDS.search(text)) or hr_sheet_id(text)


# Spreadsheet column names that mean people data, beyond the payroll words.
HR_HEADERS = re.compile(r"\b(?:employee|staff|worker)[ _-]?(?:id|no|number|code|name)\b|national[ _-]?id|"
                        r"citizen[ _-]?id|id[ _-]?card|tax[ _-]?id|passport|date[ _-]?of[ _-]?birth|"
                        r"payslip|บัตรประชาชน|วันเกิด|ชื่อ-?สกุล|ชื่อ-?นามสกุล", re.I)
BANK_ACCOUNT = re.compile(r"(?<![\d-])\d{3}-\d-\d{5}-\d(?![\d-])")
# Written the way IDs are printed (1-2345-67890-12-3, or with spaces). email-writing's keep_out.py has a looser
# rule on purpose (free text, no check digit); this one must not trip on timestamps in data files. A bare 13-digit number is not counted:
# about 1 in 10 random ones (millisecond timestamps) pass the check digit. A sheet of bare IDs is still caught by
# its column names (HR_HEADERS) or payroll words.
THAI_ID = re.compile(r"(?<![\d-])(\d)([- ])(\d{4})\2(\d{5})\2(\d{2})\2(\d)(?![\d-])")
HR_NAME = re.compile(r"(?:^|[^a-z])(?:hr|bytehr|payroll|employees?|workers?|roster|staff|salary|salaries|payslips?|"
                     r"wages?)(?:[^a-z]|$)|เงินเดือน|พนักงาน|สลิป", re.I)
DOC_IMAGE_NAME = re.compile(r"(?<![a-z])(?:scan(?:ned)?|receipts?|invoices?|statements?|id[ _-]?cards?|passports?|"
                            r"payslips?|contracts?|licen[cs]es?|certificates?|forms?|documents?)(?![a-z])|"
                            r"ใบ|บัตร|สลิป|สัญญา|เอกสาร", re.I)


def _thai_id_ok(digits):
    """A 13-digit Thai national ID with a valid check digit (so a random 13-digit number rarely counts)."""
    if len(digits) != 13 or digits[0] == "0":
        return False
    total = sum(int(d) * (13 - i) for i, d in enumerate(digits[:12]))
    return (11 - total % 11) % 10 == int(digits[12])


def id_like(text):
    """True when the text holds a Thai national ID (valid check digit) or a Thai bank account number."""
    if BANK_ACCOUNT.search(text):
        return True
    return any(_thai_id_ok("".join(m.group(1, 3, 4, 5, 6))) for m in THAI_ID.finditer(text))


UNREAD = None   # readable_text's answer for a sheet or document whose content it cannot read


def decode(data):
    """Bytes to text: a BOM first, then UTF-8, then UTF-16 when it looks like it, then cp874 (TIS-620, what
    Thai Excel saves a CSV as), else Latin-1."""
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:].decode("utf-8", "replace")
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if len(data) > 3 and data[1:200:2].count(0) > len(data[1:200:2]) * 0.4:   # BOM-less UTF-16LE
        return data.decode("utf-16-le", "replace")
    if len(data) > 3 and data[0:200:2].count(0) > len(data[0:200:2]) * 0.4:   # BOM-less UTF-16BE
        return data.decode("utf-16-be", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("cp874")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _xml_text(data):
    import html
    return html.unescape(re.sub(r"<[^>]+>", " ", data.decode("utf-8", "replace")))


def readable_text(name, data):
    """The text a file holds, for the content checks: the XML parts of an .xlsx/.xlsm/.ods/.docx/.pptx/.odt (zip),
    the strings of an old .xls/.doc/.ppt (best effort), else the bytes decoded (decode()). UNREAD (None) for a sheet
    or document whose cells cannot be read here: .xlsb and .numbers (binary parts), a PDF (compressed), a zip kind
    that is not a zip (password-protected) or holds no text. Never raises."""
    import io
    import zipfile
    ext = os.path.splitext(name.lower())[1]
    if ext in {".xlsb", ".numbers", ".pages", ".key", ".pdf"}:
        return UNREAD
    try:
        if ext in ZIP_TEXT_EXT:
            if data[:2] != b"PK":
                return UNREAD
            parts = []
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for n in z.namelist():
                    if n.endswith(".xml") and (n.startswith(("xl/", "word/", "ppt/")) or n == "content.xml"):
                        parts.append(_xml_text(z.read(n)[:20_000_000]))
            text = " ".join(parts)
            return text if text.strip() else UNREAD
        if ext in {".xls", ".doc", ".ppt"}:   # OLE binary: strings are UTF-16LE or Latin-1 (cp874 for Thai)
            return (data.decode("utf-16-le", "ignore") + " " + data.decode("cp874", "ignore") + " "
                    + data.decode("latin-1", "ignore"))
        return decode(data)
    except Exception:  # noqa: BLE001  a broken zip or file cannot be read
        return UNREAD


def sensitive_reason(path, data, rescue=False):
    """(kind, reason) when a file must not go into Git, else None. kind:
      "hr"      ID-like numbers (a printed national ID, a bank account), people-data column names or the HR
                sheet's ID: never in Git, no allow list;
      "hrwords" payroll words, or people-data column names below a CSV/TSV's first line: Git only under a
                "files" entry for that one .csv or .tsv file that also says "hr_words": true (a reviewed prose
                list, such as dictation phrases that hold the words for wages and birthday);
      "unread"  a spreadsheet whose cells cannot be read (.xlsb, .numbers, password-protected): Git only under a
                "files" entry that also says "unreadable": true;
      "office"  any other binary office file or PDF: Git only under a "files" entry;
      "image"   an image of a document (rescue only; the commit gate lets images through).
    rescue=True is a wider net for an agent's untracked files, whose content is unknown: ID-like numbers in any
    file, payroll words in any data file (not code or docs), HR words in an office file's name, images of
    documents."""
    name = os.path.basename(path)
    ext = os.path.splitext(name.lower())[1]
    if ext in IMAGE_EXT:
        if rescue and DOC_IMAGE_NAME.search(name):
            return ("hr" if HR_NAME.search(name) else "image"), "an image of a document"
        return None
    text = readable_text(name, data)
    seen = text or ""
    if ext in SHEET_EXT or ext in OFFICE_EXT:
        # People-data column names anywhere count. In a CSV/TSV, a match below its first line may be prose (a
        # dictation phrase with the word for birthday), so only there it is "hrwords", which only a reviewed
        # entry for that one file lets in; in its first line, or anywhere in a workbook, it is people data.
        first = next((ln for ln in seen.splitlines() if ln.strip()), "") if ext in (".csv", ".tsv") else seen
        if id_like(seen) or HR_HEADERS.search(first) or hr_sheet_id(seen):
            return "hr", "a spreadsheet or office file with people data (ID numbers or people-data columns)"
        if ext in SHEET_EXT and text is UNREAD:
            return "unread", "a spreadsheet whose cells cannot be read here (it could hold HR data)"
        if PAYROLL_WORDS.search(seen) or HR_HEADERS.search(seen):
            return "hrwords", "a spreadsheet or office file with payroll words or people-data column names"
        if ext in OFFICE_EXT:
            if rescue and HR_NAME.search(name):
                return "hrwords", "an office file or PDF named for HR or payroll"
            return "office", "a binary office file or PDF"
    if rescue:
        if id_like(seen):
            return "hr", "a file with ID-like numbers (a national ID or a bank account)"
        if ext and ext not in PROSE_EXT and payroll_marker(seen):
            return "hr", "a data file with payroll or HR words"
    return None


def load_file_allow(text):
    """(path patterns, problems) from the allow list's "files" entries: [{"path": "^folder/", "reason": "..."}].
    They let a binary office file or PDF in (samples, fixtures); never one with HR or ID-like content."""
    if not text:
        return [], []
    try:
        data = json.loads(text)
    except ValueError:
        return [], []   # load_allow reports it
    entries = data.get("files") if isinstance(data, dict) else None
    if entries is None:
        return [], []
    if not isinstance(entries, list):
        return [], [f"{ALLOW_FILE} \"files\" must be a list; no file entries used"]
    valid, problems = [], []
    for i, e in enumerate(entries):
        path = str((e or {}).get("path") or "") if isinstance(e, dict) else ""
        reason = str((e or {}).get("reason") or "").strip() if isinstance(e, dict) else ""
        if len(reason.split()) < 3:
            problems.append(f"files entry {i}: reason needs 3 or more words; ignored")
            continue
        try:
            re.compile(path)
        except re.error:
            problems.append(f"files entry {i}: path is not a valid regular expression; ignored")
            continue
        if "|" in path or not re.match(r"\^[A-Za-z0-9_][A-Za-z0-9_./-]{2,}", path):
            problems.append(f"files entry {i}: path must start with ^ and a literal folder or file name and hold "
                            "no |; ignored")
            continue
        hr_words = e.get("hr_words") is True
        if hr_words and not re.fullmatch(r"\^(?:[^.*+?()\[\]{}|\\]|\\\.)+\\\.(?:csv|tsv)\$", path):
            problems.append(f"files entry {i}: \"hr_words\" needs the path of one .csv or .tsv file "
                            "(^dir/name\\.tsv$); hr_words ignored")
            hr_words = False
        valid.append({"i": i, "path": path, "reason": reason, "unreadable": e.get("unreadable") is True,
                      "hr_words": hr_words})
    return valid, problems


def file_allowed(entry, path, kind):
    """True when a "files" entry lets a file of this kind in: "hr" never; "hrwords" and "unread" only with their
    own flag on the entry."""
    if kind == "hr" or not re.search(entry["path"], path):
        return False
    return kind == "office" or (kind == "unread" and entry["unreadable"]) or (kind == "hrwords" and entry["hr_words"])


def check_files(files, allow_text, github=False):
    """files: [(path, bytes)]. Prints each refusal (path and reason only); returns the number refused."""
    entries, problems = load_file_allow(allow_text)
    for p in problems:
        say(f"allow list: {p}")
    refused = 0
    for path, data in files:
        found = sensitive_reason(path, data)
        if not found:
            continue
        kind, reason = found
        if kind != "hr":
            entry = next((e for e in entries if file_allowed(e, path, kind)), None)
            if entry:
                continue
        refused += 1
        tail = {"hr": "; people data never goes into Git", "hrwords": "; payroll data goes to Dropbox, never Git",
                "unread": f"; not on the \"files\" allow list in {ALLOW_FILE} as unreadable"}
        say(f"FAIL {path}: {reason}" + tail.get(kind, f"; not on the \"files\" allow list in {ALLOW_FILE}"))
        if github:
            print(f"::error file={gh_prop(path)},title=Sensitive file::{gh_escape(reason)}")
    if refused:
        say("keep spreadsheets, PDFs, office files and HR data in Dropbox (Agent Backups, bytehr for HR or payroll; "
            "stay-current --rescue <folder> copies them there with a hash check), never in Git. A sample or fixture "
            f"office file made of made-up data only: add a \"files\" entry with a reason to {ALLOW_FILE}, reviewed with "
            "the change. Rule: scripts/secret-scan/README.md "
            "in nuey-skills. Never --no-verify.")
    return refused


def staged_files(repo, entries):
    """[(path, bytes)] of the staged blobs worth reading: sheets, office files, PDFs."""
    out = []
    for path, sha in entries:
        ext = os.path.splitext(path.lower())[1]
        if ext in SHEET_EXT or ext in OFFICE_EXT:
            r = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", sha], capture_output=True)
            if r.returncode != 0:
                raise RuntimeError(f"staged file {path} could not be read from the index")
            out.append((path, r.stdout))
    return out


def range_files(repo, commits):
    """[(path, bytes)] of every version of a sheet, office file or PDF that one of commits (the same set the
    TruffleHog scan judges: on no remote ref for a push, not on the base for CI) added or changed, so one added
    and removed again inside the range counts. A merge commit counts only for what it changed itself (a conflict
    resolution: --cc, files that differ from every parent), so merging main never re-judges main's own files."""
    out, seen = [], set()

    def add(path, blob):
        if (path, blob) in seen:
            return
        seen.add((path, blob))
        ext = os.path.splitext(path.lower())[1]
        if ext in SHEET_EXT or ext in OFFICE_EXT:
            b = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", blob], capture_output=True)
            if b.returncode != 0:
                raise RuntimeError(f"{path} could not be read from the commits")
            out.append((path, b.stdout))

    for c in sorted(commits):
        r = subprocess.run(["git", "-C", str(repo), "diff-tree", "-r", "-z", "--no-commit-id", "--raw", "--no-abbrev",
                            "--no-renames", "--root", "--diff-filter=ACMT", c], capture_output=True)
        if r.returncode != 0:
            raise RuntimeError(f"could not list the files of {c[:12]}: "
                               f"{r.stderr.decode('utf-8', 'replace').strip()[:200]}")
        parts = r.stdout.split(b"\0")
        for k in range(0, len(parts) - 1, 2):
            meta = parts[k].decode("ascii", "replace").split()
            if len(meta) >= 5 and meta[1] in STAGED_FILE_MODES:
                add(parts[k + 1].decode("utf-8", "surrogateescape"), meta[3])
        if len(git(repo, "rev-list", "--parents", "-n", "1", c).split()) > 2:   # a merge: its own changes
            m = subprocess.run(["git", "-C", str(repo), "diff-tree", "-r", "-z", "--cc", "--name-only",
                                "--no-commit-id", c], capture_output=True)
            if m.returncode != 0:
                raise RuntimeError(f"could not list what merge {c[:12]} changed itself")
            for path in [p.decode("utf-8", "surrogateescape") for p in m.stdout.split(b"\0") if p]:
                blob = git(repo, "rev-parse", "-q", "--verify", f"{c}:{path}", check=False)
                if blob:
                    add(path, blob)
    return out


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


LIVE_TOOL = "secret-scan-live"


def repo_name(repo):
    """The repository's name from its origin URL (else its folder name); used only in a message and a job title."""
    try:
        url = subprocess.run(["git", "-C", str(repo), "remote", "get-url", "origin"], capture_output=True,
                             text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        url = ""
    name = url.rstrip("/").rsplit("/", 1)[-1] if url else Path(repo).name
    return name[:-4] if name.endswith(".git") else name


def hand_off_live(failing, repo, mode):
    """A LIVE (verified) key opens one rotation job and sends one iMessage (record security-13ee2b part D) through
    this machine's secret-scan-live tool (nuey-skills scripts/secret-scan/live_key.py). Only the safe fields go to
    it. Nothing happens where the tool is not installed (a CI runner, a repo's own clone elsewhere); it never
    changes the scan's result."""
    live = [{k: f[k] for k in ("detector", "status", "file", "line", "commit", "fingerprint")}
            for f in failing if f["status"] == "verified"]
    if not live or os.environ.get("GITHUB_ACTIONS") == "true":
        return
    tool = shutil.which(LIVE_TOOL) or str(Path.home() / ".local/bin" / LIVE_TOOL)
    if not os.access(tool, os.X_OK):
        return
    payload = {"repo": repo_name(repo), "path": str(repo), "mode": mode, "findings": live}
    try:
        r = subprocess.run([tool], input=json.dumps(payload), text=True, capture_output=True, timeout=300)
        if r.returncode == 0:
            say("a live key opens one rotation job and one iMessage (secret-scan-live --list shows them).")
        else:
            say(f"secret-scan-live failed (exit {r.returncode}); rotate the key now and tell Narathip.")
    except (OSError, subprocess.SubprocessError) as exc:
        say(f"could not open the rotation job ({type(exc).__name__}); the next scan that finds it tries again.")


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
        refused = 0
        if args.staged:
            entries = staged_entries(repo)
            if not entries:
                return 0
            refused = check_files(staged_files(repo, entries), read_allow_text(repo, ":"), args.github)
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
        if not args.staged and not args.full:
            for _since, head, added in ranges:
                refused += check_files(range_files(repo, added or ()), read_allow_text(repo, head), args.github)
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
    if refused:
        say(f"{refused} sensitive file(s); refused.")
    if failing:
        say(f"{len(failing)} secret finding(s); refused.")
        advice(failing, staged=args.staged)
        mode = "staged" if args.staged else "pre-push" if args.pre_push else "full" if args.full else "ci"
        hand_off_live(failing, repo, mode)
        return 1
    if refused:
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
