#!/usr/bin/env python3
"""Night Shift gate: decides if an unattended agent branch may merge into the base branch.

The agent never runs this copy and cannot change it: the merge workflow runs it from the
base branch's `.night-shift/gate.py`, with the base branch's `.night-shift/config.toml`,
against a checkout of the agent's branch. A branch that touches `.night-shift/` or
`.github/` fails, so a branch can never loosen its own gate.

Usage:
  python3 gate.py --repo <checkout> --base <sha> --head <sha> --config <config.toml>
                  [--out verdict.json] [--summary summary.md] [--no-run]

Checks, in order (any failure rejects the whole branch):
  1. switch      enabled = true in config and no `.night-shift/PAUSED` on base
  2. commits     every commit has `Night-Shift-Run:` and an allowed `Night-Shift-Kind:` trailer
  3. paths       nothing under protected globs; everything under `allowed` globs when set
  4. size        changed lines and files within limits (lockfiles not counted)
  5. tests kept  no test file deleted; test-case and assertion counts do not go down
  6. no cheats   no added skip/only/xfail/ts-ignore/eslint-disable/noqa markers
  7. secrets     no secret-shaped values in added lines
  8. merge       branch merges cleanly into base
  9. checks      setup + every check command passes on the merged tree
 10. ratchet     test command passes `repeat` times; passed count >= base passed count
 11. fix proof   for `fix` commits, the new or changed tests fail on base (fail-before)

Stdlib only; Python 3.11+ (tomllib).
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

VERSION = "0.1.2"

DEFAULT_PROTECTED = [
    ".github/**", ".night-shift/**", ".jev/**", ".githooks/**", ".claude/**", ".codex/**",
    ".cursor/**", "AGENTS.md", "CLAUDE.md", "**/.env", "**/.env.*", "**/*.pem", "**/*.key",
    "**/.dev.vars", "**/.dev.vars.*",
]
DEFAULT_KINDS = ["fix", "test", "refactor", "perf", "security", "deps", "docs", "chore"]
LOCKFILES = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock", "poetry.lock",
             "uv.lock", "Pipfile.lock", "bun.lockb"}

TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec)/|(^|/)test[_-][^/]*$|[._-](test|spec)\.[^/]+$|Test\.php$")
TEST_CASE_RE = re.compile(
    r"(?m)(?:^|[^\w.])(?:it|test)(?:\.each\s*\([^)]*\))?\s*\(\s*[`'\"]"   # JS/TS it('..') test('..')
    r"|^\s*(?:async\s+)?def\s+test_\w+"                                  # Python
    r"|function\s+test\w*\s*\("                                           # PHP
    r"|@test\b")
ASSERT_RE = re.compile(r"\bexpect\s*\(|\bassert\w*\b|\$this->assert\w+|\.should\b|\bt\.(?:is|deepEqual|true|false|throws)\b")
CHEAT_RE = re.compile(
    r"\.(?:skip|only|todo)\s*\(|\bx(?:it|describe|test)\s*\(|@pytest\.mark\.(?:skip|xfail)|pytest\.skip\s*\("
    r"|@unittest\.skip|\.skipTest\s*\(|@unittest\.expectedFailure|markTestSkipped|markTestIncomplete|@ts-ignore|@ts-nocheck|@ts-expect-error|eslint-disable"
    r"|#\s*type:\s*ignore|#\s*noqa|phpcs:ignore|@phpstan-ignore")
SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{30,}")),
    ("sk- API key", re.compile(r"(?<![A-Za-z0-9_-])sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"\bxox[bp]-[A-Za-z0-9-]{10,}")),
    ("private key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("hard-coded credential", re.compile(
        r"(?i)(?:api[_-]?key|secret|token|password)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']")),
]
TRAILER_RE = re.compile(r"(?mi)^Night-Shift-(Run|Kind):[ \t]*(\S.*?)\s*$")


class Gate:
    def __init__(self, repo: Path, base: str, head: str, cfg: dict, run: bool = True, selftest: bool = False):
        self.repo, self.base, self.head, self.cfg, self.run_checks = repo, base, head, cfg, run
        self.selftest = selftest  # run setup/checks/tests on base only: proves the config works in CI
        self.reasons: list[str] = []
        self.notes: list[str] = []
        self.checks: list[dict] = []
        self.metrics: dict = {}
        self.boxes: dict[str, str] = {}

    # --- helpers -----------------------------------------------------------
    def git(self, *args, check=True, cwd=None) -> str:
        p = subprocess.run(["git", "-C", str(cwd or self.repo), "-c", "core.quotepath=off", *args],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        if check and p.returncode != 0:
            raise RuntimeError(f"git {' '.join(args[:2])}: {p.stderr.strip()[:300]}")
        return p.stdout

    def fail(self, msg: str):
        self.reasons.append(msg)

    def sh(self, cmd: str, cwd: Path, timeout: int) -> tuple[int, str, float]:
        """Run one untrusted command. In CI (NIGHT_SHIFT_SANDBOX=docker) it runs inside a container
        that sees only this tree, so branch code cannot touch the runner, the gate or its outputs."""
        t = time.time()
        box = self.boxes.get(str(cwd))
        if box:
            argv = ["docker", "exec", "-e", "CI=true", "-e", "NIGHT_SHIFT_GATE=1", box, "sh", "-c", cmd]
            kw = {}
        else:
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("GITHUB_", "ACTIONS_", "RUNNER_")) and k not in ("GH_TOKEN", "ALERT_KEY")}
            argv, kw = ["sh", "-c", cmd], {"cwd": cwd, "env": {**env, "CI": "true", "NIGHT_SHIFT_GATE": "1"},
                                           "start_new_session": True}
        try:
            # one stream, in order, and the full text: the passed-count line can sit far from the end
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout, **kw)
            return p.returncode, p.stdout, time.time() - t
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            if box:
                subprocess.run(["docker", "restart", "-t", "1", box], capture_output=True)
            return 124, out[-3000:] + f"\n[timeout after {timeout}s]", time.time() - t

    def box_start(self, tree: Path, name: str):
        if os.environ.get("NIGHT_SHIFT_SANDBOX") != "docker":
            return
        image = self.cfg.get("image", "node:22-bookworm")
        box = f"ns-{name}-{os.getpid()}"
        # Same paths inside and out, so the worktree's .git link to the repository still resolves.
        p = subprocess.run(["docker", "run", "-d", "--rm", "--name", box, "-v", f"{tree}:{tree}",
                            "-v", f"{self.repo}:{self.repo}", "-w", str(tree),
                            "-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory",
                            "-e", "GIT_CONFIG_VALUE_0=*", image, "sleep", "infinity"], capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"sandbox did not start: {p.stderr.strip()[:200]}")
        self.boxes[str(tree)] = box

    def box_stop(self, tree: Path):
        box = self.boxes.pop(str(tree), None)
        if box:
            subprocess.run(["docker", "rm", "-f", box], capture_output=True)

    @staticmethod
    def match_any(path: str, globs: list[str]) -> bool:
        for g in globs:
            if fnmatch.fnmatchcase(path, g):
                return True
            if g.startswith("**/") and fnmatch.fnmatchcase(path, g[3:]):
                return True
            if g.endswith("/**") and (path == g[:-3] or path.startswith(g[:-2])):
                return True
        return False

    # --- checks ------------------------------------------------------------
    def check_switch(self):
        if not self.cfg.get("enabled", False):
            self.fail("switch: enabled is not true in .night-shift/config.toml")
        paused = subprocess.run(["git", "-C", str(self.repo), "cat-file", "-e", f"{self.base}:.night-shift/PAUSED"],
                                capture_output=True)
        if paused.returncode == 0:
            self.fail("switch: .night-shift/PAUSED exists on the base branch")

    def check_commits(self):
        kinds_ok = self.cfg.get("kinds", DEFAULT_KINDS)
        shas = self.git("rev-list", "--no-merges", f"{self.base}..{self.head}").split()
        if not shas:
            self.fail("commits: branch has no new commits")
        self.commit_kinds: dict[str, str] = {}
        for sha in shas:
            msg = self.git("log", "-1", "--format=%B", sha)
            found = {k.lower(): v for k, v in TRAILER_RE.findall(msg)}
            if "run" not in found:
                self.fail(f"commits: {sha[:8]} has no Night-Shift-Run trailer")
            kind = found.get("kind", "").lower()
            if kind not in kinds_ok:
                self.fail(f"commits: {sha[:8]} kind '{kind or '-'}' not allowed here (allowed: {', '.join(kinds_ok)})")
            self.commit_kinds[sha] = kind
        self.metrics["commits"] = len(shas)

    def changed(self) -> list[tuple[str, str]]:
        out = self.git("diff", "--name-status", "--no-renames", f"{self.base}...{self.head}")
        rows = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                rows.append((parts[0][0], parts[-1]))
        return rows

    def check_paths_and_size(self, rows):
        protected = DEFAULT_PROTECTED + self.cfg.get("protected", [])
        allowed = self.cfg.get("allowed", [])
        for status, path in rows:
            if self.match_any(path, protected):
                self.fail(f"paths: {path} is protected")
            elif allowed and not self.match_any(path, allowed):
                self.fail(f"paths: {path} is outside the allowed paths")
            if status == "D" and TEST_PATH_RE.search(path):
                self.fail(f"tests kept: test file {path} was deleted")
        files = [p for _, p in rows if Path(p).name not in LOCKFILES]
        lines = 0
        for row in self.git("diff", "--numstat", "--no-renames", f"{self.base}...{self.head}").splitlines():
            a, d, path = (row.split("\t") + ["", "", ""])[:3]
            if Path(path).name in LOCKFILES or a == "-":
                continue
            lines += int(a) + int(d)
        self.metrics.update(changed_files=len(files), changed_lines=lines)
        max_lines, max_files = self.cfg.get("max_changed_lines", 400), self.cfg.get("max_files", 20)
        if lines > max_lines:
            self.fail(f"size: {lines} changed lines > limit {max_lines}")
        if len(files) > max_files:
            self.fail(f"size: {len(files)} changed files > limit {max_files}")

    def tree_counts(self, rev: str) -> tuple[int, int]:
        cases = asserts = 0
        for path in self.git("ls-tree", "-r", "--name-only", rev).splitlines():
            if not TEST_PATH_RE.search(path) or "node_modules/" in path or "/fixtures/" in path:
                continue
            text = self.git("show", f"{rev}:{path}", check=False)
            cases += len(TEST_CASE_RE.findall(text))
            asserts += len(ASSERT_RE.findall(text))
        return cases, asserts

    def check_test_counts(self):
        bc, ba = self.tree_counts(self.base)
        hc, ha = self.tree_counts(self.head)
        self.metrics.update(test_cases_base=bc, test_cases_head=hc, asserts_base=ba, asserts_head=ha)
        if hc < bc:
            self.fail(f"tests kept: test cases went down {bc} -> {hc}")
        if ha < ba:
            self.fail(f"tests kept: assertions went down {ba} -> {ha}")

    def added_lines(self) -> list[tuple[str, str]]:
        out = self.git("diff", "-U0", "--no-renames", f"{self.base}...{self.head}")
        cur, rows = "", []
        for line in out.splitlines():
            if line.startswith("+++ "):
                cur = line[6:] if line.startswith("+++ b/") else ""
            elif line.startswith("+") and not line.startswith("+++") and cur:
                rows.append((cur, line[1:]))
        return rows

    def check_cheats_and_secrets(self):
        allow_cheat = self.cfg.get("allow_markers", [])
        for path, text in self.added_lines():
            m = CHEAT_RE.search(text)
            if m and m.group(0) not in allow_cheat:
                self.fail(f"no cheats: {path} adds '{m.group(0).strip()}'")
            for kind, pat in SECRET_PATTERNS:
                if pat.search(text):
                    self.fail(f"secrets: {path} adds a {kind}")

    def worktree(self, rev: str, name: str) -> Path:
        d = Path(tempfile.mkdtemp(prefix=f"ns-{name}-"))
        shutil.rmtree(d)
        self.git("worktree", "add", "--detach", "-f", str(d), rev)
        return d

    def run_cmds(self, label: str, cmds: list[str], cwd: Path, timeout: int) -> bool:
        for cmd in cmds:
            code, out, secs = self.sh(cmd, cwd, timeout)
            self.checks.append({"stage": label, "cmd": cmd, "code": code, "secs": round(secs, 1),
                                "tail": out[-1500:]})
            if code != 0:
                return False
        return True

    def passed_count(self, out: str) -> int | None:
        rx = self.cfg.get("passed_regex")
        if not rx:
            return None
        nums = [int(n) for n in re.findall(rx, out)]
        return max(nums) if nums else None

    def check_build_and_tests(self):
        timeout = int(self.cfg.get("timeout_seconds", 900))
        setup, checks = self.cfg.get("setup", []), self.cfg.get("checks", [])
        test_cmd, repeat = self.cfg.get("test_command", ""), int(self.cfg.get("repeat", 2))
        merged = self.worktree(self.base, "merged")
        try:
            self.git("-c", "user.name=night-shift", "-c", "user.email=night-shift@invalid",
                     "merge", "--no-ff", "--no-edit", self.head, cwd=merged)
        except RuntimeError as e:
            self.fail(f"merge: branch does not merge cleanly into base ({e})")
            return
        base_wt = None
        try:
            self.box_start(merged, "merged")
            if not self.run_cmds("setup", setup, merged, timeout):
                self.fail("checks: setup failed on the merged tree")
                return
            if not self.run_cmds("check", checks, merged, timeout):
                self.fail(f"checks: '{self.checks[-1]['cmd']}' failed on the merged tree")
                return
            if not test_cmd:
                self.notes.append("no test_command configured: ratchet and fail-before skipped")
                return
            head_passed = None
            for i in range(repeat):
                code, out, secs = self.sh(test_cmd, merged, timeout)
                self.checks.append({"stage": f"test run {i + 1}/{repeat}", "cmd": test_cmd, "code": code,
                                    "secs": round(secs, 1), "tail": out[-1500:]})
                if code != 0:
                    self.fail(f"ratchet: test run {i + 1}/{repeat} failed on the merged tree (flaky or broken)")
                    return
                n = self.passed_count(out)
                head_passed = n if head_passed is None or (n is not None and n < head_passed) else head_passed
            base_wt = self.worktree(self.base, "base")
            self.box_start(base_wt, "base")
            self.run_cmds("base setup", setup, base_wt, timeout)
            code, out, _ = self.sh(test_cmd, base_wt, timeout)
            base_passed = self.passed_count(out) if code == 0 else None
            self.metrics.update(tests_passed_base=base_passed, tests_passed_head=head_passed)
            if base_passed is not None and head_passed is not None and head_passed < base_passed:
                self.fail(f"ratchet: passed tests went down {base_passed} -> {head_passed}")
            if self.cfg.get("passed_regex") and head_passed is None:
                self.fail("ratchet: could not read the passed-test count on the merged tree")
            self.check_fail_before(base_wt, test_cmd, timeout)
        finally:
            for wt in (merged, base_wt):
                if wt:
                    self.box_stop(wt)
                    self.git("worktree", "remove", "--force", str(wt), check=False)

    def check_fail_before(self, base_wt: Path, test_cmd: str, timeout: int):
        fix_shas = [s for s, k in getattr(self, "commit_kinds", {}).items() if k == "fix"]
        if not fix_shas:
            return
        tests: set[str] = set()
        for sha in fix_shas:
            for path in self.git("diff-tree", "--no-commit-id", "--name-only", "-r", sha).splitlines():
                if TEST_PATH_RE.search(path):
                    tests.add(path)
        if not tests:
            self.fail("fix proof: a fix commit adds or changes no test")
            return
        for path in tests:
            content = self.git("show", f"{self.head}:{path}", check=False)
            target = base_wt / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        code, out, secs = self.sh(test_cmd, base_wt, timeout)
        self.checks.append({"stage": "fail-before (base code + new tests)", "cmd": test_cmd, "code": code,
                            "secs": round(secs, 1), "tail": out[-1500:]})
        if code == 0:
            self.fail("fix proof: the new tests also pass on the old code, so they do not prove the fix")

    # --- main --------------------------------------------------------------
    def run(self) -> dict:
        try:
            if self.selftest:
                self.check_build_and_tests()
                raise StopIteration
            self.check_switch()
            self.check_commits()
            rows = self.changed()
            self.check_paths_and_size(rows)
            self.check_test_counts()
            self.check_cheats_and_secrets()
            if not self.reasons and self.run_checks:
                self.check_build_and_tests()
        except StopIteration:
            pass
        except Exception as e:  # a gate error is a rejection, never a pass
            self.fail(f"gate error: {e}")
        return {"gate_version": VERSION, "verdict": "fail" if self.reasons else "pass",
                "base": self.base, "head": self.head, "reasons": self.reasons, "notes": self.notes,
                "metrics": self.metrics, "checks": self.checks}


def summary_md(v: dict) -> str:
    lines = [f"## Night Shift gate: {v['verdict'].upper()}", "",
             f"base `{v['base'][:10]}` head `{v['head'][:10]}` · gate {v['gate_version']}", ""]
    if v["reasons"]:
        lines += ["### Why it failed"] + [f"- {r}" for r in v["reasons"]] + [""]
    if v["metrics"]:
        lines += ["### Metrics"] + [f"- {k}: {val}" for k, val in v["metrics"].items()] + [""]
    if v["checks"]:
        lines += ["### Commands", "| stage | command | exit | secs |", "|---|---|---|---|"]
        lines += [f"| {c['stage']} | `{c['cmd']}` | {c['code']} | {c['secs']} |" for c in v["checks"]]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--summary", type=Path)
    ap.add_argument("--no-run", action="store_true", help="static checks only (no commands)")
    ap.add_argument("--selftest", action="store_true", help="only run setup, checks and tests on --base")
    a = ap.parse_args(argv)
    cfg = tomllib.loads(a.config.read_text(encoding="utf-8"))
    repo = a.repo.resolve()
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", a.base], capture_output=True, text=True).stdout.strip()
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", a.head], capture_output=True, text=True).stdout.strip()
    v = Gate(repo, base or a.base, head or a.head, cfg, run=not a.no_run, selftest=a.selftest).run()
    if a.out:
        a.out.write_text(json.dumps(v, indent=2), encoding="utf-8")
    md = summary_md(v)
    if a.summary:
        a.summary.write_text(md, encoding="utf-8")
    print(md)
    return 0 if v["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
