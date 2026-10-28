#!/usr/bin/env python3
"""Night Shift merge step: runs in the trusted `merge` job after the gate passed, or records a rejection.

It runs from the base branch's `.night-shift/merge.py` in a checkout of the base branch, with
GH_TOKEN set to the workflow's GITHUB_TOKEN. It never runs code from the agent's branch.

  merge.py merge  --branch B --head SHA --base SHA --verdict verdict.json
  merge.py reject --branch B --head SHA --base SHA --verdict verdict.json

merge:
  1. [deploy] staging: merge the head into `staging_branch` (if set), dispatch the deploy
     workflow there, wait; failure = rejection.
  2. push mode: merge commit (--no-ff) of the tested head into base, pushed to origin.
     pr mode: open a PR, bring it up to date, dispatch the required check workflows, wait, merge.
  3. [deploy] live: dispatch the deploy workflow on base, wait. On failure revert the merge,
     redeploy, and send Narathip an iMessage through the alert hub (unless `self_rollback`:
     the deploy workflow reverts and alerts by itself).
  4. Delete the branch and append one line to `results.jsonl` on the `night-shift-log` branch.
reject: append the rejection to the log and delete the branch.

Alerts (iMessage via the Email Screening alert hub, ALERT_KEY secret) go out only when something
broke: a revert, a failed redeploy, or an error inside this script. A rejected branch is normal.
Stdlib + git + gh; Python 3.11+.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import time
import tomllib
import urllib.request
from pathlib import Path

ALERT_URL = "https://email-screening.narathip.workers.dev/alert"
LOG_BRANCH = "night-shift-log"
REPO = os.environ.get("GITHUB_REPOSITORY", "")
NAME = REPO.rsplit("/", 1)[-1]  # repo name for the iMessage, without the owner


def run(*cmd, check=True, cwd=None) -> str:
    p = subprocess.run(list(cmd), capture_output=True, text=True, cwd=cwd)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed: {(p.stderr or p.stdout).strip()[:400]}")
    return p.stdout.strip()


def git(*args, check=True) -> str:
    return run("git", *args, check=check)


def alert(type_: str, what: str, means: str = "", do: str = "", link: str = ""):
    """One iMessage in the standard shape (imessage-writing skill, Narathip 2026-10-18):
    type broken|fixed|needs-you, the point first, what it means, one action, a link."""
    key = os.environ.get("ALERT_KEY")
    print(f"ALERT: {type_}: {what} | {means} | {do} | {link}")
    if not key:
        print("::warning::ALERT_KEY secret not set; alert only in the log")
        return
    body = json.dumps({"type": type_, "what": what, "means": means or None, "do": do or None,
                       "link": link or None, "agent": "claude", "source": "night-shift"}).encode()
    req = urllib.request.Request(ALERT_URL, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-Alert-Key": key,
                                          "User-Agent": "night-shift/1.0"})  # Cloudflare blocks Python-urllib
    try:
        urllib.request.urlopen(req, timeout=20).read()
    except Exception as e:  # never fail the job because the alert hub is down
        print(f"::warning::alert hub unreachable: {e}")


def dispatch_and_wait(workflow: str, ref: str, inputs: dict | None = None, timeout=1800) -> tuple[bool, str]:
    """Dispatch a workflow on ref and wait for that run. Returns (success, run url)."""
    started = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=5)
    args = ["gh", "workflow", "run", workflow, "--repo", REPO, "--ref", ref]
    for k, v in (inputs or {}).items():
        args += ["-f", f"{k}={v}"]
    run(*args)
    run_id, url = None, ""
    deadline = time.time() + 120
    while time.time() < deadline and not run_id:
        time.sleep(8)
        rows = json.loads(run("gh", "run", "list", "--repo", REPO, "--workflow", workflow, "--branch", ref,
                              "--event", "workflow_dispatch", "--limit", "10",
                              "--json", "databaseId,createdAt,url"))
        for r in rows:
            if dt.datetime.fromisoformat(r["createdAt"].replace("Z", "+00:00")) >= started:
                run_id, url = r["databaseId"], r["url"]
                break
    if not run_id:
        return False, f"could not find the dispatched {workflow} run"
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(15)
        r = json.loads(run("gh", "run", "view", str(run_id), "--repo", REPO, "--json", "status,conclusion"))
        if r["status"] == "completed":
            return r["conclusion"] == "success", url
    return False, f"{url} (timed out)"


# Checks from main (2026-10-28): run on pull_request_target, so a workflow-token PR's held run of them has
# that event, not pull_request. Required checks named here are waited for before the merge.
FROM_MAIN_CHECKS = ("checks-from-main", "gates-from-main")


def approve_held(branch: str):
    """Approve every run on the branch that waits for approval, from either PR event."""
    for event in ("pull_request", "pull_request_target"):
        rows = json.loads(run("gh", "run", "list", "--repo", REPO, "--branch", branch, "--event", event,
                              "--limit", "20", "--json", "databaseId,status,conclusion", check=False) or "[]")
        for r in rows:
            if "action_required" in (r.get("status"), r.get("conclusion")):
                run("gh", "api", "-X", "POST", f"repos/{REPO}/actions/runs/{r['databaseId']}/approve", check=False)


def wait_from_main(pr: str, branch: str, timeout=1800) -> tuple[bool, str]:
    """Wait for the PR's checks-from-main / gates-from-main (approving held runs). (True, "") when it
    passed or skipped, or never appeared in 3 minutes (the repo does not have it; the merge then says)."""
    start = time.time()
    while time.time() - start < timeout:
        approve_held(branch)
        rows = json.loads(run("gh", "pr", "checks", pr, "--repo", REPO, "--json", "name,state,link",
                              check=False) or "[]")
        mine = [r for r in rows if r.get("name") in FROM_MAIN_CHECKS]
        if not mine and time.time() - start > 180:
            print("no checks-from-main / gates-from-main on this PR after 3 minutes; merging as before "
                  "(if the repo requires one, GitHub refuses the merge and says which)")
            return True, ""
        if mine and all(r.get("state") not in ("PENDING", "QUEUED", "IN_PROGRESS", "EXPECTED") for r in mine):
            bad = [r for r in mine if r.get("state") not in ("SUCCESS", "SKIPPED", "NEUTRAL")]
            return (not bad), (bad[0].get("link", "") if bad else "")
        time.sleep(15)
    return False, f"{pr}: checks from main did not finish (timed out)"


def pr_checks_and_wait(workflow: str, branch: str, timeout=1800) -> tuple[bool, str]:
    """A PR opened by the workflow token gets its pull_request runs held for approval
    ("action_required"). Approve them and wait; required checks are judged on the PR's
    own run. Falls back to a workflow_dispatch run when no pull_request run appears."""
    deadline = time.time() + 90
    run_id = None
    while time.time() < deadline and not run_id:
        rows = json.loads(run("gh", "run", "list", "--repo", REPO, "--workflow", workflow, "--branch", branch,
                              "--event", "pull_request", "--limit", "5", "--json", "databaseId,status,conclusion"))
        for r in rows:
            run_id = r["databaseId"]
            if r["conclusion"] == "action_required" or r["status"] == "action_required":
                run("gh", "api", "-X", "POST", f"repos/{REPO}/actions/runs/{run_id}/approve", check=False)
            break
        if not run_id:
            time.sleep(10)
    if not run_id:
        return dispatch_and_wait(workflow, branch, timeout=timeout)
    url = f"https://github.com/{REPO}/actions/runs/{run_id}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(15)
        r = json.loads(run("gh", "run", "view", str(run_id), "--repo", REPO, "--json", "status,conclusion"))
        if r["conclusion"] == "action_required":
            run("gh", "api", "-X", "POST", f"repos/{REPO}/actions/runs/{run_id}/approve", check=False)
            continue
        if r["status"] == "completed":
            return r["conclusion"] == "success", url
    return False, f"{url} (timed out)"


def append_log(entry: dict):
    """Append one JSON line to results.jsonl on the log branch (created on first use)."""
    line = json.dumps(entry, sort_keys=True)
    wt = Path("/tmp/ns-log")
    run("rm", "-rf", str(wt))
    for attempt in range(3):
        exists = git("ls-remote", "--heads", "origin", LOG_BRANCH) != ""
        if exists:
            git("fetch", "-q", "origin", f"+refs/heads/{LOG_BRANCH}:refs/remotes/origin/{LOG_BRANCH}")
            git("worktree", "add", "-f", "--detach", str(wt), f"origin/{LOG_BRANCH}")
        else:
            git("worktree", "add", "-f", "--detach", str(wt), "HEAD")
            run("git", "checkout", "-q", "--orphan", "tmp-log", cwd=wt)
            run("git", "rm", "-rfq", ".", cwd=wt)
            (wt / "README.md").write_text("Night Shift results, one JSON line per gated branch. Written only by the "
                                          "night-shift-merge workflow.\n")
        f = wt / "results.jsonl"
        with f.open("a") as fh:
            fh.write(line + "\n")
        run("git", "add", "-A", cwd=wt)
        run("git", "-c", "user.name=night-shift", "-c", "user.email=night-shift@users.noreply.github.com",
            "commit", "-qm", f"log: {entry['branch']} {entry['outcome']}", cwd=wt)
        ok = subprocess.run(["git", "push", "-q", "origin", f"HEAD:refs/heads/{LOG_BRANCH}"], cwd=wt).returncode == 0
        git("worktree", "remove", "--force", str(wt), check=False)
        if ok:
            return
        time.sleep(5)
    print("::warning::could not append to the night-shift-log branch")


def delete_branch(branch: str):
    git("push", "-q", "origin", "--delete", branch, check=False)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["merge", "reject"])
    ap.add_argument("--branch", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--verdict", type=Path, required=True)
    a = ap.parse_args(argv)
    if not a.branch.startswith("night-shift/"):
        print("refusing: not a night-shift/ branch")
        return 1
    cfg = tomllib.loads(Path(".night-shift/config.toml").read_text())
    base_branch = cfg.get("base", "main")
    verdict = json.loads(a.verdict.read_text()) if a.verdict.exists() else {"verdict": "fail", "reasons": ["no verdict file"]}
    entry = {"time": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "repo": REPO,
             "branch": a.branch, "head": a.head, "base": a.base, "gate": verdict.get("verdict"),
             "reasons": verdict.get("reasons", []), "metrics": verdict.get("metrics", {}),
             "run": f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{REPO}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"}
    git("config", "user.name", "night-shift[bot]")
    git("config", "user.email", "night-shift@users.noreply.github.com")

    if a.mode == "reject":
        entry["outcome"] = "rejected"
        if any(r.startswith("gate error") for r in entry["reasons"]):
            print(f"gate error: {entry['reasons'][0]}")
            alert("broken", f"Nightly check could not run in {NAME}", "That night's change was not merged.",
                  "Nothing to do.", entry["run"])
        append_log(entry)
        delete_branch(a.branch)
        return 0

    try:
        deploy = cfg.get("deploy")
        git("fetch", "-q", "origin", f"+refs/heads/{a.branch}:refs/remotes/origin/{a.branch}", base_branch)
        if git("rev-parse", f"origin/{a.branch}") != a.head:
            entry.update(outcome="stale", reasons=["branch moved after the gate ran; the newer push is gated separately"])
            append_log(entry)
            return 0

        if deploy and deploy.get("staging_inputs") is not None:
            ref = a.branch
            if deploy.get("staging_branch"):
                # the staging server deploys a branch: merge the tested head into it first (never force)
                sb = deploy["staging_branch"]
                git("fetch", "-q", "origin", sb)
                git("checkout", "-q", "-B", sb, f"origin/{sb}")
                git("merge", "--no-ff", "-m", f"Night Shift staging: {a.branch}", a.head)
                git("push", "-q", "origin", f"HEAD:{sb}")
                git("checkout", "-q", base_branch)
                ref = sb
            ok, url = dispatch_and_wait(deploy["workflow"], ref, deploy["staging_inputs"])
            entry["staging"] = url
            if not ok:
                entry.update(outcome="rejected", reasons=[f"staging deploy or its checks failed: {url}"])
                append_log(entry)
                delete_branch(a.branch)
                return 0

        title = f"Night Shift: {a.branch.removeprefix('night-shift/')}"
        body = (f"Gated by night-shift-merge: {entry['run']}\nMetrics: {json.dumps(entry['metrics'])}\n\n"
                f"Night-Shift-Merge: {a.branch}")
        if cfg.get("merge_mode", "push") == "pr":
            existing = run("gh", "pr", "list", "--repo", REPO, "--head", a.branch, "--state", "open",
                           "--json", "url", "--jq", ".[0].url // empty")
            pr = existing or run("gh", "pr", "create", "--repo", REPO, "--base", base_branch, "--head", a.branch,
                                 "--title", title, "--body", body)
            entry["pr"] = pr
            run("gh", "api", "-X", "PUT", f"repos/{REPO}/pulls/{pr.rsplit('/', 1)[-1]}/update-branch", check=False)
            time.sleep(10)
            for wf in cfg.get("dispatch_before_merge", []):
                ok, url = pr_checks_and_wait(wf, a.branch)
                if not ok:
                    run("gh", "pr", "close", pr, "--repo", REPO, "--comment", f"Night Shift: required check failed: {url}",
                        check=False)
                    entry.update(outcome="rejected", reasons=[f"required check {wf} failed: {url}"])
                    append_log(entry)
                    delete_branch(a.branch)
                    return 0
            ok, url = wait_from_main(pr, a.branch)
            if not ok:
                run("gh", "pr", "close", pr, "--repo", REPO, "--comment", f"Night Shift: checks from main failed: {url}",
                    check=False)
                entry.update(outcome="rejected", reasons=[f"checks from main failed: {url}"])
                append_log(entry)
                delete_branch(a.branch)
                return 0
            run("gh", "pr", "merge", pr, "--repo", REPO, "--merge", "--subject", title, "--body", body)
            git("fetch", "-q", "origin", base_branch)
            merge_sha = git("rev-parse", f"origin/{base_branch}")
        else:
            git("checkout", "-q", "-B", base_branch, f"origin/{base_branch}")
            if git("rev-parse", "HEAD") != a.base:
                # base moved since the gate ran: gate again against the new base (once per push)
                entry.update(outcome="regate", reasons=[f"{base_branch} moved after the gate ran"])
                run("gh", "workflow", "run", "night-shift-merge.yml", "--repo", REPO, "--ref", base_branch,
                    "-f", f"branch={a.branch}")
                append_log(entry)
                return 0
            git("merge", "--no-ff", "-m", title, "-m", body, a.head)
            git("push", "-q", "origin", f"HEAD:{base_branch}")
            merge_sha = git("rev-parse", "HEAD")
        entry.update(outcome="merged", merge=merge_sha)

        if deploy and deploy.get("live_inputs") is not None:
            ok, url = dispatch_and_wait(deploy["workflow"], base_branch, deploy["live_inputs"])
            entry["live"] = url
            if not ok and deploy.get("self_rollback"):
                # the deploy script already reverted the commits on the base branch and alerted
                entry.update(outcome="reverted", revert="by deploy workflow")
            elif not ok:
                git("fetch", "-q", "origin", base_branch)
                git("checkout", "-q", "-B", base_branch, f"origin/{base_branch}")
                git("revert", "--no-edit", "-m", "1", merge_sha)
                git("push", "-q", "origin", f"HEAD:{base_branch}")
                ok2, url2 = dispatch_and_wait(deploy["workflow"], base_branch, deploy["live_inputs"])
                entry.update(outcome="reverted", revert=git("rev-parse", "HEAD"), redeploy=url2)
                if ok2:
                    alert("broken", f"A nightly change broke {NAME} and was undone",
                          "The live version is back to before.", "Nothing to do.", url)
                else:
                    alert("needs-you", f"A nightly change broke {NAME} and the undo failed",
                          "The live site may show errors now.", "Check the live site now.", url2)
        for wf in cfg.get("dispatch_after_merge", []):
            ok, url = dispatch_and_wait(wf, base_branch)
            entry.setdefault("after_merge", []).append({"workflow": wf, "ok": ok, "url": url})
            if not ok and entry["outcome"] == "merged" and cfg.get("merge_mode", "push") == "push":
                git("fetch", "-q", "origin", base_branch)
                git("checkout", "-q", "-B", base_branch, f"origin/{base_branch}")
                git("revert", "--no-edit", "-m", "1", merge_sha)
                git("push", "-q", "origin", f"HEAD:{base_branch}")
                entry.update(outcome="reverted", revert=git("rev-parse", "HEAD"))
                alert("broken", f"A nightly change in {NAME} failed a check and was undone",
                      "The main branch is back to before.", "Nothing to do.", url)
        append_log(entry)
        delete_branch(a.branch)
        return 0
    except Exception as e:
        entry.update(outcome="error", reasons=[str(e)[:500]])
        print(f"merge step error: {str(e)[:500]}")
        alert("broken", f"Nightly Repo Improvements could not merge in {NAME}",
              "The change waits on its branch; nothing else changed.", "Ask Claude to look at the run.", entry["run"])
        append_log(entry)
        return 1


if __name__ == "__main__":
    sys.exit(main())
