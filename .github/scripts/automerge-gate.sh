#!/usr/bin/env bash
# Auto-merge gate. Executed by .github/workflows/auto-merge.yml, which runs on
# the DEFAULT branch's definition whenever one of the PR's workflows completes
# — so neither this script nor the merge token ever comes from a PR's own
# head. The review workflows themselves hold no merge token.
#
# Nothing is ever ARMED: GitHub's auto-merge is not bound to a head, so an
# arming made for one head would merge whatever head the PR has when its
# checks turn green. This gate instead re-evaluates on every completion and
# merges only with the head SHA pinned (--match-head-commit): a merge happens
# only for the exact commit whose reviews it verified, and a push in between
# makes the merge fail closed. If required checks are still pending the
# attempt is refused by GitHub and the next completion re-evaluates.
#
# Both review agents submit their PR reviews as github-actions[bot], so
# GitHub's own review decision only reflects whichever agent reviewed LAST;
# the gate requires the latest review of every agent this PR needs to be an
# approval of the current head.
#
# The reviews only mean something when everything that shaped them is the
# base branch's: a pull_request workflow runs the PR head's definition, and
# the review agents read the head's instruction files. So the head's
# .github/, .claude/, CLAUDE.md (root or nested), .mcp.json and root
# action.yml must be byte-identical to the base branch's, and the PR must not
# change them at all; otherwise the gate refuses and the PR is merged by hand.
# Every workflow in this repository declares a read-only token, so no
# head-executed job can post a review, and the review agents execute nothing
# from the head (Read/Grep/Glob).
#
# Threat model, stated: the gate defends against the CONTENT of one pull
# request (code an agent was steered into committing). It does not defend
# against whoever holds push rights: a second, attacker-authored PR carrying
# a workflow with pull-requests: write could post forged approvals on any PR,
# and that actor could equally push to main. Per-agent App identities and
# protected environments would close that; both are outside this gate.
#
# Merging is verified, not assumed: the PR's merge state must be CLEAN (every
# required check green, no conflict) at the verified head, because the merge
# token belongs to an administrator and branch protection does not bind
# administrators here. Dependabot PRs are left to their own gate.
#
# Whether the security agent is required is derived from facts a PR cannot
# influence from its branch: the base branch's security-review.yml path filter
# matched against the PR's full changed-file list; any Security Review Agent
# run for the head; a standing security REQUEST_CHANGES on the PR. Every probe
# fails CLOSED (required and unsatisfied, with a ::warning::).
#
# Residual, stated: an agent's identity is the review body header its Submit
# step writes; see the threat model above for what that does and does not
# cover.
#
# Env: GH_TOKEN (PAT with merge rights), PR, REPO, DRY_RUN=1 to print the
# decision without acting.
set -uo pipefail

PR="${PR:?}"; REPO="${REPO:?}"; DRY_RUN="${DRY_RUN:-0}"
say() { printf '%s\n' "$*" | tr -d '\000-\010\013-\037'; }          # script-authored lines only
clean() { printf '%s' "$*" | tr -d '\000-\037' | cut -c1-200; }     # PR-influenced values: no newline can start a workflow command

merge_now() {
  # The merge state is GitHub's own verdict on required checks, conflicts and
  # review requirements; it can be UNKNOWN for a moment after a push.
  for ATTEMPT in 1 2 3; do
    MS=$(gh pr view "$PR" --repo "$REPO" --json mergeStateStatus,headRefOid --jq '"\(.mergeStateStatus) \(.headRefOid)"' 2>/dev/null) || MS="PROBE_FAILED -"
    STATE=${MS%% *}; NOW_SHA=${MS##* }
    [ "$STATE" = "UNKNOWN" ] && [ "$ATTEMPT" -lt 3 ] && { sleep 15; continue; }
    break
  done
  [ "$NOW_SHA" = "$HEAD_SHA" ] || { say "Not merged: the head moved from $HEAD_SHA to $(clean "$NOW_SHA") while evaluating"; return 0; }
  if [ "$STATE" != "CLEAN" ]; then
    ROLLUP=$(gh pr view "$PR" --repo "$REPO" --json statusCheckRollup --jq '[.statusCheckRollup[] | select((.conclusion // "") != "SUCCESS" and (.conclusion // "") != "SKIPPED" and (.conclusion // "") != "NEUTRAL") | "\(.name // .context)=\(.conclusion // .status // "pending")"] | join(", ")' 2>/dev/null || true)
    say "::notice::Not merged: merge state is $(clean "$STATE") at $HEAD_SHA (${ROLLUP:-no failing or pending checks listed}); the next completion re-evaluates"
    return 0
  fi
  if [ "$DRY_RUN" = "1" ]; then say "DRY_RUN: would merge #$PR at $HEAD_SHA (merge state CLEAN)"; return 0; fi
  for ATTEMPT in 1 2 3; do
    OUT=$(gh pr merge "$PR" --repo "$REPO" --squash --match-head-commit "$HEAD_SHA" 2>&1) && { say "Merged #$PR at $HEAD_SHA"; return 0; }
    say "::notice::merge attempt $ATTEMPT/3 refused: $(clean "$OUT")"
    [ "$ATTEMPT" -lt 3 ] && sleep 15
  done
  say "::warning::PR #$PR was not merged although its merge state was CLEAN; the next completion re-evaluates"
}
disarm() {
  # nothing is armed by this gate; disarming covers an arming made by hand or by an older gate
  if [ "$DRY_RUN" = "1" ]; then say "DRY_RUN: would not merge #$PR ($1)"; return 0; fi
  gh pr merge "$PR" --repo "$REPO" --disable-auto >/dev/null 2>&1 || true
  say "Not merged: $1"
}

PRJSON=$(gh pr view "$PR" --repo "$REPO" --json headRefOid,baseRefName,state,changedFiles,author 2>/dev/null) || { disarm "could not read PR #$PR"; exit 0; }
[ "$(printf '%s' "$PRJSON" | jq -r .state)" = "OPEN" ] || { say "PR #$PR is not open; nothing to do"; exit 0; }
HEAD_SHA=$(printf '%s' "$PRJSON" | jq -r .headRefOid)
BASE_REF=$(printf '%s' "$PRJSON" | jq -r .baseRefName)
N_FILES=$(printf '%s' "$PRJSON" | jq -r '.changedFiles // 0')
AUTHOR=$(printf '%s' "$PRJSON" | jq -r '.author.login // ""')
case "$AUTHOR" in
  dependabot\[bot\]|app/dependabot) say "PR #$PR is a Dependabot PR; its own gate in dependency-review.yml decides, nothing to do here"; exit 0;;
esac
case "$N_FILES" in ''|*[!0-9]*) disarm "could not determine the PR's file count ('$(clean "$N_FILES")')"; exit 0;; esac

# ── the PR's files: a PR-controlled workflow definition is never armed ─────
if [ "$N_FILES" -gt 3000 ]; then disarm "PR changes $N_FILES files, more than the files API lists; manual merge required"; exit 0; fi
CHANGED=$(gh api "repos/$REPO/pulls/$PR/files" --paginate --jq '.[].filename' 2>/dev/null) || { disarm "could not list the PR files"; exit 0; }
WF_CHANGE=$(printf '%s\n' "$CHANGED" | grep -m1 -E '^\.github/|(^|/)CLAUDE\.md$|^\.claude/|^\.mcp\.json$|^action\.ya?ml$' || true)
if [ -n "$WF_CHANGE" ]; then
  disarm "PR changes the workflow or reviewer-instruction surface ($(clean "$WF_CHANGE")); reviews produced under a PR-controlled definition are not trusted, manual merge required"; exit 0
fi
# The head's copy of that surface must also equal the base branch's current
# copy: a PR branched before a change to it would otherwise run the older
# definition without changing anything itself.
BASE_SHA=$(gh api "repos/$REPO/branches/$BASE_REF" --jq .commit.sha 2>/dev/null) || { disarm "could not read the base branch"; exit 0; }
HEAD_TREE=$(gh api "repos/$REPO/git/trees/$HEAD_SHA" --jq '.tree[] | select(.path == ".github" or .path == ".claude" or .path == "CLAUDE.md" or .path == ".mcp.json" or .path == "action.yml" or .path == "action.yaml") | "\(.path) \(.sha)"' 2>/dev/null | sort) || { disarm "could not read the head tree"; exit 0; }
BASE_TREE=$(gh api "repos/$REPO/git/trees/$BASE_SHA" --jq '.tree[] | select(.path == ".github" or .path == ".claude" or .path == "CLAUDE.md" or .path == ".mcp.json" or .path == "action.yml" or .path == "action.yaml") | "\(.path) \(.sha)"' 2>/dev/null | sort) || { disarm "could not read the base tree"; exit 0; }
if [ "$HEAD_TREE" != "$BASE_TREE" ]; then
  disarm "the head's workflow or reviewer-instruction surface differs from the base branch's current one (rebase or merge $BASE_REF first); manual merge otherwise"; exit 0
fi

# ── the reviews at head ─────────────────────────────────────────────────────
REVIEWS=$(gh api "repos/$REPO/pulls/$PR/reviews" --paginate \
  --jq '.[] | select(.user.login == "github-actions[bot]")
        | [ ((.body // "") | if startswith("## Security Review Agent") then "security"
                     elif startswith("## Code Review Agent") then "code"
                     else "other" end), .state, .commit_id ] | @tsv') || { disarm "could not read the PR reviews"; exit 0; }
latest() { printf '%s\n' "$REVIEWS" | awk -F'\t' -v k="$1" '$1 == k { line = $0 } END { print line }'; }
for KIND in code security; do
  L=$(latest "$KIND")
  if [ -n "$L" ] && [ "$(printf '%s' "$L" | cut -f2)" = "CHANGES_REQUESTED" ] && [ "$(printf '%s' "$L" | cut -f3)" = "$HEAD_SHA" ]; then
    disarm "$KIND review requested changes on the current head"; exit 0
  fi
done

# ── is the security agent required? ────────────────────────────────────────
SECURITY_REQUIRED=0
BASE_WF=$(gh api "repos/$REPO/contents/.github/workflows/security-review.yml?ref=$BASE_REF" --jq .content 2>/dev/null | base64 -d 2>/dev/null) || BASE_WF="__FETCH_FAILED__"
if [ "$BASE_WF" = "__FETCH_FAILED__" ]; then
  LISTING=$(gh api "repos/$REPO/contents/.github/workflows?ref=$BASE_REF" --jq '.[].name' 2>/dev/null) || { say "::warning::could not list the base workflows; security review treated as required"; SECURITY_REQUIRED=1; LISTING=""; }
  if printf '%s\n' "$LISTING" | grep -qx 'security-review.yml'; then say "::warning::could not fetch the base security-review.yml; security review treated as required"; SECURITY_REQUIRED=1
  elif [ -n "$LISTING" ]; then say "Base branch has no security-review workflow; only the code review is required"; fi
else
  MATCH=$(BASE_WF_TEXT="$BASE_WF" CHANGED_FILES="$CHANGED" python3 - <<'PY'
import os, re, sys
text = os.environ.get("BASE_WF_TEXT", "")
paths = None
try:
    import yaml  # present on ubuntu-latest; the line parser below is the fallback
    doc = yaml.safe_load(text) or {}
    on = doc.get("on") or doc.get(True) or {}
    pr = on.get("pull_request") if isinstance(on, dict) else None
    if pr is None:
        print("__NO_PULL_REQUEST_TRIGGER__"); sys.exit(0)
    paths = pr.get("paths") if isinstance(pr, dict) else None
    paths = list(paths) if paths else []
except Exception:
    paths = None
if paths is None:
    paths, in_pr, in_paths, pr_indent, paths_indent = [], False, False, None, None
    for line in text.splitlines():
        stripped = line.strip(); indent = len(line) - len(line.lstrip(" "))
        if not stripped or stripped.startswith("#"): continue
        if in_paths:
            if indent > paths_indent and stripped.startswith("- "):
                paths.append(stripped[2:].strip().strip('"').strip("'")); continue
            in_paths = False
        if in_pr and pr_indent is not None and indent <= pr_indent and not stripped.startswith("- "): in_pr = False
        if stripped.startswith("pull_request:"): in_pr, pr_indent = True, indent; continue
        if in_pr and stripped.startswith("paths:"): in_paths, paths_indent = True, indent; continue
if not paths:
    print("all"); sys.exit(0)          # no filter: the security agent runs on every PR
def glob_re(g):
    if "[" in g or "]" in g or "{" in g:
        return None                    # character classes are not modeled: fail closed
    out, i = "", 0
    while i < len(g):
        if g.startswith("**/", i): out += "(?:.*/)?"; i += 3
        elif g.startswith("**", i): out += ".*"; i += 2
        elif g[i] == "*": out += "[^/]*"; i += 1
        elif g[i] == "?": out += "[^/]"; i += 1
        else: out += re.escape(g[i]); i += 1
    return re.compile("^" + out + "$")
res = []
for p in paths:
    if p.startswith("!"): continue     # negations ignored in the safe direction
    r = glob_re(p)
    if r is None:
        print("__UNMODELED_PATTERN__"); sys.exit(0)
    res.append(r)
for f in os.environ.get("CHANGED_FILES", "").split("\n"):
    if f and any(r.match(f) for r in res):
        print("match"); sys.exit(0)
print("none")
PY
) || MATCH="__PY_FAILED__"
  case "$MATCH" in
    all|match) SECURITY_REQUIRED=1; say "Security review required by the base path filter ($MATCH)";;
    none) say "No changed file matches the base security path filter";;
    *) say "::warning::path filter evaluation: $MATCH; security review treated as required"; SECURITY_REQUIRED=1;;
  esac
fi
RUNS=$(gh api "repos/$REPO/actions/workflows/security-review.yml/runs?head_sha=$HEAD_SHA&per_page=100" --paginate --jq '.workflow_runs | length' 2>/dev/null) || RUNS="__FAILED__"
if [ "$RUNS" = "__FAILED__" ]; then
  [ "$BASE_WF" != "__FETCH_FAILED__" ] && { say "::warning::could not query the security workflow runs; security review treated as required"; SECURITY_REQUIRED=1; }
elif [ "$(printf '%s\n' "$RUNS" | awk '{s+=$1} END {print s+0}')" -gt 0 ]; then
  SECURITY_REQUIRED=1; say "A Security Review Agent run exists for $HEAD_SHA"
fi
SEC_LATEST=$(latest security)
if [ -n "$SEC_LATEST" ] && [ "$(printf '%s' "$SEC_LATEST" | cut -f2)" = "CHANGES_REQUESTED" ]; then
  SECURITY_REQUIRED=1; say "A security REQUEST_CHANGES is standing; a newer security approval at head is required"
fi

# ── decide ──────────────────────────────────────────────────────────────────
REQUIRED="code"; [ "$SECURITY_REQUIRED" = "1" ] && REQUIRED="code security"
for KIND in $REQUIRED; do
  L=$(latest "$KIND"); STATE=$(clean "$(printf '%s' "$L" | cut -f2)"); SHA=$(clean "$(printf '%s' "$L" | cut -f3)")
  if [ "$STATE" != "APPROVED" ] || [ "$SHA" != "$HEAD_SHA" ]; then
    disarm "latest $KIND review is '${STATE:-none}' on '${SHA:-none}', head is $HEAD_SHA"; exit 0
  fi
done
say "Every required agent ($REQUIRED) approved $HEAD_SHA; merging PR #$PR at that head"
merge_now
