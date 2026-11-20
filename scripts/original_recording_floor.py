"""Conservative admission floor from an immutable original post-check recording.

This is a read-only admission check, not a correction of State's event clock.
Missing historical metadata holds admission; it never spends a release attempt.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
import subprocess
from typing import Any

if __package__:
    from .embargo import eligible_at, parse_utc_milliseconds
    from .release_qualification import qualify_repository
else:
    from embargo import eligible_at, parse_utc_milliseconds
    from release_qualification import qualify_repository

REPOSITORY = "leanprover/lean-eval-submissions"


class RecordingFloorError(ValueError):
    """Original post-check recording is not independently established."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RecordingFloorError(message)


def _git(root: pathlib.Path, *args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", "--no-replace-objects", "-C", str(root), *args], check=True, capture_output=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise RecordingFloorError("original immutable Git evidence is unavailable") from error


def _json(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            _require(key not in result, "duplicate JSON field in original evidence")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def _time(value: Any) -> dt.datetime:
    _require(isinstance(value, str), "recording metadata timestamp is missing")
    # The original base recorder uses whole UTC seconds. Reject other
    # spellings rather than silently changing the precision bound.
    parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    _require(parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "noncanonical recording clock")
    return parsed


def _events(root: pathlib.Path, commit: str, subject: str) -> list[dict[str, Any]]:
    paths = _git(root, "grep", "-l", "-F", subject, commit, "--", "events").decode().splitlines()
    _require(len(paths) <= 100, "ambiguous original State event inventory")
    events = [_json(_git(root, "show", path)) for path in paths]
    return [event for event in events if event["subject_id"] == subject]


def _one(events: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    matches = [event for event in events if event["event_type"] == kind]
    _require(len(matches) == 1, f"expected one original {kind}")
    return matches[0]


def recording_floor(plan: dict[str, Any], *, state_root: pathlib.Path,
                    results_root: pathlib.Path) -> str:
    request = plan["request"]
    controller = request["controller"]
    state_commit = controller["state_commit"]
    qualify_repository(state_root, "leanprover/lean-eval-state", expected_head=state_commit)
    results_head = qualify_repository(results_root, REPOSITORY)
    result, identity = request["result"], request["submission"]
    commit, identifier = result["commit"], result["result_id"]
    _git(results_root, "merge-base", "--is-ancestor", commit, results_head)
    events = _events(state_root, state_commit, identifier)
    recorded = _one(events, "result.recorded")
    _require(not any(e["event_type"] == "result.retracted" for e in events), "Result is retracted")
    _require(recorded["payload"] == {
        "submission_id": identity["submission_id"], "problem_id": result["problem_id"],
        "statement_revision": result["statement_revision"], "result_commit": commit,
        "tree_digest": result["tree_digest"],
    }, "canonical original result.recorded binding differs")
    submission_events = _events(state_root, state_commit, identity["submission_id"])
    received = _one(submission_events, "submission.received")
    accepted = _one(submission_events, "evaluation.accepted")
    _require(request["release"]["accepted_at"] == accepted["occurred_at"],
             "canonical acceptance clock differs from plan")
    starts = [e for e in submission_events if e["event_id"] == accepted["causation_event_id"]
              and e["event_type"] == "evaluation.started"]
    _require(len(starts) == 1 and recorded["causation_event_id"] == accepted["event_id"],
             "original evaluation causation differs")
    started = starts[0]
    source = received["payload"]
    _require(received["actor"] == {"kind": "github", "login": identity["owner_login"]}
             and all(source.get(key) == value for key, value in {
                 "declared_model": identity["declared_model"], "problem_id": result["problem_id"],
                 "statement_revision": result["statement_revision"],
             }.items()), "original submission identity differs")
    path = f"results/{identity['owner_login'].lower()}.json"
    raw = _git(results_root, "show", f"{commit}:{path}")
    entries = [{"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}]
    digest = hashlib.sha256(b"lean-eval-result-tree-v1\0" + json.dumps(
        entries, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    _require(digest == result["tree_digest"], "original Result tree digest differs")
    document = _json(raw)
    _require(document.get("schema_version") == 2
             and document.get("user", "").lower() == identity["owner_login"].lower(),
             "original Results document identity differs")
    rows = [row for row in document["results"] if row["result_id"] == identifier]
    _require(len(rows) == 1, "ambiguous original Result row")
    row = rows[0]
    _require(all(row.get(key) == value for key, value in {
        "declared_model": identity["declared_model"], "problem_id": result["problem_id"],
        "statement_revision": result["statement_revision"],
        "benchmark_commit": started["payload"]["benchmark_commit"],
        "intake": {"kind": "server", "submission_id": identity["submission_id"]},
        "submission": {"kind": "github_repo", "repo": source["source_repository"],
                       "ref": source["source_commit"], "public": source["source_visibility"] == "public"},
    }.items()), "original Result UUID, Source, or provenance differs")
    # This is the existing trusted post-check receipt clock, not a new caller
    # timestamp. The original workflow samples it only after evaluation and the
    # successful recording step. State binds the exact immutable Results file.
    recorded_at = recorded["occurred_at"]
    recording_time = parse_utc_milliseconds(recorded_at)
    _require(recorded["actor"] == {"kind": "system"}
             and recording_time > parse_utc_milliseconds(accepted["occurred_at"]),
             "original result.recorded clock/actor differs")
    # Base recorder UTC seconds are truncated: require the event at/after the
    # upper bound of that second rather than pretending this is checker finish.
    _require(_time(row["accepted_at"]) + dt.timedelta(seconds=1) <= recording_time,
             "canonical Result clock does not bound original recording")
    return max(request["release"]["eligible_at"], eligible_at(recorded_at))


def admit(plan: dict[str, Any], trusted_as_of: str, **kwargs: Any) -> dict[str, Any]:
    if plan["kind"] != "execution":
        return plan
    floor = recording_floor(plan, **kwargs)
    if parse_utc_milliseconds(trusted_as_of) < parse_utc_milliseconds(floor):
        return {"schema_version": 1, "kind": "not_due", "next_release_at": floor}
    return plan
