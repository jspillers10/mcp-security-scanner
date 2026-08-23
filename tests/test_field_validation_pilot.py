import json
from pathlib import Path

import pytest

from benchmark.pilot import (
    SCHEMA_ROOT,
    build_blind_packet,
    build_file_inventory,
    calculate_pilot_metrics,
    canonical_sha256,
    deterministic_select,
    initialize_quarantine,
    match_cases,
    normalize_findings,
    recall_subset_size,
    screen_public_artifact,
    select_external_review_cases,
    validate_artifact,
)
from benchmark.validation import BenchmarkInputError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = PROJECT_ROOT / "benchmark/field_validation/templates"


def _candidate(
    candidate_id,
    lineage_id=None,
    framework="framework-a",
    status="included",
    lineage_role="canonical",
    duplicate_of=None,
):
    return {
        "candidate_id": candidate_id,
        "repository_url": f"https://example.invalid/{candidate_id}",
        "discovery_query_ids": ["synthetic-query"],
        "lineage_id": lineage_id or candidate_id,
        "lineage_role": lineage_role,
        "duplicate_of": duplicate_of,
        "screening_status": status,
        "screening_reason": "synthetic unit-test record",
        "intentionally_vulnerable_training": False,
        "used_for_scanner_development": False,
        "license": {
            "declared": "MIT",
            "status": "compatible",
            "source": "synthetic test data",
            "license_file_present": True,
        },
        "strata": {
            "framework": framework,
            "maintenance": "active",
            "size_band": "small",
            "popularity_band": "not-used-for-quality",
            "application_type": "standalone",
        },
    }


def _register(candidates):
    return {
        "schema_version": "1.0",
        "study_id": "synthetic-test",
        "discovery_frozen": True,
        "queries": [],
        "candidates": candidates,
    }


def _finding(finding_id, claim_class="command-execution", line=10):
    return {
        "finding_id": finding_id,
        "tool": "mcp-security-scanner",
        "repository_id": "repo-1",
        "tool_rule_id": "MCP001",
        "claim_class": claim_class,
        "path": "server.py",
        "line": line,
        "context": "tool",
        "severity": "critical",
        "redacted_message": "redacted test message",
    }


def _case(case_id="case-1", line=10):
    return {
        "case_id": case_id,
        "study_id": "synthetic-test",
        "corpus_id": "synthetic-corpus",
        "repository_id": "repo-1",
        "commit": "a" * 40,
        "file": "server.py",
        "location": {"start_line": line, "end_line": line},
        "context": {"kind": "tool", "name": "tool"},
        "source_region": "synthetic source region",
        "claim_class": "command-execution",
        "applicable_tool_rules": {"mcp_security_scanner": ["MCP001"], "bandit": [], "semgrep": []},
        "source": "synthetic input",
        "sink": "synthetic sink",
        "attack_preconditions": "synthetic precondition",
        "relevant_control": None,
        "security_claim": "synthetic security claim",
        "threat_model_assumptions": "synthetic untrusted input assumption",
        "proposed_expected_state": "positive",
        "metric_group": "security",
        "matching": {"mode": "exact", "line_tolerance": 0},
        "disclosure_status": "not-applicable",
    }


@pytest.mark.parametrize(
    ("artifact_type", "template_name"),
    [
        ("candidate-register", "candidate-register.json"),
        ("pilot-manifest", "pilot-manifest.json"),
        ("case-inventory", "case-inventory.json"),
        ("normalized-findings", "normalized-mcp-security-scanner.json"),
        ("normalized-findings", "normalized-bandit.json"),
        ("normalized-findings", "normalized-semgrep.json"),
        ("adjudication", "adjudication.json"),
        ("review-history", "review-history.json"),
        ("review-selection", "review-selection.json"),
        ("reviewer-packet", "reviewer-packet.json"),
        ("tool-run", "tool-run.json"),
        ("evidence-record", "evidence-record.json"),
        ("pilot-metrics", "pilot-metrics.json"),
    ],
)
def test_field_validation_templates_are_schema_valid(artifact_type, template_name):
    assert (SCHEMA_ROOT / f"{artifact_type}.schema.json").is_file()
    assert validate_artifact(TEMPLATE_ROOT / template_name, artifact_type)["schema_version"] == "1.0"


def test_selection_is_deterministic_stratified_and_deduplicates_lineages():
    register = _register(
        [
            _candidate("candidate-a", framework="framework-a"),
            _candidate(
                "candidate-a-fork",
                lineage_id="candidate-a",
                framework="framework-a",
                status="duplicate",
                lineage_role="duplicate",
                duplicate_of="candidate-a",
            ),
            _candidate("candidate-b", framework="framework-b"),
            _candidate("candidate-c", framework="framework-c"),
            _candidate("candidate-excluded", status="excluded"),
        ]
    )
    first = deterministic_select(register, 3, "frozen-test-seed")
    second = deterministic_select(register, 3, "frozen-test-seed")
    assert first == second
    assert set(first["selected_candidate_ids"]) == {"candidate-a", "candidate-b", "candidate-c"}
    assert first["candidate_register_sha256"] == canonical_sha256(register)


def test_selection_fails_when_unique_lineages_are_insufficient():
    register = _register(
        [
            _candidate("candidate-a"),
            _candidate(
                "candidate-a-fork",
                lineage_id="candidate-a",
                status="duplicate",
                lineage_role="duplicate",
                duplicate_of="candidate-a",
            ),
        ]
    )
    with pytest.raises(BenchmarkInputError, match="only 1 lineages"):
        deterministic_select(register, 2, "frozen-test-seed")


def test_selection_requires_frozen_discovery_compatible_license_and_nontraining_canonical():
    candidate = _candidate("candidate-a")
    register = _register([candidate])
    register["discovery_frozen"] = False
    with pytest.raises(BenchmarkInputError, match="discovery must be frozen"):
        deterministic_select(register, 1, "seed")
    register["discovery_frozen"] = True
    candidate["license"]["status"] = "ambiguous"
    with pytest.raises(BenchmarkInputError, match="only 0 lineages"):
        deterministic_select(register, 1, "seed")
    candidate["license"]["status"] = "compatible"
    candidate["used_for_scanner_development"] = True
    with pytest.raises(BenchmarkInputError, match="only 0 lineages"):
        deterministic_select(register, 1, "seed")


def test_candidate_semantics_reject_invalid_duplicate_relationship(tmp_path):
    canonical = _candidate("candidate-a")
    duplicate = _candidate(
        "candidate-b",
        lineage_id="lineage-b",
        status="duplicate",
        lineage_role="duplicate",
        duplicate_of="candidate-a",
    )
    document = _register([canonical, duplicate])
    document["queries"] = [
        {
            "query_id": "synthetic-query",
            "service": "synthetic",
            "query": "synthetic",
            "run_date": "2026-08-23",
            "result_limit": 1,
            "ordering": "synthetic",
        }
    ]
    path = tmp_path / "candidates.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(BenchmarkInputError, match="Duplicate relationship"):
        validate_artifact(path, "candidate-register")


def test_explicit_file_inventory_hashes_python_without_importing(tmp_path):
    source = tmp_path / "nested/server.py"
    source.parent.mkdir()
    source.write_text("value = 1\nvalue += 1\n", encoding="utf-8")
    inventory = build_file_inventory(tmp_path, "repo-1", "a" * 40, [r"nested\server.py"])
    assert inventory["files"][0]["path"] == "nested/server.py"
    assert inventory["files"][0]["python_lines"] == 2
    assert inventory["files"][0]["encoding"] == "utf-8"
    assert inventory["files"][0]["source_status"] == "ready"
    assert inventory["files"][0]["scanner_status"] == "pending"
    assert len(inventory["scoped_tree_sha256"]) == 64


def test_file_inventory_rejects_escape_and_non_python(tmp_path):
    outside = tmp_path.parent / "outside.py"
    outside.write_text("pass\n", encoding="utf-8")
    with pytest.raises(BenchmarkInputError, match="escapes"):
        build_file_inventory(tmp_path, "repo-1", "a" * 40, ["../outside.py"])
    with pytest.raises(BenchmarkInputError, match="not Python"):
        build_file_inventory(tmp_path, "repo-1", "a" * 40, ["README.md"])


def test_file_inventory_detects_python_encoding_and_records_decode_failure(tmp_path):
    latin = tmp_path / "latin.py"
    latin.write_bytes("# coding: latin-1\nname = 'caf\xe9'\n".encode("latin-1"))
    invalid = tmp_path / "invalid.py"
    invalid.write_bytes(b"# coding: ascii\nvalue = '\xff'\n")
    inventory = build_file_inventory(tmp_path, "repo-1", "a" * 40, ["latin.py", "invalid.py"])
    by_path = {item["path"]: item for item in inventory["files"]}
    assert by_path["latin.py"]["encoding"] == "iso-8859-1"
    assert by_path["latin.py"]["source_status"] == "ready"
    assert by_path["invalid.py"]["source_status"] == "encoding-error"
    assert by_path["invalid.py"]["scanner_status"] == "not-presented"


def test_file_inventory_rejects_symlinks_when_supported(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("pass\n", encoding="utf-8")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(BenchmarkInputError, match="symlink"):
        build_file_inventory(tmp_path, "repo-1", "a" * 40, ["link.py"])


def test_normalization_is_stable_and_tool_specific():
    raw = [
        {
            "tool_rule_id": "MCP001",
            "claim_class": "command-execution",
            "path": r"nested\server.py",
            "line": 7,
            "context": "tool",
            "severity": "critical",
            "redacted_message": "redacted",
        }
    ]
    first = normalize_findings("mcp-security-scanner", "repo-1", raw)
    second = normalize_findings("mcp-security-scanner", "repo-1", raw)
    assert first == second
    assert first["findings"][0]["path"] == "nested/server.py"
    with pytest.raises(BenchmarkInputError, match="Unsupported"):
        normalize_findings("unknown", "repo-1", raw)


def test_normalization_preserves_duplicate_physical_findings():
    raw = [
        {
            "tool_rule_id": "MCP001",
            "claim_class": "command-execution",
            "path": "server.py",
            "line": 7,
            "context": "tool",
            "redacted_message": "duplicate",
        },
        {
            "tool_rule_id": "MCP001",
            "claim_class": "command-execution",
            "path": "server.py",
            "line": 7,
            "context": "tool",
            "redacted_message": "duplicate",
        },
    ]
    normalized = normalize_findings("mcp-security-scanner", "repo-1", raw)["findings"]
    assert len(normalized) == 2
    assert normalized[0]["physical_identity"] == normalized[1]["physical_identity"]
    assert {item["occurrence"] for item in normalized} == {1, 2}
    assert len({item["finding_id"] for item in normalized}) == 2


def test_semantic_location_matching_is_one_to_one():
    cases = [_case()]
    findings = [_finding("finding-a"), _finding("finding-b")]
    matched = match_cases(cases, findings)
    assert len(matched["matches"]) == 1
    assert matched["unmatched_case_ids"] == []
    assert len(matched["unmatched_finding_ids"]) == 1


def test_matching_maximizes_cardinality_before_priority():
    broad = _case("case-a-broad", line=10)
    broad["matching"] = {"mode": "line-tolerant", "line_tolerance": 1}
    narrow = _case("case-z-narrow", line=10)
    findings = [_finding("finding-a", line=10), _finding("finding-b", line=11)]
    matched = match_cases([broad, narrow], findings)
    assert len(matched["matches"]) == 2
    pairs = {(item["case_id"], item["finding_id"]) for item in matched["matches"]}
    assert pairs == {("case-a-broad", "finding-b"), ("case-z-narrow", "finding-a")}


def test_matching_does_not_apply_implicit_tolerance():
    assert match_cases([_case(line=10)], [_finding("finding-a", line=11)])["matches"] == []


def test_blind_packet_deduplicates_and_omits_tool_outcomes():
    selection = select_external_review_cases(
        [_case()], {"mandatory-high": ["case-1"], "random": ["case-1"]}, [], "review-seed"
    )
    packet = build_blind_packet([_case()], [], selection)
    assert packet["item_count"] == 1
    serialized = json.dumps(packet)
    for forbidden in (
        "selection_reason",
        "finding_id",
        "tool_rule",
        "severity",
        '"TP"',
        '"FP"',
        '"FN"',
        "disputed",
        "detected",
    ):
        assert forbidden not in serialized
    assert selection["members"][0]["selection_reasons"] == ["mandatory-high", "random"]


def test_external_review_selection_deduplicates_mandatory_and_samples_remaining():
    cases = []
    for index in range(40):
        case = _case(f"case-{index:02d}", line=index + 1)
        case.update(
            {
                "rule_family": f"family-{index % 2}",
                "framework": f"framework-{index % 3}",
                "detection_status": "detected" if index % 2 else "undetected",
                "case_kind": "positive" if index % 3 else "safe",
            }
        )
        cases.append(case)
    selected = select_external_review_cases(
        cases,
        {"mandatory-high": ["case-00"], "disputed": ["case-00", "case-01"]},
        [],
        "review-seed",
    )
    repeated = select_external_review_cases(
        cases,
        {"mandatory-high": ["case-00"], "disputed": ["case-00", "case-01"]},
        [],
        "review-seed",
    )
    assert selected == repeated
    random_members = [item for item in selected["members"] if item["selection_reasons"] == ["seeded-random"]]
    assert len(random_members) == 30
    assert "review-case-case-00" not in {item["review_item_id"] for item in random_members}
    assert "review-case-case-01" not in {item["review_item_id"] for item in random_members}


def test_zero_finding_source_samples_are_administrative_not_detected_cases():
    source_sample = {
        "source_sample_id": "sample-1",
        "repository_id": "repo-zero",
        "commit": "b" * 40,
        "file": "server.py",
        "source_region": "neutral source excerpt",
        "security_claim": "assess the declared claim",
        "threat_model_assumptions": "declared assumptions",
    }
    selection = select_external_review_cases([], {}, [source_sample], "review-seed")
    assert selection["members"][0]["member_kind"] == "zero-finding-source"
    packet = build_blind_packet([], [source_sample], selection)
    assert packet["item_count"] == 1
    serialized = json.dumps(packet)
    assert "zero-finding" not in serialized
    assert "selection" not in serialized


def test_public_artifact_screen_rejects_common_secret_form():
    with pytest.raises(BenchmarkInputError, match="possible GitHub token"):
        screen_public_artifact({"value": "ghp_" + "a" * 28})
    screen_public_artifact({"value": "[REDACTED]"})


def test_review_history_preserves_blind_and_output_aware_decisions(tmp_path):
    review = {
        "schema_version": "1.0",
        "study_id": "synthetic-test",
        "round_id": "review-round-1",
        "round_sequence": 1,
        "supersedes": None,
        "reviews": [
            {
                "review_record_id": "review-1",
                "review_item_id": "item-1",
                "reviewer_role_id": "external-reviewer-1",
                "review_date": "2026-08-23",
                "confidence": "high",
                "initial_blind_decision": "positive",
                "initial_blind_rationale": "synthetic rationale",
                "output_aware_decision": "safe",
                "output_aware_rationale": "synthetic discussion rationale",
                "decision_changed": True,
                "disagreement_state": "resolved",
                "resolution_method": "discussion",
                "third_reviewer_role_id": None,
                "third_reviewer_decision": None,
                "third_reviewer_rationale": "",
            }
        ],
    }
    path = tmp_path / "review.json"
    path.write_text(json.dumps(review), encoding="utf-8")
    assert validate_artifact(path, "review-history")["reviews"][0]["initial_blind_decision"] == "positive"
    review["reviews"][0]["decision_changed"] = False
    path.write_text(json.dumps(review), encoding="utf-8")
    with pytest.raises(BenchmarkInputError, match="contradictory"):
        validate_artifact(path, "review-history")


def test_adjudication_semantics_reject_missing_identity_and_self_supersession(tmp_path):
    document = json.loads((TEMPLATE_ROOT / "adjudication.json").read_text(encoding="utf-8"))
    document["round_id"] = "round-1"
    document["supersedes"] = "round-1"
    path = tmp_path / "adjudication.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(BenchmarkInputError, match="supersede itself"):
        validate_artifact(path, "adjudication")
    document["supersedes"] = None
    document["records"] = [
        {
            "record_id": "record-1",
            "case_id": None,
            "finding_id": None,
            "tool": "mcp-security-scanner",
            "outcome": "unsupported",
            "rationale": "synthetic",
            "review_record_ids": [],
            "disagreement_state": "none",
            "resolution_method": "not-needed",
            "disclosure_status": "not-applicable",
        }
    ]
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(BenchmarkInputError, match="no case or finding"):
        validate_artifact(path, "adjudication")


def test_tool_run_requires_phase5b_authorization_and_preserves_subject_prohibitions(tmp_path):
    document = json.loads((TEMPLATE_ROOT / "tool-run.json").read_text(encoding="utf-8"))
    document["execution_state"] = "completed"
    path = tmp_path / "run.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(BenchmarkInputError, match="Phase 5B"):
        validate_artifact(path, "tool-run")
    document["authorization_state"] = "phase-5b-authorized"
    document["subject_code_execution_prohibited"] = False
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(BenchmarkInputError, match="True was expected"):
        validate_artifact(path, "tool-run")


def test_metrics_separate_incremental_unique_scope_and_analyzability():
    eligible = _finding("finding-eligible")
    unique = _finding("finding-unique", claim_class="mcp-transport-auth")
    false_positive = _finding("finding-fp", line=11)
    repositories = [
        {
            "repository_id": "repo-1",
            "scoped_python_lines": 800,
            "unhandled_error": None,
            "files": [
                {"source_status": "ready", "scanner_status": "result"},
                {"source_status": "ready", "scanner_status": "supported-no-finding"},
            ],
        },
        {
            "repository_id": "repo-2",
            "scoped_python_lines": 200,
            "unhandled_error": None,
            "files": [{"source_status": "ready", "scanner_status": "parse-error"}],
        },
    ]
    adjudications = [
        {"finding_id": "finding-eligible", "outcome": "TP"},
        {"finding_id": "finding-unique", "outcome": "TP"},
        {"finding_id": "finding-fp", "outcome": "FP"},
    ]
    metrics = calculate_pilot_metrics(
        repositories,
        [eligible, unique, false_positive],
        adjudications,
        [
            {
                "claim_class": "command-execution",
                "comparison_status": "comparison-eligible",
                "bandit_rule_ids": ["B602"],
                "semgrep_rule_ids": [],
            },
            {
                "claim_class": "mcp-transport-auth",
                "comparison_status": "unique-scope",
                "bandit_rule_ids": [],
                "semgrep_rule_ids": [],
            },
        ],
        {"finding-eligible": []},
    )
    assert metrics["precision"] == {"tp": 2, "fp": 1, "value": 0.666667}
    assert metrics["repository_analyzability"] == {"successful": 1, "included": 2, "value": 0.5}
    assert metrics["comparison_eligible_incremental_signal"] == {"count": 1, "denominator": 1, "proportion": 1.0}
    assert metrics["unique_scope_validated_signal"] == {"count": 1}
    assert metrics["mapping_outcomes"]["unsupported_count"] == 0
    assert metrics["mapping_outcomes"]["unresolved_count"] == 0
    assert metrics["review_burden"]["per_scoped_thousand_python_lines"] == 1.0
    assert metrics["outcomes_not_reported"] == ["recall", "f1"]


def test_metrics_report_unsupported_and_unresolved_mappings_outside_denominators():
    unsupported = _finding("finding-unsupported", claim_class="unsupported-claim")
    unresolved = _finding("finding-unresolved", claim_class="missing-claim")
    metrics = calculate_pilot_metrics(
        [],
        [unsupported, unresolved],
        [
            {"finding_id": "finding-unsupported", "outcome": "TP"},
            {"finding_id": "finding-unresolved", "outcome": "TP"},
        ],
        [
            {
                "claim_class": "unsupported-claim",
                "comparison_status": "unsupported",
                "bandit_rule_ids": [],
                "semgrep_rule_ids": [],
            }
        ],
        {},
    )
    assert metrics["comparison_eligible_incremental_signal"]["denominator"] == 0
    assert metrics["unique_scope_validated_signal"]["count"] == 0
    assert metrics["mapping_outcomes"]["unsupported_count"] == 1
    assert metrics["mapping_outcomes"]["unresolved_count"] == 1


def test_metrics_reject_duplicate_or_contradictory_claim_mappings():
    finding = _finding("finding-1")
    adjudication = [{"finding_id": "finding-1", "outcome": "TP"}]
    duplicate = {
        "claim_class": "command-execution",
        "comparison_status": "comparison-eligible",
        "bandit_rule_ids": ["B602"],
        "semgrep_rule_ids": [],
    }
    with pytest.raises(BenchmarkInputError, match="Duplicate claim mappings"):
        calculate_pilot_metrics([], [finding], adjudication, [duplicate, duplicate], {})
    contradictory = {**duplicate, "bandit_rule_ids": []}
    with pytest.raises(BenchmarkInputError, match="no applicable baseline rule"):
        calculate_pilot_metrics([], [finding], adjudication, [contradictory], {})


@pytest.mark.parametrize(("corpus_size", "expected"), [(20, 5), (26, 6), (30, 6)])
def test_recall_subset_rounding_rule(corpus_size, expected):
    assert recall_subset_size(corpus_size) == expected


def test_quarantine_directory_is_created(tmp_path):
    quarantine = tmp_path / "quarantine"
    initialize_quarantine(quarantine)
    assert quarantine.is_dir()
