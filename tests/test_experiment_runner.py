import json
from unittest.mock import MagicMock, patch

import pytest

from ai_analysis.evaluation.experiment_runner import (
    ExperimentConfig,
    ExperimentEvaluationError,
    ExperimentParserError,
    GroundTruthValidationError,
    InvalidOpenAPIError,
    load_ground_truth,
    run_experiment,
)
from ai_analysis.llm.base import LLMProvider, LLMProviderError


API2 = "API2:2023 Broken Authentication"
API8 = "API8:2023 Security Misconfiguration"


class QueueProvider(LLMProvider):
    def __init__(self, responses):
        self.responses = iter(responses)
        self.prompts = []

    def generate(self, prompt):
        self.validate_prompt(prompt)
        self.prompts.append(prompt)
        return next(self.responses)


class FailingProvider(LLMProvider):
    def generate(self, prompt):
        self.validate_prompt(prompt)
        raise LLMProviderError("model unavailable")


def _safe(endpoint):
    return json.dumps(
        {
            "endpoint": endpoint,
            "method": "GET",
            "status": "SAFE",
            "findings": [],
        }
    )


def _vulnerable(endpoint, category, duplicate=False):
    finding = {
        "endpoint": endpoint,
        "method": "GET",
        "rule": "Semantic access-control risk",
        "owasp_category": category,
        "severity": "HIGH",
        "confidence": 0.8,
        "evidence": "The supplied endpoint context documents the risk.",
        "detected_by": "AI",
    }
    return json.dumps(
        {
            "endpoint": endpoint,
            "method": "GET",
            "status": "POTENTIAL_VULNERABILITY",
            "findings": [finding, dict(finding)] if duplicate else [finding],
        }
    )


def _write_corpus(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Evaluation API", "version": "1.0.0"},
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            }
        },
        "paths": {
            "/users": {
                "get": {
                    "security": [],
                    "responses": {"200": {"description": "Users"}},
                }
            },
            "/accounts": {
                "get": {
                    "security": [],
                    "responses": {"200": {"description": "Accounts"}},
                }
            },
            "/health": {
                "get": {"responses": {"200": {"description": "Healthy"}}}
            },
        },
    }
    labels = [
        {
            "file": "api.json",
            "endpoint": "/users",
            "method": "GET",
            "vulnerable": True,
            "owasp_category": API2,
        },
        {
            "file": "api.json",
            "endpoint": "/accounts",
            "method": "GET",
            "vulnerable": True,
            "owasp_category": API2,
        },
        {
            "file": "api.json",
            "endpoint": "/health",
            "method": "GET",
            "vulnerable": False,
            "owasp_category": None,
        },
    ]
    (tmp_path / "api.json").write_text(json.dumps(spec), encoding="utf-8")
    truth_path = tmp_path / "truth.json"
    truth_path.write_text(json.dumps(labels), encoding="utf-8")
    return truth_path


def test_ground_truth_loader_validates_records_and_file_references(tmp_path):
    truth_path = _write_corpus(tmp_path)

    records = load_ground_truth(truth_path)

    assert len(records) == 3
    assert records[0].method == "GET"

    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            [{"file": "missing.json", "endpoint": "/x", "method": "GET",
              "vulnerable": True, "owasp_category": None}]
        ),
        encoding="utf-8",
    )
    with pytest.raises(GroundTruthValidationError, match="Invalid ground-truth"):
        load_ground_truth(bad)

    bad.write_text(
        json.dumps(
            [{"file": "api.json", "endpoint": "/health", "method": "GET",
              "vulnerable": False, "owasp_category": API8}]
        ),
        encoding="utf-8",
    )
    with pytest.raises(GroundTruthValidationError, match="Invalid ground-truth"):
        load_ground_truth(bad)

    bad.write_text(
        json.dumps(
            [{"file": "api.json", "endpoint": "/health", "method": "GET",
              "vulnerable": "false", "owasp_category": None}]
        ),
        encoding="utf-8",
    )
    with pytest.raises(GroundTruthValidationError, match="Invalid ground-truth"):
        load_ground_truth(bad)


def test_ground_truth_loader_rejects_malformed_json_and_missing_spec(tmp_path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(GroundTruthValidationError, match="Malformed"):
        load_ground_truth(malformed)

    missing = tmp_path / "missing.json"
    missing.write_text(
        json.dumps(
            [{"file": "no-api.json", "endpoint": "/x", "method": "GET",
              "vulnerable": False, "owasp_category": None}]
        ),
        encoding="utf-8",
    )
    with pytest.raises(GroundTruthValidationError, match="Referenced OpenAPI"):
        load_ground_truth(missing)


def test_runner_compares_static_ai_and_hybrid_and_deduplicates(tmp_path, monkeypatch):
    truth_path = _write_corpus(tmp_path)
    provider = QueueProvider(
        [
            _vulnerable("/users", API2, duplicate=True),
            _safe("/accounts"),
            _vulnerable("/health", API8),
        ]
    )

    from ai_analysis.evaluation import experiment_runner

    original = experiment_runner.cross_validate_findings
    observed = []

    def capture_hybrid(static_findings, ai_findings):
        result = original(static_findings, ai_findings)
        observed.extend(result)
        return result

    monkeypatch.setattr(experiment_runner, "cross_validate_findings", capture_hybrid)
    result = run_experiment(
        ExperimentConfig(
            ground_truth_path=truth_path,
            model="mock-model",
            use_rag=False,
        ),
        provider=provider,
    )

    assert result.status == "COMPLETE"
    assert result.file_count == 1
    assert result.endpoint_count == 3
    assert result.static_evaluation.counts.model_dump() == {
        "true_positive": 2,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 1,
    }
    assert result.ai_evaluation.counts.true_positive == 1
    assert result.ai_evaluation.counts.false_positive == 1
    assert result.ai_evaluation.counts.false_negative == 1
    assert result.hybrid_evaluation.counts.true_positive == 2
    assert result.hybrid_evaluation.counts.false_positive == 1
    assert {item.detected_by for item in observed} == {"BOTH", "STATIC", "AI"}
    assert any(item.validation_status == "MANUAL_REVIEW" for item in observed)


def test_runner_enables_pattern_rag_with_configured_top_k(tmp_path):
    truth_path = _write_corpus(tmp_path)
    provider = QueueProvider([_safe("/users"), _safe("/accounts"), _safe("/health")])

    result = run_experiment(
        ExperimentConfig(
            ground_truth_path=truth_path,
            model="mock-model",
            use_rag=True,
            top_k=1,
        ),
        provider=provider,
    )

    assert result.use_rag is True
    assert result.top_k == 1
    assert result.pattern_count > 0
    assert all("Retrieved similar vulnerable API patterns" in p for p in provider.prompts)


def test_provider_failure_is_incomplete_and_never_counted_as_safe(tmp_path):
    truth_path = _write_corpus(tmp_path)

    result = run_experiment(
        ExperimentConfig(ground_truth_path=truth_path, model="mock-model"),
        provider=FailingProvider(),
    )

    assert result.status == "INCOMPLETE"
    assert result.successful_ai_analyses == 0
    assert result.failed_ai_analyses == 3
    assert result.ai_evaluation is None
    assert result.hybrid_evaluation is None
    assert {error.category for error in result.errors} == {"MODEL_PROVIDER"}


def test_invalid_openapi_and_parser_failures_are_distinguished(tmp_path):
    truth_path = _write_corpus(tmp_path)
    (tmp_path / "api.json").write_text(
        json.dumps({"openapi": "3.0.0", "paths": {}}), encoding="utf-8"
    )
    config = ExperimentConfig(ground_truth_path=truth_path, model="mock-model")

    with pytest.raises(InvalidOpenAPIError, match="Invalid OpenAPI"):
        run_experiment(config, provider=QueueProvider([]))

    with patch(
        "ai_analysis.evaluation.experiment_runner.parse_openapi",
        side_effect=OSError("read failed"),
    ):
        with pytest.raises(ExperimentParserError, match="Unable to parse"):
            run_experiment(config, provider=QueueProvider([]))


def test_evaluation_failure_is_reported_separately(tmp_path):
    truth_path = _write_corpus(tmp_path)
    provider = QueueProvider([_safe("/users"), _safe("/accounts"), _safe("/health")])

    with patch(
        "ai_analysis.evaluation.experiment_runner.evaluate_predictions",
        side_effect=ValueError("conflicting evaluation labels"),
    ):
        with pytest.raises(ExperimentEvaluationError, match="Unable to evaluate"):
            run_experiment(
                ExperimentConfig(ground_truth_path=truth_path, model="mock-model"),
                provider=provider,
            )


@patch("scripts.run_evaluation.run_experiment")
def test_cli_preserves_configuration_and_emits_json(mock_run, tmp_path, capsys):
    from scripts import run_evaluation

    result = MagicMock(status="COMPLETE")
    result.model_dump.return_value = {"status": "COMPLETE"}
    mock_run.return_value = result

    exit_code = run_evaluation.main(
        [
            "--ground-truth", str(tmp_path / "truth.json"),
            "--model", "llama-test",
            "--base-url", "http://ollama.test:11434",
            "--timeout", "30",
            "--no-rag",
            "--top-k", "5",
            "--file", "api.json",
        ]
    )

    config = mock_run.call_args.args[0]
    assert config.model == "llama-test"
    assert config.base_url == "http://ollama.test:11434"
    assert config.timeout == 30
    assert config.use_rag is False
    assert config.top_k == 5
    assert config.file_filter == ["api.json"]
    assert json.loads(capsys.readouterr().out) == {"status": "COMPLETE"}
    assert exit_code == 0


def test_cli_requires_ground_truth_and_model():
    from scripts import run_evaluation

    with pytest.raises(SystemExit):
        run_evaluation.main([])
