"""Command-line entry point for labeled static/AI/hybrid experiments."""

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai_analysis.evaluation.experiment_runner import ExperimentConfig, run_experiment


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate static, AI, and hybrid API security detection"
    )
    parser.add_argument("--ground-truth", required=True, help="Ground-truth JSON path")
    parser.add_argument("--model", required=True, help="Ollama model name")
    parser.add_argument(
        "--evaluation-dir",
        help="Base directory for relative OpenAPI file references",
    )
    parser.add_argument("--base-url", default="http://localhost:11434")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--no-rag", action="store_true", help="Disable pattern RAG")
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument(
        "--file",
        action="append",
        dest="file_filter",
        help="Evaluate only this referenced file (repeatable)",
    )
    parser.add_argument("--output", help="Write JSON result to this path")
    return parser


def main(argv=None) -> int:
    args = build_argument_parser().parse_args(argv)
    config = ExperimentConfig(
        ground_truth_path=args.ground_truth,
        model=args.model,
        evaluation_directory=args.evaluation_dir,
        base_url=args.base_url,
        timeout=args.timeout,
        use_rag=not args.no_rag,
        top_k=args.top_k,
        file_filter=args.file_filter,
    )
    result = run_experiment(config)
    rendered = json.dumps(result.model_dump(mode="json"), indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if result.status == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
