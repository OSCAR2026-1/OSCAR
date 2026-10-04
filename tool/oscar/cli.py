#!/usr/bin/env python3
"""OSCAR command line interface.

The GT validator is deliberately a separate command path from the blind
effectiveness runtime. Only the independent evaluator reads hidden GT labels.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from oscar.paths import RESEARCH_ROOT

try:
    from oscar.runtime.blind_runtime import BlindCaseError, load_json, run_blind_case, validate_blind_case
    from oscar.workflows.case_pipeline import build_plan, make_case_blueprint, run_case, validate_case
    from oscar.evaluation.validator import analyze_active, analyze_active_case, validate_command
    from oscar.workflows.auto_pipeline import auto_run, normalize
    from oscar.workflows.e2e_pipeline import run_test_set
    from oscar.workflows.stage0_onboarding import prepare_case, preparation_required_report
    from oscar.workflows.linux_case_assembly import assemble_linux_case
    from oscar.contracts.component_contract import COMPONENT_ORIGINS, validate_label_free_evidence
except ImportError:  # pragma: no cover - direct script execution
    from oscar.runtime.blind_runtime import BlindCaseError, load_json, run_blind_case, validate_blind_case
    from oscar.workflows.case_pipeline import build_plan, make_case_blueprint, run_case, validate_case
    from oscar.evaluation.validator import analyze_active, analyze_active_case, validate_command
    from oscar.workflows.auto_pipeline import auto_run, normalize
    from oscar.workflows.e2e_pipeline import run_test_set
    from oscar.workflows.stage0_onboarding import prepare_case, preparation_required_report
    from oscar.workflows.linux_case_assembly import assemble_linux_case
    from oscar.contracts.component_contract import COMPONENT_ORIGINS, validate_label_free_evidence


def init_case(args: argparse.Namespace) -> int:
    spec = make_case_blueprint(
        advisory=args.advisory,
        package=args.package,
        vulnerable_version=args.vulnerable_version,
        fixed_version=args.fixed_version,
        experiment_type=args.experiment_type,
        repository=args.repository,
        module=args.module,
        tool=args.tool,
    )
    if args.case_id:
        spec["case_id"] = args.case_id
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {"status": "BLUEPRINT", "output": str(output), "validation_errors": validate_case(spec)},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def validate_case_command(args: argparse.Namespace) -> int:
    spec = load_json(Path(args.input).resolve())
    errors = validate_case(spec, require_runner=args.require_runner)
    result = {
        "status": "OK" if not errors else "ERROR",
        "case_id": spec.get("case_id", spec.get("identity", {}).get("advisory")),
        "errors": errors,
        "blueprint": spec.get("status") == "blueprint",
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


def plan_case(args: argparse.Namespace) -> int:
    spec = load_json(Path(args.input).resolve())
    plan = build_plan(spec, Path(args.output).resolve())
    output = Path(args.plan).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "OK", "plan": str(output), "case_hash": plan["case_hash"]}, ensure_ascii=False, indent=2))
    return 0


def run_case_command(args: argparse.Namespace) -> int:
    spec = load_json(Path(args.input).resolve())
    summary = run_case(spec, Path(args.output).resolve())
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["invalid_run_count"] == 0 else 1


def run_blind_command(args: argparse.Namespace) -> int:
    try:
        spec = load_json(Path(args.case).resolve())
        prediction = run_blind_case(
            spec,
            Path(args.output).resolve(),
            base_dir=Path(args.case).resolve().parent,
        )
    except (OSError, ValueError, BlindCaseError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps(prediction, ensure_ascii=False, indent=2))
    return 0 if prediction["run_status"] == "VALID" else 2


def validate_blind_command(args: argparse.Namespace) -> int:
    errors = validate_blind_case(load_json(Path(args.case).resolve()))
    result = {"status": "OK" if not errors else "ERROR", "errors": errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


def auto_run_command(args: argparse.Namespace) -> int:
    output = Path(args.output) if args.output else Path("working_artifacts") / "vulveil_auto_runs" / "-".join(
        normalize(value)
        for value in (args.advisory, args.package, args.vulnerable_version, args.fixed_version)
    )
    result = auto_run(
        Path(args.root).resolve(),
        args.advisory,
        args.package,
        args.vulnerable_version,
        args.fixed_version,
        output.resolve(),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status") == "PREDICTION_GENERATED" and result.get("run_status") == "VALID" else 2


def _parse_component_evidence(raw: str | None, option_name: str) -> object | None:
    """Parse JSON or ``@path`` evidence while keeping the input label-free."""
    if raw is None:
        return None
    value = raw
    if raw.startswith("@"):
        path = Path(raw[1:]).expanduser()
        path_errors = validate_label_free_evidence(str(path), field=option_name)
        if path_errors:
            raise ValueError("component evidence path is not label-free: " + "; ".join(path_errors))
        try:
            value = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ValueError(f"{option_name} evidence file cannot be read: {type(exc).__name__}") from exc
    else:
        value = raw
    try:
        parsed: object = json.loads(value)
    except json.JSONDecodeError:
        parsed = value
    errors = validate_label_free_evidence(parsed, field=option_name)
    if errors:
        raise ValueError("component evidence is not label-free: " + "; ".join(errors))
    return parsed


def prepare_case_command(args: argparse.Namespace) -> int:
    try:
        report = prepare_case(
            Path(args.root).resolve(), args.advisory, args.package, args.vulnerable_version,
            args.fixed_version, args.repository, Path(args.output).resolve(),
            vulnerable_source_root=Path(args.vulnerable_source_root).resolve() if args.vulnerable_source_root else None,
            fixed_source_root=Path(args.fixed_source_root).resolve() if args.fixed_source_root else None,
            vulnerable_dependency_source_root=Path(args.vulnerable_dependency_source_root).resolve() if args.vulnerable_dependency_source_root else None,
            fixed_dependency_source_root=Path(args.fixed_dependency_source_root).resolve() if args.fixed_dependency_source_root else None,
            dependency_patch=Path(args.dependency_patch).resolve() if args.dependency_patch else None,
            source_root=Path(args.source_root).resolve() if args.source_root else None,
            tool=args.tool, tool_input=json.loads(args.tool_input) if args.tool_input else None,
            agent_task=args.agent_task, experiment_type=args.experiment_type,
            component_origin=getattr(args, "component_origin", None),
            component_repository=getattr(args, "component_repository", None),
            component_purl=getattr(args, "component_purl", None),
            component_entrypoint=getattr(args, "component_entrypoint", None),
            component_source_evidence=_parse_component_evidence(getattr(args, "component_source_evidence", None), "--component-source-evidence"),
            component_patch_evidence=_parse_component_evidence(getattr(args, "component_patch_evidence", None), "--component-patch-evidence"),
            component_advisory_evidence=_parse_component_evidence(getattr(args, "component_advisory_evidence", None), "--component-advisory-evidence"),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        report = preparation_required_report(
            Path(args.output).resolve(),
            f"Stage 0 input could not be validated: {type(exc).__name__}",
            input_data={
                "advisory": args.advisory,
                "package": args.package,
                "component_origin": getattr(args, "component_origin", None) or "DIRECT_RUNTIME_DEPENDENCY",
            },
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("status") in {"READY", "PREPARED_AWAITING_CONTAINER"} else 2


def assemble_case_command(args: argparse.Namespace) -> int:
    try:
        result = assemble_linux_case(Path(args.case), base_image=args.base_image,
                                     external_boundary=json.loads(args.external_boundary),
                                     build=args.build, build_network=args.build_network)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "ASSEMBLY_FAILED", "reason": str(exc)}, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "READY" else 2


def run_test_set_command(args: argparse.Namespace) -> int:
    result = run_test_set(
        Path(args.manifest).resolve(),
        Path(args.output).resolve(),
        Path(args.hidden_gt).resolve() if args.hidden_gt else None,
        evaluation_target=args.evaluation_target,
        workers=args.workers,
        resume=args.resume,
        environment_retries=args.retry_environment,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if result["status"] != "COMPLETED":
        return 1
    if result.get("valid_count", 0) != result.get("case_count", 0):
        return 2
    if result.get("evaluation_status") == "FAILED":
        return 3
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OSCAR blind runtime and GT validator")
    sub = parser.add_subparsers(dest="command", required=True)

    active = sub.add_parser("analyze-active", help="GT/evidence validation only")
    active.add_argument(
        "--gt",
        default=str(RESEARCH_ROOT / "03_gt" / "canonical" / "v1" / "active_cases.json"),
    )
    active.add_argument("--evidence-root")
    active.add_argument("--output", required=True)
    active.add_argument("--root", default=str(RESEARCH_ROOT))
    active.set_defaults(func=analyze_active)

    blind = sub.add_parser("run-blind", help="run OSCAR without GT files or labels")
    blind.add_argument("--case", required=True)
    blind.add_argument("--output", required=True)
    blind.set_defaults(func=run_blind_command)

    blind_validate = sub.add_parser("validate-blind-case")
    blind_validate.add_argument("--case", required=True)
    blind_validate.set_defaults(func=validate_blind_command)

    auto = sub.add_parser("auto-run", help="resolve a registered blind case and generate prediction")
    auto.add_argument("--advisory", required=True)
    auto.add_argument("--package", required=True)
    auto.add_argument("--vulnerable-version", required=True)
    auto.add_argument("--fixed-version", required=True)
    auto.add_argument("--output")
    auto.add_argument("--root", default=str(RESEARCH_ROOT))
    auto.set_defaults(func=auto_run_command)

    prepare = sub.add_parser("prepare-case", help="Stage 0: build a label-free case from any supported OSS component origin")
    prepare.add_argument("--advisory", required=True)
    prepare.add_argument("--package", required=True)
    prepare.add_argument("--vulnerable-version", required=True)
    prepare.add_argument("--fixed-version", required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--output", required=True)
    prepare.add_argument("--root", default=str(RESEARCH_ROOT))
    prepare.add_argument("--source-root")
    prepare.add_argument("--vulnerable-source-root")
    prepare.add_argument("--fixed-source-root")
    prepare.add_argument("--vulnerable-dependency-source-root")
    prepare.add_argument("--fixed-dependency-source-root")
    prepare.add_argument("--dependency-patch")
    prepare.add_argument("--tool")
    prepare.add_argument("--component-origin", choices=sorted(COMPONENT_ORIGINS), help="OSS component origin used for Stage 0/1 routing")
    prepare.add_argument("--component-repository", help="repository of the vulnerable component when it differs from the MCP Server")
    prepare.add_argument("--component-purl", help="package URL of the vulnerable component")
    prepare.add_argument("--component-entrypoint", help="entrypoint used to prove the Tool-to-component path")
    prepare.add_argument("--component-source-evidence", help="JSON evidence or @path; must contain no GT labels, IDs or paths")
    prepare.add_argument("--component-patch-evidence", help="JSON evidence or @path; must contain no GT labels, IDs or paths")
    prepare.add_argument("--component-advisory-evidence", help="structured OSV/public-advisory relation evidence as JSON or @path")
    prepare.add_argument("--tool-input", help="JSON object for the frozen Tool input")
    prepare.add_argument("--agent-task")
    prepare.add_argument("--experiment-type", default="SENSITIVE_INFORMATION_DISCLOSURE")
    prepare.set_defaults(func=prepare_case_command)

    assemble = sub.add_parser("assemble-linux-case", help="assemble and smoke-test a prepared stdio case")
    assemble.add_argument("--case", required=True)
    assemble.add_argument("--base-image", required=True, help="local pinned image reference, repo@sha256:...")
    assemble.add_argument("--external-boundary", required=True, help="offline boundary JSON with kind and initial_state_sha256")
    assemble.add_argument("--build", action="store_true")
    assemble.add_argument("--build-network", choices=("none", "default"), default="none")
    assemble.set_defaults(func=assemble_case_command)

    test_set = sub.add_parser("run-test-set", help="run label-free blind cases and optionally evaluate hidden GT")
    test_set.add_argument("--manifest", required=True)
    test_set.add_argument("--output", required=True)
    test_set.add_argument("--hidden-gt")
    test_set.add_argument("--evaluation-target", choices=("agent-observation", "concrete-impact"))
    test_set.add_argument("--workers", type=int, default=1, help="parallel blind case workers (default: 1)")
    test_set.add_argument("--resume", action="store_true", help="reuse matching label-free predictions in the output directory")
    test_set.add_argument("--retry-environment", type=int, default=0, help="retry only environment-classified failures without replacing the original prediction")
    test_set.set_defaults(func=run_test_set_command)

    init = sub.add_parser("init-case", help="legacy runner-adapter blueprint")
    init.add_argument("--output", required=True)
    init.add_argument("--advisory", required=True)
    init.add_argument("--package", required=True)
    init.add_argument("--vulnerable-version", required=True)
    init.add_argument("--fixed-version", required=True)
    init.add_argument("--experiment-type", required=True)
    init.add_argument("--repository", default="")
    init.add_argument("--module", default="")
    init.add_argument("--tool", default="")
    init.add_argument("--case-id")
    init.set_defaults(func=init_case)

    validate_case_parser = sub.add_parser("validate-case")
    validate_case_parser.add_argument("--input", required=True)
    validate_case_parser.add_argument("--require-runner", action="store_true")
    validate_case_parser.set_defaults(func=validate_case_command)

    plan = sub.add_parser("plan-case")
    plan.add_argument("--input", required=True)
    plan.add_argument("--plan", required=True)
    plan.add_argument("--output", required=True)
    plan.set_defaults(func=plan_case)

    run = sub.add_parser("run-case", help="legacy runner contract smoke; use run-blind for predictions")
    run.add_argument("--input", required=True)
    run.add_argument("--output", required=True)
    run.set_defaults(func=run_case_command)

    validate = sub.add_parser("validate", help="validate GT/evidence validator output")
    validate.add_argument("--input", required=True)
    validate.set_defaults(func=validate_command)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
