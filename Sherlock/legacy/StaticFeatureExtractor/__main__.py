"""
Command-line interface for StaticIOCExtractor.

Usage:
    python -m StaticIOCExtractor extract <path> [--floss] [--out features.json]
    python -m StaticIOCExtractor analyze <path> [--ember PATH] [--nfs PATH] \\
                                    [--threshold 0.5] [--force] [--floss] \\
                                    [--out report.json]
    python -m StaticIOCExtractor judge features.json [--feature-model model.joblib]
    python -m StaticIOCExtractor train-feature-model malware_features.jsonl --model-out model.joblib
    python -m StaticIOCExtractor ember2024-download-dataset /data/ember2024 --split challenge
    python -m StaticIOCExtractor ember2024-download-models /models/ember2024
"""
from __future__ import annotations
import argparse
import json
import logging
import sys
from pathlib import Path

from . import (
    StaticIOCExtractor,
    IOCExtractionPipeline,
    EnsembleDetector,
    HeuristicFeatureModel,
    SklearnOneClassFeatureModel,
    VALID_EMBER2024_FILE_TYPES,
    VALID_EMBER2024_SPLITS,
    download_ember2024_dataset,
    download_ember2024_models,
    ember2024_download_plan,
    vectorize_ember2024_dataset,
    static_features_from_dict,
    train_one_class_feature_model,
)


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _cmd_extract(args: argparse.Namespace) -> int:
    extractor = StaticIOCExtractor(args.path, use_floss=args.floss)
    features = extractor.extract()

    output = features.to_json(indent=2)
    if args.out:
        Path(args.out).write_text(output)
        print(f"Wrote features to {args.out}")
    else:
        print(output)

    if args.iocs:
        iocs = features.to_iocs()
        iocs_path = Path(args.iocs)
        iocs_path.write_text(json.dumps(iocs, indent=2, default=str))
        print(f"Wrote {len(iocs)} IOCs to {iocs_path}", file=sys.stderr)

    if args.assessment_out:
        feature_model = _build_feature_model(args)
        assessment = feature_model.assess(features)
        assessment_path = Path(args.assessment_out)
        assessment_path.write_text(assessment.to_json(indent=2))
        print(f"Wrote feature assessment to {assessment_path}", file=sys.stderr)

    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    detector = EnsembleDetector.default(
        ember_model_path=Path(args.ember) if args.ember else None,
        ember2024_model_path=Path(args.ember2024) if args.ember2024 else None,
        nfs_model_path=Path(args.nfs) if args.nfs else None,
        threshold=args.threshold,
    )
    feature_model = _build_feature_model(args)
    pipeline = IOCExtractionPipeline(
        detector=detector,
        feature_model=feature_model,
        use_floss=args.floss,
    )
    result = pipeline.analyze(args.path, force=args.force, rule_name=args.rule_name)

    output = json.dumps(result.to_dict(), indent=2, default=str)
    if args.out:
        Path(args.out).write_text(output)
        print(f"Wrote report to {args.out}")
    else:
        print(output)

    if args.rule_out and result.composed_rule:
        Path(args.rule_out).write_text(result.composed_rule)
        print(f"Wrote YARA rule to {args.rule_out}", file=sys.stderr)

    if result.detection.is_malicious or args.force:
        return 0
    return 0    # benign is not an error


def _cmd_judge(args: argparse.Namespace) -> int:
    features = static_features_from_dict(json.loads(Path(args.features_json).read_text(encoding="utf-8")))
    feature_model = _build_feature_model(args)
    assessment = feature_model.assess(features)
    output = assessment.to_json(indent=2)
    if args.out:
        Path(args.out).write_text(output)
        print(f"Wrote feature assessment to {args.out}")
    else:
        print(output)
    return 0


def _cmd_train_feature_model(args: argparse.Namespace) -> int:
    try:
        result = train_one_class_feature_model(
            args.jsonl,
            args.model_out,
            nu=args.nu,
            max_features=args.max_features,
            min_df=args.min_df,
            max_iter=args.max_iter,
        )
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"feature-model training failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result.to_dict(), indent=2))
    return 0


def _cmd_ember2024_download_dataset(args: argparse.Namespace) -> int:
    try:
        if args.dry_run:
            plan = ember2024_download_plan(
                args.download_dir,
                split=args.split,
                file_type=args.file_type,
            )
        else:
            plan = download_ember2024_dataset(
                args.download_dir,
                split=args.split,
                file_type=args.file_type,
            )
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"EMBER2024 dataset download failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(plan.to_dict(), indent=2))
    return 0


def _cmd_ember2024_download_models(args: argparse.Namespace) -> int:
    try:
        if args.dry_run:
            result = {
                "download_dir": args.download_dir,
                "model_glob": "*.model",
                "note": "Dry run only. This will download EMBER2024 benchmark LightGBM models via thrember.",
            }
        else:
            result = download_ember2024_models(args.download_dir)
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"EMBER2024 model download failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def _cmd_ember2024_vectorize(args: argparse.Namespace) -> int:
    try:
        result = vectorize_ember2024_dataset(
            args.data_dir,
            label_type=args.label_type,
            class_min=args.class_min,
        )
    except ImportError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"EMBER2024 vectorization failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def _build_feature_model(args: argparse.Namespace):
    model_path = getattr(args, "feature_model", None)
    if model_path:
        return SklearnOneClassFeatureModel.load(
            model_path,
            threshold=args.feature_threshold,
        )
    return HeuristicFeatureModel(threshold=args.feature_threshold)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="StaticIOCExtractor",
                                      description="Static IOC extractor for malware")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_extract = sub.add_parser("extract",
                                help="Run Layer 3 only (structured features)")
    p_extract.add_argument("path")
    p_extract.add_argument("--floss", action="store_true",
                            help="Run FLOSS for deobfuscated strings (slow)")
    p_extract.add_argument("--out", help="Write features JSON to this path")
    p_extract.add_argument("--iocs", help="Write IOC list JSON to this path")
    p_extract.add_argument("--assessment-out", help="Write feature malware assessment JSON")
    p_extract.add_argument("--feature-threshold", type=float, default=0.45,
                           help="Feature-model malware threshold")
    p_extract.add_argument("--feature-model", help="Load trained static feature model")
    p_extract.set_defaults(func=_cmd_extract)

    p_analyze = sub.add_parser("analyze",
                                help="Run the full three-layer pipeline")
    p_analyze.add_argument("path")
    p_analyze.add_argument("--ember", help="Path to EMBER LightGBM model")
    p_analyze.add_argument("--ember2024", help="Path to EMBER2024/thrember LightGBM .model")
    p_analyze.add_argument("--nfs", help="Path to needforspeed model")
    p_analyze.add_argument("--threshold", type=float, default=0.5)
    p_analyze.add_argument("--feature-threshold", type=float, default=0.45,
                           help="Feature-model malware threshold")
    p_analyze.add_argument("--feature-model", help="Load trained static feature model")
    p_analyze.add_argument("--force", action="store_true",
                            help="Skip Layer 1 gate; run Layers 2+3 unconditionally")
    p_analyze.add_argument("--floss", action="store_true")
    p_analyze.add_argument("--rule-name", help="YARA rule name")
    p_analyze.add_argument("--out", help="Write JSON report")
    p_analyze.add_argument("--rule-out", help="Write composed YARA rule")
    p_analyze.set_defaults(func=_cmd_analyze)

    p_judge = sub.add_parser("judge",
                             help="Assess an existing StaticFeatures JSON dump")
    p_judge.add_argument("features_json")
    p_judge.add_argument("--feature-threshold", type=float, default=0.45,
                         help="Feature-model malware threshold")
    p_judge.add_argument("--feature-model", help="Load trained static feature model")
    p_judge.add_argument("--out", help="Write assessment JSON")
    p_judge.set_defaults(func=_cmd_judge)

    p_train = sub.add_parser("train-feature-model",
                             help="Train a one-class model from malware StaticFeatures JSONL")
    p_train.add_argument("jsonl", help="JSONL with raw StaticFeatures or envelopes containing `features`")
    p_train.add_argument("--model-out", required=True, help="Write trained feature model")
    p_train.add_argument("--nu", type=float, default=0.05,
                         help="Expected outlier fraction inside malware training data")
    p_train.add_argument("--max-features", type=int, default=50000,
                         help="Maximum TF-IDF token vocabulary size")
    p_train.add_argument("--min-df", type=int, default=1,
                         help="Minimum document frequency for a token")
    p_train.add_argument("--max-iter", type=int, default=2000,
                         help="Maximum SGD optimization iterations")
    p_train.set_defaults(func=_cmd_train_feature_model)

    p_e24_data = sub.add_parser("ember2024-download-dataset",
                                help="Download EMBER2024 features/labels via thrember")
    p_e24_data.add_argument("download_dir")
    p_e24_data.add_argument("--split", default="challenge", choices=VALID_EMBER2024_SPLITS,
                            help="Dataset split to download; default is the smaller challenge set")
    p_e24_data.add_argument("--file-type", default="PE", choices=VALID_EMBER2024_FILE_TYPES,
                            help="File type to download; ignored by the challenge split")
    p_e24_data.add_argument("--dry-run", action="store_true",
                            help="Print the download plan without downloading")
    p_e24_data.set_defaults(func=_cmd_ember2024_download_dataset)

    p_e24_models = sub.add_parser("ember2024-download-models",
                                  help="Download EMBER2024 benchmark models via thrember")
    p_e24_models.add_argument("download_dir")
    p_e24_models.add_argument("--dry-run", action="store_true",
                              help="Print the action without downloading")
    p_e24_models.set_defaults(func=_cmd_ember2024_download_models)

    p_e24_vectorize = sub.add_parser("ember2024-vectorize",
                                     help="Create thrember vectorized .dat files")
    p_e24_vectorize.add_argument("data_dir")
    p_e24_vectorize.add_argument("--label-type", default="label",
                                 choices=("label", "family", "behavior", "file_property", "packer", "exploit", "group"))
    p_e24_vectorize.add_argument("--class-min", type=int, default=10)
    p_e24_vectorize.set_defaults(func=_cmd_ember2024_vectorize)

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
