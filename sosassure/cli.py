from __future__ import annotations

import argparse
import logging
import sys

from .engine import Engine


LOG = logging.getLogger("sosassure")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sosassure", description="Identity-Centric Assurance Engine v0.1")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="Run scan pipeline")
    run.add_argument("domain")
    run.add_argument("--timeout", type=int, default=30)
    run.add_argument("--profile", choices=["lure", "ent1"], default="ent1")
    run.add_argument("--out", default="scans")
    run.add_argument("--subs-file")
    run.add_argument("--max-requests", type=int, default=100)
    run.add_argument("--delay-ms", type=int, default=200)
    run.add_argument("--debug", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "run":
        parser.print_help()
        return 1

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(levelname)s %(message)s")
    LOG.info("Starting SOSAssure run for %s", args.domain)

    try:
        engine = Engine(
            domain=args.domain,
            out_dir=args.out,
            timeout=args.timeout,
            subs_file=args.subs_file,
            max_requests=args.max_requests,
            delay_ms=args.delay_ms,
            debug=args.debug,
        )
        run_dir = engine.run()
        LOG.info("Scan completed. Output: %s", run_dir)
        return 0
    except Exception as exc:
        LOG.error("Fatal error: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
