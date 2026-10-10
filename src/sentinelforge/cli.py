"""The ``sentinelforge`` command-line interface.

Only commands that work are registered. More are added in later phases.

Exit codes (useful for Bash scripts):
    0  success
    1  the command ran but found a problem (invalid events, unsafe privileges)
    2  usage or configuration error
    3  database unavailable
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from sentinelforge import __version__
from sentinelforge.config import ConfigError, load_settings

EXIT_OK = 0
EXIT_PROBLEM = 1
EXIT_CONFIG = 2
EXIT_DB_UNAVAILABLE = 3


def _err(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


# --- config ------------------------------------------------------------------
def cmd_config_show(_args: argparse.Namespace) -> int:
    settings = load_settings()
    print("SentinelForge configuration (passwords are never displayed)")
    for key, value in settings.safe_summary().items():
        print(f"  {key:<18} {value}")
    return EXIT_OK


# --- events ------------------------------------------------------------------
def cmd_events_validate(args: argparse.Namespace) -> int:
    from sentinelforge.events.validate import validate_jsonl

    path: Path = args.file
    if not path.is_file():
        _err(f"file not found: {path}")
        return EXIT_CONFIG
    try:
        report = validate_jsonl(path)
    except UnicodeDecodeError:
        _err(f"{path} is not UTF-8 text")
        return EXIT_CONFIG

    # Normalised events go to stdout so they can be redirected to a file;
    # the human-readable summary goes to stderr in that mode.
    summary_stream = sys.stdout
    if args.show_normalised:
        summary_stream = sys.stderr
        for event in report.valid_events:
            print(json.dumps(event.model_dump(mode="json"), sort_keys=True))

    def out(text: str = "") -> None:
        print(text, file=summary_stream)

    out(f"Validated {path}")
    out(f"  Records:  {report.total}")
    out(f"  Valid:    {report.valid}")
    out(f"  Invalid:  {report.invalid}")
    if report.errors:
        out("Errors:")
        for error in report.errors[: args.max_errors]:
            out(f"  line {error.line_number:<5} {error.field}: {error.message}")
        hidden = len(report.errors) - args.max_errors
        if hidden > 0:
            out(f"  ... {hidden} more (use --max-errors to show more)")
    out(f"Result: {'OK' if report.ok else 'INVALID RECORDS FOUND'}")
    return EXIT_OK if report.ok else EXIT_PROBLEM


# --- db ----------------------------------------------------------------------
def cmd_db_bootstrap(_args: argparse.Namespace) -> int:
    from sentinelforge.db.bootstrap import bootstrap

    settings = load_settings()
    result = bootstrap(settings)
    action = "created" if result.role_created else "already existed; password and limits refreshed"
    print(f"Application role '{result.app_user}' {action}.")
    print(f"Schema '{result.schema}' is ready in database '{result.database}'.")
    print("The application role can SELECT, INSERT and UPDATE; it cannot CREATE, DROP or DELETE.")
    return EXIT_OK


def cmd_db_status(_args: argparse.Namespace) -> int:
    from sentinelforge.db.status import get_status

    settings = load_settings()
    status = get_status(settings.app_connection(), settings.db_schema)

    def yes_no(value: bool) -> str:
        return "yes" if value else "no"

    print("Database status")
    print(f"  Server:             PostgreSQL {status.server_version}")
    print(f"  Database:           {status.database}")
    print(f"  Connected as:       {status.user}")
    print(f"  Superuser:          {yes_no(status.is_superuser)}")
    print(
        f"  Schema:             {status.schema} "
        f"({'exists' if status.schema_exists else 'MISSING - run sentinelforge db bootstrap'})"
    )
    print(f"  Can use schema:     {yes_no(status.can_use_schema)}")
    print(f"  Can create tables:  {yes_no(status.can_create_in_schema)} (expected: no)")
    if status.least_privilege_ok:
        print("Result: OK (application role is connected with least privilege)")
        return EXIT_OK
    print("Result: PROBLEM (see the lines above)")
    return EXIT_PROBLEM


# --- parser ------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelforge",
        description="SentinelForge: a local SOC lab for security monitoring, "
        "threat detection and incident response.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    groups = parser.add_subparsers(dest="group", metavar="COMMAND", required=True)

    # config
    config = groups.add_parser("config", help="inspect configuration")
    config_cmds = config.add_subparsers(dest="command", metavar="ACTION", required=True)
    show = config_cmds.add_parser("show", help="show settings (passwords hidden)")
    show.set_defaults(func=cmd_config_show)

    # events
    events = groups.add_parser("events", help="work with security event files")
    event_cmds = events.add_subparsers(dest="command", metavar="ACTION", required=True)
    validate = event_cmds.add_parser(
        "validate",
        help="check a JSON Lines event file against the event schema (no database needed)",
    )
    validate.add_argument("file", type=Path, help="path to a .jsonl file")
    validate.add_argument(
        "--max-errors", type=int, default=20, help="maximum errors to print (default: 20)"
    )
    validate.add_argument(
        "--show-normalised",
        action="store_true",
        help="print each valid event in normalised form as JSON Lines on stdout",
    )
    validate.set_defaults(func=cmd_events_validate)

    # db
    db = groups.add_parser("db", help="database setup and health")
    db_cmds = db.add_subparsers(dest="command", metavar="ACTION", required=True)
    boot = db_cmds.add_parser(
        "bootstrap",
        help="create or refresh the least-privilege app role and schema (uses the admin role)",
    )
    boot.set_defaults(func=cmd_db_bootstrap)
    status = db_cmds.add_parser("status", help="check connectivity and privileges as the app role")
    status.set_defaults(func=cmd_db_status)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "max_errors", 1) < 1:
        parser.error("--max-errors must be at least 1")

    import psycopg

    from sentinelforge.db.bootstrap import UnsafeRoleError
    from sentinelforge.db.connect import DatabaseUnavailable

    try:
        return args.func(args)
    except ConfigError as exc:
        _err(str(exc))
        return EXIT_CONFIG
    except DatabaseUnavailable as exc:
        _err(str(exc))
        if exc.hint:
            print(f"hint: {exc.hint}", file=sys.stderr)
        return EXIT_DB_UNAVAILABLE
    except UnsafeRoleError as exc:
        _err(str(exc))
        return EXIT_PROBLEM
    except psycopg.Error as exc:
        # Unexpected database error: show PostgreSQL's message, not a traceback.
        _err(f"database error: {exc.__class__.__name__}: {str(exc).splitlines()[0]}")
        return EXIT_PROBLEM
