"""Command-line entry point for the CyberTrace endpoint agent."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from pathlib import Path

from cybertrace_agent import AGENT_VERSION
from cybertrace_agent.config import AgentConfigError, load_config
from cybertrace_agent.runner import AgentRunner, AgentRuntimeError

logger = logging.getLogger("cybertrace_agent")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybertrace-agent",
        description="CyberTrace Linux endpoint collection agent.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("run", "check"),
        default="run",
        help="run the agent (default) or validate its configuration",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/cybertrace-agent/config.json"),
        help="path to the JSON configuration file",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {AGENT_VERSION}",
    )
    return parser


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _check_summary(config_path: Path) -> str:
    config = load_config(config_path)
    summary = {
        "agent_version": AGENT_VERSION,
        "config": str(config_path),
        "server_url": config.server_url,
        "investigation_id": config.investigation_id,
        "display_name": config.display_name,
        "state_dir": str(config.state_dir),
        "start_position": config.start_position,
        "sources": [
            {
                "key": source.key,
                "source_type": source.source_type,
                "path": str(source.path),
                "enabled": source.enabled,
            }
            for source in config.sources
        ],
    }
    return json.dumps(summary, indent=2)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _configure_logging(args.log_level)

    command = args.command
    config_path: Path = args.config
    if command == "check":
        try:
            print(_check_summary(config_path))
        except AgentConfigError as exc:
            logger.error("Configuration is invalid: %s", exc)
            return 2
        return 0

    try:
        config = load_config(config_path)
    except AgentConfigError as exc:
        logger.error("Configuration is invalid: %s", exc)
        return 2

    stop_event = threading.Event()

    def _stop(signum, _frame) -> None:
        logger.info("Received signal %s; stopping after the current operation.", signum)
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            pass

    try:
        runner = AgentRunner(config, stop_event=stop_event)
        runner.run()
    except AgentRuntimeError as exc:
        logger.error("Agent stopped: %s", exc)
        return 3
    except KeyboardInterrupt:
        logger.info("Interrupted.")
        return 0
    except Exception:
        logger.exception("Unexpected agent failure")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
