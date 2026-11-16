"""python -m threatmonitor [--demo]"""
import argparse
import logging

from aiohttp import web

from . import config
from .server import make_app


def main():
    ap = argparse.ArgumentParser(prog="threatmonitor", description="Live OPNsense threat globe")
    ap.add_argument("--demo", action="store_true", help="generate synthetic OPNsense traffic")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    app = make_app(args.demo or config.DEMO)
    # a History page query still running gets 5 s at a stop (the dashboards' connections are closed first: server.py)
    web.run_app(app, host=config.BIND, port=config.HTTP_PORT, print=None, shutdown_timeout=5)


if __name__ == "__main__":
    main()
