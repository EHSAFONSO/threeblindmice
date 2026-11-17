"""Dashboard web (opcional): pip install -e ".[web]" e depois `tbm dashboard`."""

from tbm.dashboard.app import create_app

__all__ = ["create_app"]
