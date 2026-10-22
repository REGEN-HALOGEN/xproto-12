"""API package for XProto-12."""

from __future__ import annotations

from xproto.api.app import app, create_app
from xproto.api.events import GLOBAL_EVENT_BUS, EventBus
from xproto.api.runs import get_run, list_runs, start_run
from xproto.api.scenarios import (
    delete_custom_scenario,
    get_all_scenario_sets,
    validate_and_create_custom_scenario,
)

__all__ = [
    "EventBus",
    "GLOBAL_EVENT_BUS",
    "app",
    "create_app",
    "delete_custom_scenario",
    "get_all_scenario_sets",
    "get_run",
    "list_runs",
    "start_run",
    "validate_and_create_custom_scenario",
]
