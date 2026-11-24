# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Shared fixtures for all tests."""

import logging
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def restore_root_logger() -> Iterator[None]:
    """Undo the CLI's logging setup, e.g. the CRITICAL level for JSON output."""
    root = logging.getLogger()
    level, handlers = root.level, root.handlers[:]
    yield
    root.setLevel(level)
    root.handlers[:] = handlers
