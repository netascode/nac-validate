# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Daniel Schmidt

"""Shared fixtures for unit tests."""

from pathlib import Path

import pytest


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Empty project directory that is also the working directory.

    Artifact discovery is relative to the working directory, so tests that
    exercise it run inside an isolated project with no inherited TF_DATA_DIR.
    """
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.chdir(project_dir)
    monkeypatch.delenv("TF_DATA_DIR", raising=False)
    return project_dir
