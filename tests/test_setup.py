"""Smoke tests for the initial project setup."""

from importlib.metadata import version

import security_analyzer


def test_package_imports():
    """The application package should import successfully."""
    assert security_analyzer.__version__ == "0.1.0"


def test_required_dependencies_are_installed():
    """Core libraries and the test runner should be available."""
    required_packages = [
        "streamlit",
        "pandas",
        "plotly",
        "pytest",
    ]

    for package in required_packages:
        assert version(package)
