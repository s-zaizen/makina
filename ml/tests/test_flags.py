"""Tests for the OpenFeature-backed runtime flags."""

from __future__ import annotations

import os

import pytest

pytest.importorskip("openfeature")

from makina_ml import flags  # noqa: E402  — after importorskip


@pytest.fixture(autouse=True)
def _restore_provider():
    """Each test re-installs the provider from a known env, so we don't
    leak state between runs."""
    prev = os.environ.get("MAKINA_PUBLIC_MODE")
    yield
    if prev is None:
        os.environ.pop("MAKINA_PUBLIC_MODE", None)
    else:
        os.environ["MAKINA_PUBLIC_MODE"] = prev
    flags.setup_flags()


def test_public_mode_off_by_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MAKINA_PUBLIC_MODE", raising=False)
    flags.setup_flags()
    assert flags.is_public_mode() is False


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_public_mode_truthy(monkeypatch: pytest.MonkeyPatch, value: str):
    monkeypatch.setenv("MAKINA_PUBLIC_MODE", value)
    flags.setup_flags()
    assert flags.is_public_mode() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "garbage"])
def test_public_mode_falsy(monkeypatch: pytest.MonkeyPatch, value: str):
    monkeypatch.setenv("MAKINA_PUBLIC_MODE", value)
    flags.setup_flags()
    assert flags.is_public_mode() is False


def test_setup_flags_is_idempotent(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MAKINA_PUBLIC_MODE", "1")
    flags.setup_flags()
    flags.setup_flags()
    flags.setup_flags()
    assert flags.is_public_mode() is True
