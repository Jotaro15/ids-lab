"""Saving and loading trained models.

Models are stored with joblib, which relies on pickle, and loading a pickle
runs whatever code it contains. Each model file is therefore saved with a
SHA-256 checksum next to it, and the checksum is verified before the file is
opened. That catches corruption and accidental swaps; it does not make a model
from someone else safe to load, so only load models you trained yourself.
"""

import hashlib
from pathlib import Path
from typing import Any

import joblib

from idslab.features.windows import FEATURE_COLUMNS


class ModelIntegrityError(Exception):
    """Raised when a model file cannot be trusted or does not fit the code."""


def checksum_path(path: Path) -> Path:
    """Return the path of the checksum file that goes with a model file."""
    return path.with_name(path.name + ".sha256")


def save_model(model: Any, kind: str, path: Path) -> Path:
    """Save a model and its checksum, and return the model path.

    Args:
        model: The trained scikit-learn model.
        kind: What the model is, e.g. "random_forest". Checked on loading.
        path: Where to write the model file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"kind": kind, "feature_columns": FEATURE_COLUMNS, "model": model}, path)
    checksum_path(path).write_text(f"{_sha256(path)}  {path.name}\n", encoding="utf-8")
    return path


def load_model(path: Path, kind: str) -> Any:
    """Load a model saved by `save_model`, after checking it.

    Raises:
        ModelIntegrityError: If the checksum is missing or does not match the
            file, the model is not of the expected kind, or it was trained on
            different features than the current code produces.
    """
    expected = _read_checksum(path)
    if _sha256(path) != expected:
        raise ModelIntegrityError(f"{path}: checksum mismatch, the file was changed or corrupted")

    # Safe to unpickle only because the checksum was verified just above.
    saved = joblib.load(path)
    if saved["kind"] != kind:
        raise ModelIntegrityError(f"{path}: expected a {kind} model, found {saved['kind']}")
    if saved["feature_columns"] != FEATURE_COLUMNS:
        raise ModelIntegrityError(f"{path}: trained on different features, train it again")
    return saved["model"]


def _read_checksum(path: Path) -> str:
    sidecar = checksum_path(path)
    if not sidecar.is_file():
        raise ModelIntegrityError(f"{path}: no checksum file found at {sidecar}")
    return sidecar.read_text(encoding="utf-8").split()[0]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()
