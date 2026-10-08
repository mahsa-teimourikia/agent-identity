"""Collision-safe import facade for this course's reusable ``lab.py``."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_NAME = "_advanced_02_delegation_lab"
_module = sys.modules.get(_NAME)
if _module is None:
    _spec = importlib.util.spec_from_file_location(
        _NAME, Path(__file__).with_name("lab.py")
    )
    if _spec is None or _spec.loader is None:
        raise ImportError("cannot load Advanced 02 lab.py")
    _module = importlib.util.module_from_spec(_spec)
    sys.modules[_NAME] = _module
    _spec.loader.exec_module(_module)

__all__ = [name for name in vars(_module) if not name.startswith("_")]
globals().update({name: getattr(_module, name) for name in __all__})
