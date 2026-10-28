"""Driver registry. Importing this module registers every driver."""
from __future__ import annotations

from .base import (
    Driver,
    DriverPreviewInfo,
    PayloadArtifact,
    SignalSpec,
    TriggerPlan,
    driver_for,
    register,
    registered_categories,
)

# Register drivers by importing them for their side effects.
from . import script_injection  # noqa: F401
from . import checkout_untrusted  # noqa: F401
from . import pr_controlled_dockerfile_build  # noqa: F401
from . import pr_submodules_recursive  # noqa: F401
from . import comment_triggers  # noqa: F401
from . import workflow_run_privileged  # noqa: F401


__all__ = [
    "Driver",
    "DriverPreviewInfo",
    "PayloadArtifact",
    "SignalSpec",
    "TriggerPlan",
    "driver_for",
    "register",
    "registered_categories",
]
