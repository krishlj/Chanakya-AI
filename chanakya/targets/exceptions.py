class UnregisteredTargetError(ValueError):
    """Raised by ``TargetManager.resolve`` when a target id does not
    resolve against the composed ``TargetRegistry`` (docs/TARGET-MANAGER.md
    §1, "investigation-scoped target management"). Distinct from
    ``chanakya.runtime.exceptions.UnknownTargetError`` — that one is raised
    by ``InvestigationManager`` and lives in the Runtime layer, which
    depends on ``chanakya.targets``, not the other way around; this
    package must not import from ``chanakya.runtime``."""


class InvalidTargetStatusTransitionError(ValueError):
    """Raised by ``TargetManager.transition_status``/``register`` for any
    transition not present in ``ALLOWED_TARGET_STATUS_TRANSITIONS``
    (docs/TARGET-MANAGER.md §6), including an unrecognized initial status
    at registration. Fails closed: no lifecycle transition is ever
    silently coerced to the nearest valid state."""


class DuplicateAdapterRegistrationError(ValueError):
    """Raised by ``TargetManager.register_adapter`` when a
    ``target_type`` already has an adapter registered
    (docs/TARGET-MANAGER.md §8/§19 Phase 4.6: "reject duplicate/conflicting
    registrations"). Registration is atomic across an adapter's declared
    ``supported_target_types`` — a conflict on any one of them rejects the
    whole registration, never a partial one."""


class NoAdapterRegisteredError(ValueError):
    """Raised by ``TargetManager.select_adapter`` for a ``target_type``
    with no registered adapter. Fails closed: there is no default/
    fallback adapter and no adapter is ever chosen based on untrusted
    metadata — selection is only ever by this explicit, trusted
    ``target_type`` key."""


class UnsupportedTargetTypeError(ValueError):
    """Raised by a concrete ``TargetAdapter`` (e.g. ``LocalHostAdapter``)
    when handed a ``Target`` whose ``target_type`` it does not support, or
    a non-``Target`` object entirely (docs/TARGET-MANAGER.md §9/§19 Phase
    4.7 target boundary: "Unknown or unsupported target types must fail
    closed... do not allow a LocalHostAdapter to reinterpret another
    target type as localhost"). Never silently coerced to the adapter's
    own supported type."""
