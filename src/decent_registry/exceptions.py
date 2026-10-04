class IdentityStatePreconditionFailed(ValueError):
    """A Registry instance's accepted Identity state differed from the expected head."""


class IdentityPublicationExpired(ValueError):
    """An Identity publication deadline elapsed before the local DHT write began."""


class IdentityStateUnavailable(RuntimeError):
    """The Registry could not read a current DHT value for a conditional write."""


class IdentityHistoryUnavailable(RuntimeError):
    """A current Identity envelope was observed but its predecessor chain was unavailable."""


class ProviderAlreadyWithdrawn(ValueError):
    """A withdrawal was requested for a Provider Record already withdrawn."""


class ProviderStateUnavailable(RuntimeError):
    """The Registry could not establish an available active Provider Record."""


class ProviderStateInvalid(ValueError):
    """The selected Provider Record exists but is malformed or invalid."""


class ProviderStateConflict(ValueError):
    """The Registry observed conflicting Provider Record heads."""
