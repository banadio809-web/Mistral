"""The versioned bug-finder API: scans of wordpress.org plugins and their findings."""

from fastapi import params

# Anonymous for now: the gateway fronts the private app. An authenticated group would declare
# the credential dependency that cascades to every module beneath it.
dependencies: tuple[params.Depends, ...] = ()

# Serves /api/v1/...
segment = "v1"
