"""Parsing of PEP 508 dependency strings and PEP 440 version ranges."""
import re
from functools import lru_cache

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


def parse_requirement(text):
    """'requests>=2; extra == "x"' -> target package, range, and how optional the edge is."""
    empty = {"dst": None, "spec": None, "marker": None, "is_optional": None, "is_conditional": None}
    try:
        req = Requirement(text)
    except InvalidRequirement:
        return empty
    marker = str(req.marker) if req.marker else ""
    is_optional = "extra" in marker
    return {
        "dst": re.sub(r"[-_.]+", "-", req.name).lower(),
        "spec": str(req.specifier),
        "marker": marker,
        "is_optional": is_optional,
        "is_conditional": bool(marker) and not is_optional,
    }


@lru_cache(maxsize=200_000)
def _version(text):
    try:
        return Version(text)
    except InvalidVersion:
        return None


def allowed_versions(spec, releases):
    """The releases a PEP 440 range lets pip pick. None when the range cannot be read."""
    try:
        spec_set = SpecifierSet(spec or "")
    except InvalidSpecifier:
        return None
    allowed = []
    for release in releases or []:
        version = _version(release)
        if version is not None and spec_set.contains(version, prereleases=False):
            allowed.append(release)
    return allowed


def locked_to_affected(spec, releases, affected):
    """True when every release the range allows is affected, so the dependent cannot avoid it.

    None when the range cannot be read. False when the range allows a clean release,
    or allows no release at all (the dependent then cannot install it anyway).
    """
    allowed = allowed_versions(spec, releases)
    if allowed is None:
        return None
    return bool(allowed) and all(release in affected for release in allowed)
