"""PMC planner (W6): packages.microsoft.com apt repos -> .NET and PowerShell .debs.

Microsoft's Linux repos are ordinary signed apt repositories, so this module reuses
``apt``'s chain (InRelease -> Packages SHA256/SHA512 -> .deb, signature recorded as
``unverified`` per DECISIONS C19) with its own defaults and source label. One PMC
Packages file keeps every historical build of each package, so
``versions_per_package`` (default 1) keeps only the newest by dpkg order; C13 gives
this source 5 GiB.
"""

from __future__ import annotations

from dataclasses import dataclass

from sherlock.collect.catalog.apt import AptConfig, RepoSpec, plan_repos
from sherlock.collect.items import CatalogResult, Getter

__all__ = ["DEFAULT_CONFIG", "SOURCE", "PmcConfig", "plan"]

SOURCE = "pmc"

_SELECT = (
    r"dotnet-.*",
    r"aspnetcore-.*",
    r"netstandard-targeting-pack-.*",
    r"powershell.*",
)
_PMC = "https://packages.microsoft.com"


@dataclass(frozen=True)
class PmcConfig(AptConfig):
    """Same knobs as ``AptConfig``; only the defaults differ (see DEFAULT_CONFIG)."""


#: Repo paths and suites are unverified offline; the smoke run confirms them.
DEFAULT_CONFIG = PmcConfig(
    repos=(
        RepoSpec(
            "pmc-ubuntu-24.04",
            f"{_PMC}/ubuntu/24.04/prod",
            "noble",
            ("main",),
            select=_SELECT,
        ),
        RepoSpec(
            "pmc-debian-12",
            f"{_PMC}/debian/12/prod",
            "bookworm",
            ("main",),
            select=_SELECT,
        ),
    )
)


def plan(get: Getter, config: AptConfig = DEFAULT_CONFIG) -> CatalogResult:
    """Plan the PMC pull: one ``PlanItem`` per newest selected ``.deb``."""
    return plan_repos(get, config, SOURCE)
