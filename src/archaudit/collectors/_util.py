"""Helpers shared by several collectors."""

from __future__ import annotations

from collections.abc import Sequence

from archaudit.core import Context


def unit_states(ctx: Context, units: Sequence[str], verb: str = "is-active") -> dict[str, str]:
    """Return {unit: state} via ``systemctl is-active|is-enabled``.

    Uses the runner directly: a non-zero exit just means "some unit is not
    active", which is an answer, not an error. Returns {} without systemd.
    """
    if not units or not ctx.has("systemctl"):
        return {}
    res = ctx.runner.run(["systemctl", verb, "--", *units], ctx.timeout, ok_codes=range(256))
    lines = res.stdout.splitlines()
    if len(lines) != len(units):
        return {}
    return dict(zip(units, (ln.strip() for ln in lines), strict=True))


def active(ctx: Context, units: Sequence[str]) -> list[str]:
    return [u for u, s in unit_states(ctx, units).items() if s == "active"]
