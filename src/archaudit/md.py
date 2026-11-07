"""Small Markdown helpers tuned for Obsidian."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

_UNSAFE_FILENAME = re.compile(r'[\\/:*?"<>|#^\[\]\x00-\x1f]')
_FENCE = "```"


def safe_filename(name: str, limit: int = 90) -> str:
    """Strip characters Obsidian or the filesystem reject in note names."""
    cleaned = _UNSAFE_FILENAME.sub("-", name)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .-")
    return cleaned[:limit].rstrip(" .-") or "untitled"


def cell(value: object) -> str:
    """Escape a value for a Markdown table cell."""
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>").strip() or "—"


def table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    rows = list(rows)
    if not rows:
        return "_None._"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(cell(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def kv_table(pairs: Iterable[tuple[str, object]]) -> str:
    return table(("Item", "Value"), [(k, v) for k, v in pairs if v not in (None, "")])


def code(text: str, lang: str = "text") -> str:
    text = text.rstrip("\n") or "(empty)"
    fence = _FENCE
    while fence in text:  # never let content close our fence
        fence += "`"
    return f"{fence}{lang}\n{text}\n{fence}"


def callout(kind: str, title: str, body: str = "", folded: bool = False) -> str:
    fold = "-" if folded else ""
    lines = [f"> [!{kind}]{fold} {title}"]
    lines += [f"> {line}" if line else ">" for line in body.splitlines()]
    return "\n".join(lines)


def heading(text: str, level: int = 2) -> str:
    return f"{'#' * level} {text}"


def wikilink(path: str, alias: str | None = None) -> str:
    target = path.removesuffix(".md")
    return f"[[{target}|{alias}]]" if alias else f"[[{target}]]"


def bullet(items: Iterable[object]) -> str:
    lines = [f"- {i}" for i in items]
    return "\n".join(lines) if lines else "_None._"


def frontmatter(data: dict[str, object]) -> str:
    """Minimal YAML front matter (scalars and lists of scalars)."""
    lines = ["---"]
    for key, value in data.items():
        if isinstance(value, list | tuple):
            lines.append(f"{key}:")
            lines += [f"  - {_yaml_scalar(v)}" for v in value]
        else:
            lines.append(f"{key}: {_yaml_scalar(value)}")
    lines.append("---")
    return "\n".join(lines)


def _yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def tag(text: str) -> str:
    """Normalize free text into an Obsidian tag fragment."""
    return re.sub(r"[^a-z0-9/_-]+", "-", text.lower()).strip("-")
