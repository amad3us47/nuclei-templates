#!/usr/bin/env python3
"""
nuclei_migrate.py — Migrate & repair Nuclei YAML templates (v2 → v3).

Reads every .yaml / .yml from INPUT_DIR, applies all fixes, and writes
clean copies to OUTPUT_DIR.  Original files are NEVER touched.

Usage
─────
  python nuclei_migrate.py <input_dir> <output_dir>
  python nuclei_migrate.py <input_dir> <output_dir> --dry-run
  python nuclei_migrate.py <input_dir> <output_dir> --summary
  python nuclei_migrate.py <input_dir> <output_dir> --quarantine ./bad/

Fixes applied
─────────────
  • requests: → http:          network: → tcp:
  • attack: sniper             removed (invalid attack type)
  • severity typos             informative→info  hight→high  cretical→critical
  • unknown info: fields       verified, cvss, advisory, risk, confidence, etc.
  • unknown top-level fields   rules, expression, detail, set, manual, transport,
                               fingerprint, nuclei_tags, priority, logic …
  • unknown http fields        attacks, negative, redirect, url, detections …
  • matcher typo               word: → words:
  • top-level references:      moved inside info:
  • missing id                 derived from filename
  • missing author             inserted as "unknown"
  • missing severity           inserted as "info"
  • template id regex          sanitised to ^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$
  • non-nuclei files           nmap / GitHub Actions → quarantine folder
  • schema comment             yaml-language-server header prepended
  • trailing whitespace        stripped; single EOF newline ensured
"""

import argparse
import re
import shutil
import sys
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SCHEMA_COMMENT = (
    "# yaml-language-server: $schema=https://raw.githubusercontent.com/"
    "projectdiscovery/nuclei/dev/pkg/templates/nuclei-jsonschema.json\n"
)

TEMPLATE_ID_RE = re.compile(r"^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$")

SEVERITY_MAP = {
    "informative": "info", "information": "info",
    "hight": "high", "cretical": "critical", "critcal": "critical",
    "criticial": "critical", "meduim": "medium", "mediem": "medium",
    "low": "low", "medium": "medium", "high": "high",
    "critical": "critical", "info": "info", "unknown": "unknown",
}

INVALID_INFO_FIELDS = {
    "verified", "cvss", "refrense", "issues", "advisory",
    "risk", "confidence", "country",
}

NON_NUCLEI_SIGNATURES = {
    "directive_name", "directive_str", "rarity", "matches",   # nmap/fingerprint
    "on", "jobs",                                              # GitHub Actions
    "changelog",
}

INVALID_TOP_LEVEL_FIELDS = {
    "rules", "expression", "detail", "set",
    "fingerprint", "nuclei_tags", "priority", "manual", "transport",
    "logic", "donce", "replicate", "type", "level",
}

INVALID_HTTP_FIELDS = {
    "attacks", "negative", "redirect", "url", "detections",
    "generators", "script", "htmlhint",
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _leading_spaces(line: str) -> int:
    return len(line) - len(line.lstrip())


def _remove_key_block(lines: list[str], key: str, indent: int) -> tuple[list[str], bool]:
    """Remove a YAML key block at *indent* depth plus all deeper continuation lines."""
    out, i, changed = [], 0, False
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        at_indent = _leading_spaces(line) == indent
        is_key = stripped.startswith(key + ":") or stripped.startswith(key + " :")
        if at_indent and is_key:
            changed = True
            i += 1
            while i < len(lines):
                nxt = lines[i]
                ns = nxt.lstrip()
                if ns == "" or ns.startswith("#"):
                    break
                if _leading_spaces(nxt) > indent:
                    i += 1
                else:
                    break
        else:
            out.append(line)
            i += 1
    return out, changed


# ─────────────────────────────────────────────────────────────────────────────
# Migration rules (each returns (new_content, list_of_change_strings))
# ─────────────────────────────────────────────────────────────────────────────

def _check_non_nuclei(content: str) -> bool:
    for sig in NON_NUCLEI_SIGNATURES:
        if re.search(rf"^{re.escape(sig)}\s*:", content, re.MULTILINE):
            return True
    return False


def _rename_protocol_keys(content: str) -> tuple[str, list[str]]:
    changes = []
    for old, new in [("requests", "http"), ("network", "tcp")]:
        pat = re.compile(rf"^{re.escape(old)}(\s*:)", re.MULTILINE)
        if pat.search(content):
            content = pat.sub(rf"{new}\1", content)
            changes.append(f"Renamed '{old}:' → '{new}:'")
    return content, changes


def _fix_severity(content: str) -> tuple[str, list[str]]:
    changes = []
    pat = re.compile(r"^(\s*severity\s*:\s*)(\S+)", re.MULTILINE)

    def _fix(m):
        raw = m.group(2).strip().lower()
        return m.group(1) + SEVERITY_MAP.get(raw, raw)

    new = pat.sub(_fix, content)
    if new != content:
        for m in pat.finditer(content):
            raw = m.group(2).strip()
            fixed = SEVERITY_MAP.get(raw.lower(), raw.lower())
            if fixed != raw:
                changes.append(f"Fixed severity '{raw}' → '{fixed}'")
        content = new
    return content, changes


def _remove_attack_sniper(content: str) -> tuple[str, list[str]]:
    pat = re.compile(r"^(\s*)attack\s*:\s*sniper\s*$", re.MULTILINE | re.IGNORECASE)
    if pat.search(content):
        return pat.sub("", content), ["Removed invalid 'attack: sniper'"]
    return content, []


def _remove_invalid_info_fields(content: str) -> tuple[str, list[str]]:
    changes = []
    lines = content.splitlines(keepends=True)
    info_start = next((i for i, l in enumerate(lines) if re.match(r"^info\s*:", l)), None)
    if info_start is None:
        return content, changes
    child_indent = None
    for l in lines[info_start + 1:]:
        s = l.lstrip()
        if s and not s.startswith("#"):
            child_indent = _leading_spaces(l)
            break
    if child_indent is None:
        return content, changes
    for field in INVALID_INFO_FIELDS:
        new_lines, changed = _remove_key_block(lines, field, child_indent)
        if changed:
            lines = new_lines
            changes.append(f"Removed invalid info field '{field}:'")
    return "".join(lines), changes


def _remove_invalid_top_level_fields(content: str) -> tuple[str, list[str]]:
    changes = []
    for field in INVALID_TOP_LEVEL_FIELDS:
        lines = content.splitlines(keepends=True)
        new_lines, changed = _remove_key_block(lines, field, 0)
        if changed:
            content = "".join(new_lines)
            changes.append(f"Removed invalid top-level field '{field}:'")
    return content, changes


def _remove_invalid_http_fields(content: str) -> tuple[str, list[str]]:
    changes = []
    for field in INVALID_HTTP_FIELDS:
        pat = re.compile(
            rf"^([ \t]{{2,}}){re.escape(field)}\s*:.*$(\n([ \t]+.*$|\s*$))*",
            re.MULTILINE,
        )
        if pat.search(content):
            content = pat.sub("", content)
            changes.append(f"Removed invalid http field '{field}:'")
    return content, changes


def _fix_matcher_word_field(content: str) -> tuple[str, list[str]]:
    pat = re.compile(r"^(\s*)word(\s*:)", re.MULTILINE)
    if pat.search(content):
        return pat.sub(r"\1words\2", content), ["Fixed matcher typo 'word:' → 'words:'"]
    return content, []


def _move_top_level_references(content: str) -> tuple[str, list[str]]:
    lines = content.splitlines()
    top_ref_idx = next(
        (i for i, l in enumerate(lines) if re.match(r"^references\s*:", l)), None
    )
    if top_ref_idx is None:
        return content, []
    ref_block = [lines[top_ref_idx]]
    j = top_ref_idx + 1
    while j < len(lines) and (lines[j] == "" or _leading_spaces(lines[j]) > 0):
        ref_block.append(lines[j])
        j += 1
    in_info = False
    info_end = None
    for i, l in enumerate(lines):
        if re.match(r"^info\s*:", l):
            in_info = True
            continue
        if in_info and l and _leading_spaces(l) == 0 and not l.startswith("#"):
            info_end = i
            break
    if info_end is None:
        return content, []
    indented = [("  " + ln if ln.strip() else ln) for ln in ref_block]
    new_lines = [l for i, l in enumerate(lines)
                 if i < top_ref_idx or i >= top_ref_idx + len(ref_block)]
    real_end = info_end if info_end < top_ref_idx else info_end - len(ref_block)
    new_lines = new_lines[:real_end] + indented + new_lines[real_end:]
    return "\n".join(new_lines), ["Moved top-level 'references:' inside info:"]


def _fix_template_id(content: str, filepath: Path) -> tuple[str, list[str]]:
    pat = re.compile(r"^(id\s*:\s*)(.+)$", re.MULTILINE)
    m = pat.search(content)

    def _safe(raw: str) -> str:
        s = re.sub(r"[^a-zA-Z0-9\-_]", "-", raw).strip("-_")
        s = re.sub(r"-{2,}", "-", s)
        return s if (s and TEMPLATE_ID_RE.match(s)) else "unknown-template"

    if not m:
        safe = _safe(filepath.stem)
        first = content.split("\n")[0]
        if first.startswith("#"):
            content = content.replace(first + "\n", first + "\nid: " + safe + "\n", 1)
        else:
            content = "id: " + safe + "\n" + content
        return content, [f"Added missing id: {safe}"]

    raw_id = m.group(2).strip()
    if not TEMPLATE_ID_RE.match(raw_id):
        safe = _safe(raw_id) if raw_id else _safe(filepath.stem)
        content = pat.sub(m.group(1) + safe, content)
        return content, [f"Sanitised id '{raw_id}' → '{safe}'"]
    return content, []


def _ensure_author(content: str) -> tuple[str, list[str]]:
    if re.search(r"^\s+author\s*:", content, re.MULTILINE):
        return content, []
    content = re.sub(
        r"(^\s+name\s*:.+$)", r"\1\n  author: unknown",
        content, count=1, flags=re.MULTILINE,
    )
    return content, ["Added missing author: unknown"]


def _ensure_severity(content: str) -> tuple[str, list[str]]:
    if re.search(r"^\s+severity\s*:", content, re.MULTILINE):
        return content, []
    content = re.sub(
        r"(^\s+author\s*:.+$)", r"\1\n  severity: info",
        content, count=1, flags=re.MULTILINE,
    )
    return content, ["Added missing severity: info"]


def _ensure_schema_comment(content: str) -> tuple[str, list[str]]:
    if "yaml-language-server" not in content:
        return SCHEMA_COMMENT + content, ["Added schema comment"]
    return content, []


def _strip_trailing_whitespace(content: str) -> tuple[str, list[str]]:
    cleaned = "\n".join(l.rstrip() for l in content.splitlines()).rstrip("\n") + "\n"
    return (cleaned, ["Stripped trailing whitespace"]) if cleaned != content else (content, [])


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

RULES = [
    _rename_protocol_keys,
    _fix_severity,
    _remove_attack_sniper,
    _remove_invalid_info_fields,
    _remove_invalid_top_level_fields,
    _remove_invalid_http_fields,
    _fix_matcher_word_field,
    _move_top_level_references,
    _ensure_author,
    _ensure_severity,
    _ensure_schema_comment,
    _strip_trailing_whitespace,
]


def migrate_content(
    content: str, filepath: Path
) -> tuple[str, list[str], list[str], bool]:
    """Returns (new_content, changes, warnings, is_non_nuclei)."""
    if _check_non_nuclei(content):
        return content, [], [
            f"  ⚠ NON-NUCLEI: '{filepath.name}' (nmap / GH Actions format) — quarantine recommended."
        ], True

    changes: list[str] = []
    for rule in RULES:
        content, ch = rule(content)  # type: ignore[arg-type]
        changes.extend(ch)
    content, ch = _fix_template_id(content, filepath)
    changes.extend(ch)
    return content, changes, [], False


# ─────────────────────────────────────────────────────────────────────────────
# File processing
# ─────────────────────────────────────────────────────────────────────────────

def process_file(
    src: Path,
    out_dir: Path,
    dry_run: bool,
    quarantine_dir: Path | None,
) -> tuple[str, list[str], list[str]]:
    """
    Read *src*, migrate it, write to *out_dir / src.name*.
    Returns (status, changes, warnings).
    status: 'changed' | 'unchanged' | 'quarantined' | 'error'
    """
    try:
        original = src.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return "error", [], [f"  ✗ Cannot read: {exc}"]

    migrated, changes, warnings, is_non_nuclei = migrate_content(original, src)

    if is_non_nuclei:
        if not dry_run and quarantine_dir:
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            dest = quarantine_dir / src.name
            # avoid collisions
            if dest.exists():
                dest = quarantine_dir / (src.stem + "_" + str(src.stat().st_ino) + src.suffix)
            shutil.copy2(src, dest)
            warnings.append(f"  → Copied to quarantine: {dest}")
        return "quarantined", changes, warnings

    changed = migrated != original

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / src.name
        # handle filename collisions
        if dest.exists() and dest.read_text(encoding="utf-8", errors="replace") != migrated:
            dest = out_dir / (src.stem + "_" + str(abs(hash(str(src)))) + src.suffix)
        dest.write_text(migrated, encoding="utf-8")

    return ("changed" if changed else "unchanged"), changes, warnings


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def collect_yaml_files(path: Path) -> list[Path]:
    return sorted(path.rglob("*.yaml")) + sorted(path.rglob("*.yml"))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Migrate Nuclei YAML templates v2 → v3  (input → output folder).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("input_dir",  type=Path, help="Folder containing source .yaml files.")
    parser.add_argument("output_dir", type=Path, help="Folder to write migrated files into.")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Show what would happen; write nothing.")
    parser.add_argument("--summary",   action="store_true",
                        help="Print a grouped change-count table at the end.")
    parser.add_argument("--quarantine", type=Path, default=None, metavar="DIR",
                        help="Copy non-nuclei files here instead of output_dir.")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show unchanged files too.")
    args = parser.parse_args()

    if not args.input_dir.is_dir():
        sys.exit(f"ERROR: '{args.input_dir}' is not a directory.")

    files = collect_yaml_files(args.input_dir)
    if not files:
        print("No YAML files found.")
        sys.exit(0)

    total = len(files)
    counts = {"changed": 0, "unchanged": 0, "quarantined": 0, "error": 0}
    category_counts: dict[str, int] = {}
    dry = args.dry_run

    print(f"{'[DRY RUN] ' if dry else ''}Input  : {args.input_dir}")
    print(f"{'[DRY RUN] ' if dry else ''}Output : {args.output_dir}")
    if args.quarantine:
        print(f"Quarantine: {args.quarantine}")
    print(f"Files   : {total}\n")

    ICONS = {"changed": "✔", "unchanged": "·", "quarantined": "Q", "error": "✗"}

    for fp in files:
        status, changes, warnings = process_file(
            fp,
            out_dir=args.output_dir,
            dry_run=dry,
            quarantine_dir=args.quarantine,
        )
        counts[status] += 1

        show = status != "unchanged" or args.verbose
        if show:
            rel = fp.relative_to(args.input_dir) if fp.is_relative_to(args.input_dir) else fp.name
            print(f"{ICONS[status]}  {rel}")
            for c in changes:
                print(f"     • {c}")
                cat = c.split("'")[0].strip().rstrip(":")
                category_counts[cat] = category_counts.get(cat, 0) + 1
            for w in warnings:
                print(w)

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    print("─" * 52)
    print(f"  Total        : {total}")
    print(f"  ✔ Migrated   : {counts['changed']}")
    print(f"  · Unchanged  : {counts['unchanged']}")
    print(f"  Q Quarantined: {counts['quarantined']}")
    if counts["error"]:
        print(f"  ✗ Errors     : {counts['error']}")

    if dry:
        print("\n  (DRY RUN — no files were written)")
    else:
        print(f"\n  Output written to: {args.output_dir.resolve()}")

    if args.summary and category_counts:
        print("\n── Change breakdown ────────────────────────────")
        for cat, cnt in sorted(category_counts.items(), key=lambda x: -x[1]):
            print(f"  {cnt:4d}×  {cat}")
    print("─" * 52)


if __name__ == "__main__":
    main()
