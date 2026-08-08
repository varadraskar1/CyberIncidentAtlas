from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent

INCIDENT_PATH = (
    ROOT
    / "data"
    / "incidents"
    / "2017"
    / "INC-2017-0002.yaml"
)


# Old incident-local source IDs → global registry IDs.
SOURCE_MAP = {
    "SRC-001": "SRC-000005",  # UK National Audit Office
    "SRC-002": "SRC-000001",  # Microsoft
    "SRC-003": "SRC-000002",  # NIST
    "SRC-004": "SRC-000003",  # Microsoft MS17-010
    "SRC-005": "SRC-000004",  # MITRE ATT&CK
    "SRC-006": "SRC-000005",  # Duplicate of SRC-001
}


def replace_source_ids(text: str) -> str:
    """
    Replace old source IDs everywhere they occur.

    A temporary placeholder prevents one replacement
    from interfering with another.
    """

    placeholders = {}

    for index, (old_id, new_id) in enumerate(SOURCE_MAP.items()):
        placeholder = f"__SOURCE_MIGRATION_{index}__"
        placeholders[placeholder] = new_id

        text = re.sub(
            rf"\b{re.escape(old_id)}\b",
            placeholder,
            text,
        )

    for placeholder, new_id in placeholders.items():
        text = text.replace(
            placeholder,
            new_id,
        )

    return text


def remove_embedded_sources(text: str) -> str:
    """
    Remove the old incident-local sources block.

    The block begins at the root-level 'sources:'
    and ends immediately before the root-level
    'confidence:' section.
    """

    pattern = re.compile(
        r"(?ms)^sources:\s*\n.*?(?=^confidence:\s*$)"
    )

    updated, count = pattern.subn(
        "",
        text,
        count=1,
    )

    if count != 1:
        raise RuntimeError(
            "Could not locate exactly one root-level "
            "'sources:' block."
        )

    return updated


def main():
    if not INCIDENT_PATH.exists():
        raise SystemExit(
            f"Incident not found: {INCIDENT_PATH}"
        )

    original = INCIDENT_PATH.read_text(
        encoding="utf-8"
    )

    updated = replace_source_ids(original)

    updated = remove_embedded_sources(updated)

    INCIDENT_PATH.write_text(
        updated,
        encoding="utf-8",
    )

    print("WannaCry source migration completed.")
    print()
    print("Source mapping:")
    
    for old_id, new_id in SOURCE_MAP.items():
        print(
            f"  {old_id} -> {new_id}"
        )

    print()
    print(
        f"Updated: {INCIDENT_PATH.relative_to(ROOT)}"
    )


if __name__ == "__main__":
    main()