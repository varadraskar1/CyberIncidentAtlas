from pathlib import Path
import json
import re
import sys
from datetime import date

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent.parent

INCIDENT_SCHEMA_PATH = ROOT / "schemas" / "incident.schema.json"
SOURCE_SCHEMA_PATH = ROOT / "schemas" / "source.schema.json"

INCIDENTS_PATH = ROOT / "data" / "incidents"
SOURCES_PATH = ROOT / "data" / "sources" / "sources.yaml"


INCIDENT_ID_PATTERN = re.compile(r"^INC-\d{4}-\d{4}$")
INCIDENT_SOURCE_ID_PATTERN = re.compile(r"^SRC-\d{3,}$")
GLOBAL_SOURCE_ID_PATTERN = re.compile(r"^SRC-\d{6}$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


# ---------------------------------------------------------------------------
# File loading
# ---------------------------------------------------------------------------

def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


# ---------------------------------------------------------------------------
# JSON Schema validation
# ---------------------------------------------------------------------------

def validate_schema(data: dict, schema: dict) -> list[str]:
    validator = Draft202012Validator(schema)

    errors = sorted(
        validator.iter_errors(data),
        key=lambda error: list(error.absolute_path),
    )

    results = []

    for error in errors:
        location = " → ".join(str(part) for part in error.absolute_path)

        if not location:
            location = "root"

        results.append(
            f"schema: {location}: {error.message}"
        )

    return results


# ---------------------------------------------------------------------------
# Incident validation
# ---------------------------------------------------------------------------

def collect_source_ids(data: dict) -> set[str]:
    return {
        source["source_id"]
        for source in data.get("sources", [])
        if isinstance(source, dict) and "source_id" in source
    }


def collect_source_references(data: dict) -> list[str]:
    references = []

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():

                if key == "source_refs" and isinstance(child, list):
                    references.extend(
                        ref
                        for ref in child
                        if isinstance(ref, str)
                    )
                else:
                    walk(child)

        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(data)

    return references


def validate_source_ids(data: dict) -> list[str]:
    errors = []

    references = collect_source_references(data)

    for reference in references:

        if not GLOBAL_SOURCE_ID_PATTERN.fullmatch(reference):
            errors.append(
                f"semantic: invalid global source reference: {reference}"
            )

    return errors


def validate_incident_id(
    data: dict,
    path: Path,
) -> list[str]:

    errors = []

    incident_id = data.get("incident_id")

    if not incident_id:
        return errors

    if not INCIDENT_ID_PATTERN.fullmatch(incident_id):
        errors.append(
            f"semantic: invalid incident ID: {incident_id}"
        )

    expected_filename = f"{incident_id}.yaml"

    if path.name != expected_filename:
        errors.append(
            f"semantic: filename '{path.name}' does not match "
            f"incident ID '{incident_id}'"
        )

    return errors


def validate_vulnerabilities(data: dict) -> list[str]:
    errors = []

    for vulnerability in data.get("vulnerabilities", []):

        if not isinstance(vulnerability, dict):
            continue

        cve = vulnerability.get("id")

        if cve and not CVE_PATTERN.fullmatch(cve):
            errors.append(
                f"semantic: invalid CVE format: {cve}"
            )

    return errors


def validate_mitre(data: dict) -> list[str]:
    errors = []

    techniques = (
        data.get("attack", {})
        .get("mitre_attack_techniques", [])
    )

    for technique in techniques:

        if not isinstance(technique, dict):
            continue

        technique_id = technique.get("id")

        if technique_id and not MITRE_PATTERN.fullmatch(technique_id):
            errors.append(
                "semantic: invalid MITRE ATT&CK technique: "
                f"{technique_id}"
            )

    return errors


def validate_dates(data: dict) -> list[str]:
    errors = []

    def check_date(value, location):

        if not isinstance(value, str):
            return

        try:
            date.fromisoformat(value)

        except ValueError:
            errors.append(
                f"semantic: invalid date at {location}: {value}"
            )

    dates = data.get("dates", {})

    for key, date_data in dates.items():

        if isinstance(date_data, dict):
            check_date(
                date_data.get("value"),
                f"dates.{key}",
            )

    for index, event in enumerate(data.get("timeline", [])):

        if not isinstance(event, dict):
            continue

        event_date = event.get("date")

        if isinstance(event_date, dict):
            check_date(
                event_date.get("value"),
                f"timeline[{index}].date",
            )

    return errors


def validate_incident(
    path: Path,
    schema: dict,
) -> list[str]:

    errors = []

    try:
        data = load_yaml(path)

    except Exception as exc:
        return [
            f"YAML parsing error: {exc}"
        ]

    if not isinstance(data, dict):
        return [
            "semantic: incident root must be a YAML object"
        ]

    errors.extend(
        validate_schema(data, schema)
    )

    errors.extend(
        validate_incident_id(data, path)
    )

    errors.extend(
        validate_source_ids(data)
    )

    errors.extend(
        validate_vulnerabilities(data)
    )

    errors.extend(
        validate_mitre(data)
    )

    errors.extend(
        validate_dates(data)
    )

    return errors


def find_incidents() -> list[Path]:
    return sorted(
        INCIDENTS_PATH.rglob("*.yaml")
    )


def validate_duplicate_incident_ids(
    incidents: list[Path],
) -> list[str]:

    errors = []
    seen = {}

    for path in incidents:

        try:
            data = load_yaml(path)

        except Exception:
            continue

        if not isinstance(data, dict):
            continue

        incident_id = data.get("incident_id")

        if not incident_id:
            continue

        if incident_id in seen:

            errors.append(
                "semantic: duplicate incident ID "
                f"{incident_id}: "
                f"{seen[incident_id]} and {path}"
            )

        else:
            seen[incident_id] = path

    return errors


# ---------------------------------------------------------------------------
# Central source registry validation
# ---------------------------------------------------------------------------

def validate_source_registry(
    path: Path,
    schema: dict,
) -> tuple[list[str], set[str]]:

    errors = []
    source_ids = set()

    try:
        data = load_yaml(path)

    except Exception as exc:
        return [
            f"YAML parsing error: {exc}"
        ], source_ids

    if not isinstance(data, dict):
        return [
            "semantic: source registry root must be a YAML object"
        ], source_ids

    sources = data.get("sources")

    if not isinstance(sources, list):
        return [
            "semantic: source registry 'sources' must be a YAML list"
        ], source_ids

    for index, source in enumerate(sources):

        location = f"sources[{index}]"

        if not isinstance(source, dict):
            errors.append(
                f"semantic: {location} must be a YAML object"
            )
            continue

        # JSON Schema validation
        source_errors = validate_schema(
            source,
            schema,
        )

        for error in source_errors:
            errors.append(
                f"{location} → {error}"
            )

        source_id = source.get("source_id")

        if not source_id:
            continue

        # Global IDs must use exactly six digits.
        if not GLOBAL_SOURCE_ID_PATTERN.fullmatch(source_id):
            errors.append(
                f"semantic: invalid global source ID: {source_id}"
            )

        # Duplicate detection.
        if source_id in source_ids:
            errors.append(
                f"semantic: duplicate global source ID: {source_id}"
            )

        source_ids.add(source_id)

    return errors, source_ids


# ---------------------------------------------------------------------------
# Cross-reference validation
# ---------------------------------------------------------------------------

def validate_incident_source_references(
    incidents: list[Path],
    registry_source_ids: set[str],
) -> list[str]:

    errors = []

    for path in incidents:

        try:
            data = load_yaml(path)

        except Exception:
            continue

        if not isinstance(data, dict):
            continue

        incident_id = data.get(
            "incident_id",
            path.stem,
        )

        references = collect_source_references(data)

        for reference in references:

            # Ignore the old embedded-source references for now.
            # They will be migrated in the next architecture step.
            if reference.startswith("SRC-") and len(reference) == 10:
                if reference not in registry_source_ids:
                    errors.append(
                        f"semantic: {incident_id}: "
                        f"source reference '{reference}' "
                        f"does not exist in central source registry"
                    )

    return errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:

    print("CyberIncidentAtlas Validator")
    print("=" * 32)

    # -----------------------------------------------------------------------
    # Load incident schema
    # -----------------------------------------------------------------------

    if not INCIDENT_SCHEMA_PATH.exists():

        print(
            f"ERROR: Incident schema not found: "
            f"{INCIDENT_SCHEMA_PATH}"
        )

        return 1

    try:
        incident_schema = load_json(
            INCIDENT_SCHEMA_PATH
        )

    except Exception as exc:

        print(
            f"ERROR: Could not load incident schema: {exc}"
        )

        return 1

    # -----------------------------------------------------------------------
    # Load source schema
    # -----------------------------------------------------------------------

    if not SOURCE_SCHEMA_PATH.exists():

        print(
            f"ERROR: Source schema not found: "
            f"{SOURCE_SCHEMA_PATH}"
        )

        return 1

    try:
        source_schema = load_json(
            SOURCE_SCHEMA_PATH
        )

    except Exception as exc:

        print(
            f"ERROR: Could not load source schema: {exc}"
        )

        return 1

    # -----------------------------------------------------------------------
    # Find incidents
    # -----------------------------------------------------------------------

    if not INCIDENTS_PATH.exists():

        print(
            f"ERROR: Incident directory not found: "
            f"{INCIDENTS_PATH}"
        )

        return 1

    incidents = find_incidents()

    failed_incidents = 0

    if incidents:

        for incident in incidents:

            print(
                f"\nChecking incident: "
                f"{incident.relative_to(ROOT)}"
            )

            errors = validate_incident(
                incident,
                incident_schema,
            )

            if errors:

                failed_incidents += 1

                print("  ❌ FAILED")

                for error in errors:
                    print(
                        f"     - {error}"
                    )

            else:

                print("  ✅ PASSED")

        global_errors = validate_duplicate_incident_ids(
            incidents
        )

        if global_errors:

            failed_incidents += len(
                global_errors
            )

            print(
                "\nGlobal incident validation errors:"
            )

            for error in global_errors:

                print(
                    f"  ❌ {error}"
                )

    else:

        print("\nNo incident files found.")

    # -----------------------------------------------------------------------
    # Source registry
    # -----------------------------------------------------------------------

    failed_sources = 0
    registry_source_ids = set()

    print(
        "\nChecking source registry: "
        f"{SOURCES_PATH.relative_to(ROOT)}"
    )

    if not SOURCES_PATH.exists():

        print("  ❌ FAILED")

        print(
            f"     - source registry not found: "
            f"{SOURCES_PATH}"
        )

        failed_sources = 1

    else:

        source_errors, registry_source_ids = (
            validate_source_registry(
                SOURCES_PATH,
                source_schema,
            )
        )

        if source_errors:

            failed_sources = 1

            print("  ❌ FAILED")

            for error in source_errors:

                print(
                    f"     - {error}"
                )

        else:

            print("  ✅ PASSED")

    # -----------------------------------------------------------------------
    # Cross-reference validation
    # -----------------------------------------------------------------------

    reference_errors = validate_incident_source_references(
        incidents,
        registry_source_ids,
    )

    if reference_errors:

        print(
            "\nSource reference validation:"
        )

        for error in reference_errors:
            print(
                f"  ❌ {error}"
            )

    else:

        print(
            "\nSource reference validation:"
        )

        print(
            "  ✅ PASSED"
        )

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    print("\n" + "=" * 32)

    print(
        f"Incidents checked: {len(incidents)}"
    )

    print(
        f"Incident failures: {failed_incidents}"
    )

    print(
        f"Source registry failures: {failed_sources}"
    )

    print(
        f"Source reference failures: "
        f"{len(reference_errors)}"
    )

    total_failures = (
        failed_incidents
        + failed_sources
        + len(reference_errors)
    )

    if total_failures:

        print(
            "\nValidation failed."
        )

        return 1

    print(
        "\nAll CyberIncidentAtlas data passed validation."
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())