from pathlib import Path
import json
import re
import sys
from datetime import date

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas" / "incident.schema.json"
INCIDENTS_PATH = ROOT / "data" / "incidents"


INCIDENT_ID_PATTERN = re.compile(r"^INC-\d{4}-\d{4}$")
SOURCE_ID_PATTERN = re.compile(r"^SRC-\d{3,}$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


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

        results.append(f"schema: {location}: {error.message}")

    return results


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
                        ref for ref in child if isinstance(ref, str)
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
    seen = set()

    for source in data.get("sources", []):
        source_id = source.get("source_id")

        if source_id in seen:
            errors.append(
                f"semantic: duplicate source ID: {source_id}"
            )

        seen.add(source_id)

        if not SOURCE_ID_PATTERN.fullmatch(source_id):
            errors.append(
                f"semantic: invalid source ID: {source_id}"
            )

    references = collect_source_references(data)
    defined_sources = collect_source_ids(data)

    for reference in references:
        if reference not in defined_sources:
            errors.append(
                f"semantic: source reference does not exist: {reference}"
            )

    return errors


def validate_incident_id(data: dict, path: Path) -> list[str]:
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
        technique_id = technique.get("id")

        if technique_id and not MITRE_PATTERN.fullmatch(technique_id):
            errors.append(
                f"semantic: invalid MITRE ATT&CK technique: "
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
        return [f"YAML parsing error: {exc}"]

    if not isinstance(data, dict):
        return ["semantic: incident root must be a YAML object"]

    errors.extend(validate_schema(data, schema))
    errors.extend(validate_incident_id(data, path))
    errors.extend(validate_source_ids(data))
    errors.extend(validate_vulnerabilities(data))
    errors.extend(validate_mitre(data))
    errors.extend(validate_dates(data))

    return errors


def find_incidents() -> list[Path]:
    return sorted(INCIDENTS_PATH.rglob("*.yaml"))


def validate_duplicate_incident_ids(
    incidents: list[Path],
    schema: dict,
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


def main() -> int:
    print("CyberIncidentAtlas Validator")
    print("=" * 32)

    if not SCHEMA_PATH.exists():
        print(f"ERROR: Schema not found: {SCHEMA_PATH}")
        return 1

    if not INCIDENTS_PATH.exists():
        print(
            f"ERROR: Incident directory not found: "
            f"{INCIDENTS_PATH}"
        )
        return 1

    try:
        schema = load_json(SCHEMA_PATH)
    except Exception as exc:
        print(f"ERROR: Could not load schema: {exc}")
        return 1

    incidents = find_incidents()

    if not incidents:
        print("No incident files found.")
        return 0

    failed = 0

    for incident in incidents:
        print(f"\nChecking: {incident.relative_to(ROOT)}")

        errors = validate_incident(incident, schema)

        if errors:
            failed += 1
            print("  ❌ FAILED")

            for error in errors:
                print(f"     - {error}")
        else:
            print("  ✅ PASSED")

    global_errors = validate_duplicate_incident_ids(
        incidents,
        schema,
    )

    if global_errors:
        failed += len(global_errors)

        print("\nGlobal validation errors:")

        for error in global_errors:
            print(f"  ❌ {error}")

    print("\n" + "=" * 32)
    print(f"Checked: {len(incidents)}")
    print(f"Failed:  {failed}")
    print(f"Passed:  {len(incidents) - min(failed, len(incidents))}")

    if failed:
        print("\nValidation failed.")
        return 1

    print("\nAll incident records passed validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())