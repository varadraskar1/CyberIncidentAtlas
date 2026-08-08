from pathlib import Path
import sys

import yaml
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas" / "incident.schema.json"
INCIDENTS_PATH = ROOT / "data" / "incidents"


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_json(path: Path):
    import json

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def validate_incident(path: Path, schema: dict) -> list[str]:
    try:
        data = load_yaml(path)
    except Exception as exc:
        return [f"YAML parsing error: {exc}"]

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

        results.append(f"{location}: {error.message}")

    return results


def find_incidents() -> list[Path]:
    return sorted(INCIDENTS_PATH.rglob("*.yaml"))


def main() -> int:
    print("CyberIncidentAtlas Validator")
    print("=" * 32)

    if not SCHEMA_PATH.exists():
        print(f"ERROR: Schema not found: {SCHEMA_PATH}")
        return 1

    if not INCIDENTS_PATH.exists():
        print(f"ERROR: Incident directory not found: {INCIDENTS_PATH}")
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

    print("\n" + "=" * 32)
    print(f"Checked: {len(incidents)}")
    print(f"Failed:  {failed}")
    print(f"Passed:  {len(incidents) - failed}")

    if failed:
        return 1

    print("\nAll incident records passed schema validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())