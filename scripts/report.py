from collections import Counter
from pathlib import Path

import yaml


INCIDENTS_DIR = Path("data/incidents")


def load_incidents():
    incidents = []

    for path in sorted(INCIDENTS_DIR.rglob("*.yaml")):
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)

        if isinstance(data, dict):
            incidents.append(data)

    return incidents


def main():
    incidents = load_incidents()

    print("CyberIncidentAtlas Data Report")
    print("=" * 40)

    print(f"Total incidents: {len(incidents)}")

    years = Counter()
    statuses = Counter()
    sectors = Counter()
    incident_types = Counter()
    confidence = Counter()
    sources = Counter()

    for incident in incidents:
        incident_id = incident.get("incident_id", "UNKNOWN")

        dates = incident.get("dates", {})
        disclosed = dates.get("disclosed", {})

        if disclosed and disclosed.get("value"):
            year = disclosed["value"][:4]
            years[year] += 1

        statuses[incident.get("status", "unknown")] += 1

        victim = incident.get("victim", {})
        sectors[victim.get("sector", "unknown")] += 1

        for incident_type in incident.get("incident_type", []):
            incident_types[incident_type] += 1

        confidence_data = incident.get("confidence", {})
        confidence[confidence_data.get("overall", "unknown")] += 1

        for source in incident.get("sources", []):
            source_id = source.get("source_id")
            if source_id:
                sources[source_id] += 1

    print("\nIncidents by year:")
    for year, count in sorted(years.items()):
        print(f"  {year}: {count}")

    print("\nIncident types:")
    for incident_type, count in incident_types.most_common():
        print(f"  {incident_type}: {count}")

    print("\nSectors:")
    for sector, count in sectors.most_common():
        print(f"  {sector}: {count}")

    print("\nStatus:")
    for status, count in statuses.most_common():
        print(f"  {status}: {count}")

    print("\nConfidence:")
    for level, count in confidence.most_common():
        print(f"  {level}: {count}")

    print("\nSource usage:")
    for source_id, count in sources.most_common():
        print(f"  {source_id}: {count}")

    print("\n" + "=" * 40)
    print("Report complete.")


if __name__ == "__main__":
    main()