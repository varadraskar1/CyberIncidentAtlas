from pathlib import Path
from collections import Counter
import yaml

path = Path("data/incidents/2017/INC-2017-0002.yaml")

with path.open("r", encoding="utf-8") as file:
    data = yaml.safe_load(file)

counter = Counter()


def walk(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "source_refs" and isinstance(child, list):
                counter.update(
                    ref for ref in child
                    if isinstance(ref, str)
                )
            else:
                walk(child)

    elif isinstance(value, list):
        for item in value:
            walk(item)


walk(data)

print("WannaCry source reference counts")
print("=" * 35)

for source_id, count in sorted(counter.items()):
    print(f"{source_id}: {count}")

print("=" * 35)
print(f"Total references: {sum(counter.values())}")
print(f"Unique source IDs: {len(counter)}")