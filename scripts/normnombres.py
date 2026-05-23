import json
import sys
from collections import defaultdict


def load_sbom(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_sbom(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def extract_packages(data):
    packages = []

    for pkg in data.get("packages", []):
        name = pkg.get("name", "").strip().lower()
        purl = None

        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator").lower()
                break

        if purl:
            packages.append({
                "name": name,
                "purl": purl
            })

    return packages


def build_purl_name_map(pkgs1, pkgs2):
    purl_to_names = defaultdict(list)

    for pkg in pkgs1 + pkgs2:
        purl_to_names[pkg["purl"]].append(pkg["name"])

    purl_to_canonical = {}

    for purl, names in purl_to_names.items():
        # estrategia: nombre más corto (puedes cambiarla)
        canonical = sorted(names, key=lambda x: (len(x), x))[0]
        purl_to_canonical[purl] = canonical

    return purl_to_canonical


def normalize_sbom(data, purl_map):
    for pkg in data.get("packages", []):
        purl = None

        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator").lower()
                break

        if purl and purl in purl_map:
            pkg["name"] = purl_map[purl]

    return data


def main():
    if len(sys.argv) != 3:
        print("Usage: python sbom_normalize.py <sbom1.json> <sbom2.json>")
        sys.exit(1)

    sbom1_path = sys.argv[1]
    sbom2_path = sys.argv[2]

    sbom1 = load_sbom(sbom1_path)
    sbom2 = load_sbom(sbom2_path)

    pkgs1 = extract_packages(sbom1)
    pkgs2 = extract_packages(sbom2)

    purl_map = build_purl_name_map(pkgs1, pkgs2)

    norm_sbom1 = normalize_sbom(sbom1, purl_map)
    norm_sbom2 = normalize_sbom(sbom2, purl_map)

    out1 = sbom1_path.replace(".json", "_normalized.json")
    out2 = sbom2_path.replace(".json", "_normalized.json")

    save_sbom(norm_sbom1, out1)
    save_sbom(norm_sbom2, out2)

    print("SBOMs normalizados generados:")
    print(f"- {out1}")
    print(f"- {out2}")


if __name__ == "__main__":
    main()