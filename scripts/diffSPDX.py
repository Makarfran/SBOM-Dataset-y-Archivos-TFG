import json
import sys


def normalize(s):
    return (s or "").strip().lower()


def normalize_purl(purl: str) -> str:
    if not purl:
        return ""

    purl = purl.strip().lower()

    if "?" in purl:
        purl = purl.split("?")[0]

    return purl


def extract_component_keys_spdx(spdx_file):
    with open(spdx_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    keys = set()

    for pkg in data.get("packages", []):

        
        name = normalize(pkg.get("name"))
        version = normalize(pkg.get("versionInfo"))

        base_id = f"{name}@{version}" if version else name

        found_purl = False

        
        for ref in pkg.get("externalRefs", []):

            ref_type = normalize(ref.get("referenceType"))

            if ref_type == "purl":

                locator = ref.get("referenceLocator")

                if locator:
                    keys.add(f"purl:{normalize_purl(locator)}")
                    found_purl = True

        
        if not found_purl and name:
            keys.add(f"name:{base_id}")

    return keys


def print_basic(added, removed, common):
    print(len(common))
    print(len(added))
    print(len(removed))


def print_verbose(added, removed, common):
    print("\n=== SPDX DIFF===")

    print(f"Common components: {len(common)}")
    print(f"Added components:  {len(added)}")
    print(f"Removed components:{len(removed)}")

    print("\n--- Added ---")
    for p in sorted(added)[:20]:
        print(p)

    print("\n--- Removed ---")
    for p in sorted(removed)[:20]:
        print(p)

    print("\n--- Common ---")
    for p in sorted(common)[:20]:
        print(p)


def main():

    args = sys.argv[1:]

    if len(args) not in (2, 3):
        print("Usage: python diffSPDX.py [-b] <sbom1.json> <sbom2.json>")
        sys.exit(1)

    basic = False

    if "-b" in args:
        basic = True
        args.remove("-b")

    sbom1, sbom2 = args

    keys1 = extract_component_keys_spdx(sbom1)
    keys2 = extract_component_keys_spdx(sbom2)

    added = keys2 - keys1
    removed = keys1 - keys2
    common = keys1 & keys2

    if basic:
        print_basic(added, removed, common)
    else:
        print_verbose(added, removed, common)


if __name__ == "__main__":
    main()