import re
import sys
from collections import defaultdict


def main():
    if len(sys.argv) < 2:
        print("Usage: python resultAVG.py <path_to_results.txt>")
        sys.exit(1)

    file_path = sys.argv[1]
    feature_scores = defaultdict(list)

    try:
        with open(file_path, "r", encoding="utf-16") as f:
            for line in f:
                match = re.search(r"\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([0-9.]+)/10.0", line)
                if match:
                    feature = match.group(2).strip()
                    score = float(match.group(3))

                    if feature:
                        feature_scores[feature].append(score)

    except FileNotFoundError:
        print(f"Error: File not found -> {file_path}")
        sys.exit(1)

    if not feature_scores:
        print("No feature scores found.")
        sys.exit(0)

    print("Average score per feature:\n")
    for feature, scores in sorted(feature_scores.items()):
        avg = sum(scores) / len(scores)
        print(f"{feature:30} {avg:.2f}/10.0  (n={len(scores)})")


if __name__ == "__main__":
    main()