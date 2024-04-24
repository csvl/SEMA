

import json
import sys

def create_mapping():
    """
    Transform a tkt file into a json file
    Format of txt: line1: p1 p2
    Json file: {"p1": "p2"}
    rev json file: {"p2": "p1"}
    """
    if len(sys.argv) < 3:
        print("Usage: python dumb_script.py input_file output_file")
        return
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    mapper = {}
    rev_mapper = {}

    with open(input_file, "r") as f:
        lines = f.readlines()
    for line in lines:
        p1, p2 = line.strip().split()
        mapper[p2] = p1
        rev_mapper[p1] = p2
    with open(output_file, "w") as f:
        json.dump(mapper, f)
    with open("rev_" + output_file, "w") as f:
        json.dump(rev_mapper, f)

def sorted_metadata(mapping, sorted_metadata_file):
    """
    Create a filtered sorted metadata file for all files in mapping, keeping the order in sorted_metadata_file
    mapping: json file {"p1": "p2"}
    sorted_metadata_file: csv file sha,category,timestamp,family
    p1 is the sha in sorted_metadata_file.
    """
    with open(mapping, "r") as f:
        mapping = json.load(f)
    with open(sorted_metadata_file, "r") as f:
        lines = f.readlines()
    with open("bodmas2_" + sorted_metadata_file, "w") as f:
        for line in lines:
            sha = line.split(",")[0]
            if sha+".exe" in mapping:
                f.write(line)


if __name__ == "__main__":

    sorted_metadata("rev_bodmas2_mapping.json", "sorted_metadata.csv")