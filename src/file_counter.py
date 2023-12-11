# Count folders for each family in output/runs/100/<family>

import os
import sys
import json
import shutil


# path = "output/runs/100"
path = "output/runs/101_wselect3"
# path = "output/runs/102_clean_cdfs"

families = os.listdir(path)

families = ["berbew","sillyp2p","benjamin","small","mira","upatre","wabot"]
# families = ["cleanware"]

# print(families)

stats = {}

for family in families:
    # print(os.path.join(path, family))
    count = 0
    for root, dirs, files in os.walk(os.path.join(path, family)):
        count += len(dirs)
    stats[family] = [count]
    # print(f"{family}: {count}")

# For each family, count the number of valid graphs, a graph is output/runs/100/<family>/<sample>/<sample>.json

for family in families:
    # print(os.path.join(path, family))
    count = 0
    for root, dirs, files in os.walk(os.path.join(path, family)):
        # print(root)
        # read json (root+.json)
        # if valid, count += 1
        sample = os.path.basename(root)
        scdg = os.path.join(root, f"{sample}.json")
        # print(scdg)
        if os.path.isfile(scdg):
            with open(scdg) as f:
                print(f"Reading {scdg}")
                try:
                    data = json.load(f)
                    # import pdb; pdb.set_trace()
                    if len(data['nodes']) > 1 and len(data['links']) > 0:
                        count += 1
                        print(f"Valid graph: {scdg}")
                        
                        # # Copy file in ./database/examples_samy/BODMAS/01/<family>
                        # dest = os.path.join("./databases/examples_samy/BODMAS/clean_cdfs_01", family)
                        # os.makedirs(dest, exist_ok=True)
                        # shutil.copy(scdg, dest)
                except:
                    print(f"Invalid graph: {scdg}")
    stats[family].append(count)
    # print(f"{family}: {count}")

print(stats)

print()

# sort stats according to number of valid graphs
sorted_stats = sorted(stats.items(), key=lambda x: x[1][1], reverse=True)

print(sorted_stats)
print()

sorted_stats2 = sorted(stats.items(), key=lambda x: x[1][0], reverse=True)

print(sorted_stats2)

# print sum of files and valid files
total_files = 0
total_valid_files = 0
for family in sorted_stats:
    total_files += family[1][0]
    total_valid_files += family[1][1]

print(f"Total files: {total_files}")
print(f"Total valid files: {total_valid_files}")