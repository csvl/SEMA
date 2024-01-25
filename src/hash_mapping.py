import hashlib
import os
import json

correct_hashes = {'RemcosRAT': 'sha256', 'delf': 'md5', 'sytro': 'md5', 'lamer': 'md5', 'FeakerStealer': 'sha256', 'gandcrab': ['md5', 'sha256'], 'ircbot': ['md5', 'sha256'], 'Sodinokibi': 'sha256', 'wabot': 'md5', 'sillyp2p': 'md5', 'sfone': 'md5', 'simbot': 'md5', 'RedLineStealer': 'sha256', 'bancteian': 'md5', 'nitol': 'md5'}

families = ['delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','sytro','wabot','RemcosRAT','bancteian', 'Sodinokibi', 'simbot']

def calculate_hashes(file_path):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: file.read(4096), b""):
            md5_hash.update(byte_block)
            sha256_hash.update(byte_block)

    return md5_hash.hexdigest(), sha256_hash.hexdigest()

# root_dir = "/media/sbettaieb/1341-CC90/final/"

# hashes_mapping = {}

# for file in os.listdir(root_dir):
#     file_path = os.path.join(root_dir, file)

#     original_string = file
#     result_string = ''.join(char for char in original_string if not char.isdigit())

#     if result_string in correct_hashes:
#         if result_string != "gandcrab":
#             if correct_hashes[result_string] == 'md5':
#                 print(file, "md5")
#                 hashes_mapping[file] = calculate_hashes(file_path)[0]
#             if correct_hashes[result_string] == 'sha256':
#                 print(file, "256")
#                 hashes_mapping[file] = calculate_hashes(file_path)[1]
#         else:
#             correct_hashes[file] = calculate_hashes(file_path)
#     else:
#         correct_hashes[file] = calculate_hashes(file_path)

#     # print(file, calculate_hashes(file_path))

# with open("hashes_mapping.json", "w") as fp:
#     json.dump(hashes_mapping , fp)

ret = {}
with open('./hashes_mapping.json') as json_file:
    data = json.load(json_file)
    # import pdb; pdb.set_trace()
    for k, v in data.items():
        if type(v) == str:
            ret[v] = k

with open("final_hashes_mapping.json", "w") as fp:
    json.dump(ret , fp)
