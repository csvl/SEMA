import os
import shutil
import subprocess

# Define the source and destination directories
source_dir = "output/eval_SCDG_n"
dest_dir = "databases/examples_samy/big_dataset"

# Define the possible methods and families
possible_methods = ["WSELECT1", "WSELECT2", "WSELECT3", "CDFS", "CBFS", "CSTOCH1", "CSTOCH2", "CSTOCH3", "STOCH"]
# possible_methods = ["CSTOCH", "CSTOCH2", "CSTOCHSET2", "STOCH"]
possible_families = ["bancteian", "ircbot", "sillyp2p", "sytro", "simbot", "FeakerStealer", "sfone", "lamer", "RedLineStealer", "RemcosRAT", "Sodinokibi", "delf", "nitol", "gandcrab", "wabot"]
# import pdb; pdb.set_trace()

for i in range(0, 1):
    # Loop over each method directory in the source directory
    print("############################################### ", i)
    for method in os.listdir(source_dir):
        if method not in possible_methods:
            continue
        method_dir = os.path.join(source_dir, method, str(i))
        print(f"i:{i} - ", method_dir)
        # if not os.path.isdir(method_dir):
        #     continue

        # Loop over each family directory in the method directory
        for family in os.listdir(method_dir):
            if family not in possible_families:
                continue
            family_dir = os.path.join(method_dir, family)
            print(f"i:{i} - ", family_dir)
            # if not os.path.isdir(family_dir):
                # continue

            # Loop over each file in the family directory
            for file_name in os.listdir(family_dir):
                file_path = os.path.join(family_dir, file_name)

                # Check if the file matches the criteria
                if not file_name.startswith("SCDG_"):
                    continue
                if not (file_name.endswith(".gs") or file_name.endswith(".json")):
                    continue
                print(f"i:{i} - ", file_path)
                # Define the destination directory and copy the file
                dest_family_dir = os.path.join(dest_dir, str(i), method, family)
                os.makedirs(dest_family_dir, exist_ok=True)
                # dest_file_path = os.path.join(dest_family_dir, file_name)
                # shutil.copy(file_path, dest_file_path)
                # Convert the file to .gs
                if (file_name.endswith(".json")):
                    new_gs_file_path = os.path.join(dest_family_dir, file_name.replace(".json", ".gs"))
                    subprocess.run(["python", "json_to_gs.py", "--outfile", new_gs_file_path, file_path])
                else:
                    dest_file_path = os.path.join(dest_family_dir, file_name)
                    shutil.copy(file_path, dest_file_path)

                # Convert the file to .gs
                # if (file_name.endswith(".json")):
                #     gs_file_path = os.path.join(dest_family_dir, file_name.replace(".json", ".gs"))
                #     subprocess.run(["python", "json_to_gs.py", dest_file_path, gs_file_path])
