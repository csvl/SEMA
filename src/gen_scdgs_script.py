import os
import subprocess

# search_dir = "/media/sbettaieb/1341-CC90/final/"
# RandMethodArray = ["CSTOCH", "CSTOCH2", "CSTOCHSET2", "STOCH"]
# MethodArray = ["WSELECT", "WSELECT2", "WSELECTSET2", "CDFS", "CBFS"]
# FamArray = ["bancteian", "ircbot", "sillyp2p", "sytro", "simbot", "FeakerStealer", "sfone", "lamer", "RedLineStealer", "RemcosRAT", "Sodinokibi", "delf", "nitol", "gandcrab", "wabot"]

# j = "0"
# print(j)
# for family in FamArray:
#     print(family)
#     for file in os.listdir(os.path.join(search_dir, family))[:10]:
#         print(file)
#         for method in ["CDFS"]:
#             print(method)
#             cmd = f"python3 SemaSCDG/SemaSCDG.py --method={method} {os.path.join(search_dir, family, file)} --familly={family} --exp_dir=output/eval_SCDG_n/{method}/{j}/ --dir=output/eval_SCDG_n/{method}/{j}/"
#             # subprocess.run(cmd, shell=True)
#             print(cmd)

#             import pandas as pd

# # Read the data
# df = pd.read_csv('./bodmas_metadata.csv')

# # print(df)

# cleaned_df = df.rename(columns={"sha                                                              ": "sha"})

# cleaned_df = cleaned_df.dropna(subset=['family'])
# sorted_df = cleaned_df.sort_values(by=['family'])

# # print(cleaned_df)
# # print(sorted_df)

# # Get the families with most samples
# families = sorted_df['family'].value_counts()
# print(families[:15])

# # New dataframe for malware categories
# df_cate = pd.read_csv('../../BODMAS-open/BODMAS/bodmas_malware_category.csv')

# # get the malware categories
# malware_categories = df_cate['category'].value_counts()
# print(malware_categories)

# our_families = families[:14]
# print(our_families[:14].index)

# For each malware family, copy the samples to a new folder named with the family name, the copy is done batch by batch from each family
# The batch size is 100 samples

# import shutil
# import os

# # Create a new folder for each family
# for family in our_families.index:
#     os.mkdir('./families1/' + family)

# output_dir = './families1/'
# source_dir = '/media/sbettaieb/My Passport/mal_dataset/BODMAS_disarmed_malware_binaries-001/altered/'

# dict_families = {}
# # Copy the samples to the new folders
# for family in our_families.index:
#     # Get the samples of the family
#     dict_families[family] = []
#     samples = sorted_df[sorted_df['family'] == family]['sha']
#     for sample in samples:
#         dict_families[family].append(sample)
#     print(f"{family},{len(dict_families[family])}")


# # Copy the samples to the new folder batch by batch, round robin between the families
# for i in range(500, 1060, 10):
#     for family in our_families.index:
#         batch = dict_families[family][i:i+10]
#         for sample in batch:
#             sample = sample.strip()
#             shutil.copy(source_dir + sample + '.exe', output_dir + family + '/' + sample + '.exe')
#             print(sample + ' copied to ' + family + ' folder')


# loop over the families and create scdg for 10 files at a time from each family
import os
import subprocess

# for j in range(0, 500, 10):
#     for family in our_families.index:
#         batch = dict_families[family][j:j+10]
#         for sample in batch:
#             sample = sample.strip()
#             cmd = f"python3 python SemaSCDG/SemaSCDG.py --CDFS families0/{family}/{sample}.exe --familly={family} --exp_dir=output/runs/100/{} --dir=output/{}"
#             print(sample + ' scdg created')


# our_families = ["sfone","wacatac","upatre","wabot","small","ganelp","dinwod","mira","berbew","sillyp2p","ceeinject","gepys","benjamin","musecador"]

our_families = ["sfone","wacatac","upatre","wabot","berbew","sillyp2p","benjamin","small","mira"]


# list the files inside the families diectories
path = "/media/sbettaieb/My Passport/mal_dataset/BODMAS-20230930T221514Z-002/BODMAS"
fam_files = {}
for family in our_families:
    print(family)
    fam_files[family] = []
    for file in os.listdir(f'{path}/families0/{family}'):
        fam_files[family].append(file)

for j in range(0, 500, 10):
    for family in our_families:
        batch = fam_files[family][j:j+10]
        for sample in batch:
            sample = sample.strip()
            cmd = f"python3 SemaSCDG/SemaSCDG.py --CDFS '{path}/armed_fam0/{family}/{sample}' --familly={family} --exp_dir=output/runs/100/ --dir=output/runs/100/ --json"
            subprocess.run(cmd, shell=True)
            print(sample + ' scdg created')