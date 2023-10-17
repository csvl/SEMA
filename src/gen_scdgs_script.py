import os
import subprocess

search_dir = "/media/sbettaieb/1341-CC90/final/"
RandMethodArray = ["CSTOCH", "CSTOCH2", "CSTOCHSET2", "STOCH"]
MethodArray = ["WSELECT", "WSELECT2", "WSELECTSET2", "CDFS", "CBFS"]
FamArray = ["bancteian", "ircbot", "sillyp2p", "sytro", "simbot", "FeakerStealer", "sfone", "lamer", "RedLineStealer", "RemcosRAT", "Sodinokibi", "delf", "nitol", "gandcrab", "wabot"]

j = "0"
print(j)
for family in FamArray:
    print(family)
    for file in os.listdir(os.path.join(search_dir, family))[:10]:
        print(file)
        for method in ["CDFS"]:
            print(method)
            cmd = f"python3 SemaSCDG/SemaSCDG.py --method={method} {os.path.join(search_dir, family, file)} --familly={family} --exp_dir=output/eval_SCDG_n/{method}/{j}/ --dir=output/eval_SCDG_n/{method}/{j}/"
            # subprocess.run(cmd, shell=True)
            print(cmd)