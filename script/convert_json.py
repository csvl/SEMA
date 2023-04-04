import sys
import json

# python3 convert_json.py psapi.dll.json

f = open('temp.txt','r')
signature = f.read()
signature = signature.replace("[in]","")
signature = signature.replace("[out]","")
signature = signature.replace("[in, out]","")
signature = signature.replace("[out, optional]","")
signature = signature.replace("[in, optional]","")
signature = signature.replace("IPHLPAPI_DLL_LINKAGE ","") # iphlpapi.dll.json
signature = signature.replace("*","") # iphlpapi.dll.json
print(signature)
jsonfile_new = {}


funs = signature.split(");")

for ff in funs:
    print("#"*50)
    print(ff+");")
    chop_sig = (ff+");").split('\n')
    print(chop_sig)
    chop_sig = [elem for elem in chop_sig if elem != "" and len(elem) > 0]
    print(chop_sig)
    returns = chop_sig[0].split(' ')[0]
    name = chop_sig[0].split(' ')[1][:-1]
    cc = "__stdcall"
    returns_float = False


    Dic = {}
    Dic["cc"] = cc
    Dic["returns"] = returns
    Dic["returns_float"] = returns_float
    Dic["name"] = name
    is_float = False
    arg = []
    no_arg = True
    for l in chop_sig[1:-1]:
        print("*"*50)
        print(l)
        if True:
            no_arg=False
            print(l)
            filtered = list(filter(None,l.split(' ')))
            print(filtered)
            type_arg = filtered[0]
            name_arg = filtered[1].replace(',','')
            
            print(type_arg)
            print(name_arg)
            dic_arg = {}
            dic_arg["type"] = type_arg
            dic_arg["name"] = name_arg
            dic_arg["is_float"] = is_float
            arg.append(dic_arg)

    if no_arg:
        if name[-1] == ')' and name[-2]=='(':
            name = name[:-2]
            Dic["name"] = name
            dic_arg = {}
            dic_arg["type"] = "void"
            dic_arg["name"] = None
            dic_arg["is_float"] = False
            arg.append(dic_arg)
    Dic["arguments"] = arg        

    print(json.dumps(Dic,indent=4))
    f.close()
    
    try:
        with open(sys.argv[1], "r") as fp:
            #return json.load(fp)
            #fp = open(sys.argv[1], "r") 
            jsonfile = json.load(fp)
        with open(sys.argv[1], "r") as fp:
            jsonfile_new = json.load(fp)
    except:
        pass

    with open(sys.argv[1], "w") as fp:
        try:
            jsonfile_new[name] = Dic
            json.dump(jsonfile_new,fp,indent=4)
        except:
            print('error keeping old version')
            json.dump(jsonfile,fp,indent=4)
        #exit(0)
        
