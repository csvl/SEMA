#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

# TODO add logs
# TODO https://www.mongodb.com/docs/manual/core/geospatial-indexes/

import argparse
#from cgitb import html
import json
import os
import socket
import threading
import sys
import time
import requests
# from tkinter import N
from flask import Flask, flash, request, redirect, url_for, send_from_directory, Response, session, render_template, Markup
#from werkzeug.utils import secure_filename
#from base64 import b64encode
from django.core.paginator import (
    Paginator,
    EmptyPage,
    PageNotAnInteger,
)
#import datetime
from flask_cors import CORS
#import pathlib
import pandas as pd

#from src.Sema import *
#import yara

#import dill
#import pyzipper
#import shutil
from npf_web_extension.app import export
import uuid

class SemaServer:
    ROOTPATH = os.getcwd()
    #SemaServer.log.info(ROOTPATH)
    
    app = Flask(__name__, static_folder='static')
    app.secret_key = 'super secret key' # TODO
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['APPLICATION_ROOT'] = 'templates/'
    app.debug = True
    app.jinja_env.filters['json'] = lambda v: Markup(json.dumps(v)) # not safe
    
    # Use to filter valid binaries downloaded from VT
    # rules_pe_x86 = yara.compile(filepaths={
    #     "compilers" : ROOTPATH+'/yara/pe/x86/compilers.yara',
    #     "installers": ROOTPATH+'/yara/pe/x86/installers.yara'
    #     # "packers"  : ROOTPATH+'/yara/pe/x86/packers.yara'
    # })
    # rules_pe_x64 = yara.compile(filepaths={
    #     "compilers" : ROOTPATH+'/yara/pe/x64/compilers.yara',
    #     "installers": ROOTPATH+'/yara/pe/x64/installers.yara'
    #     # "packers"  : ROOTPATH+'/yara/pe/x64/packers.yara' #yara.SyntaxError: /app/yara/pe/x86/packers.yara(151): invalid field name "number_of_user_strings"
    # })
    # rules_serena = yara.compile(filepath=ROOTPATH+'/yara/pe/serena.yara')
    
    
    # enable CORS
    CORS(app, resources={r'/*': {'origins': '*'}})
    
    ##TODO : replace by an API call to get args
    # def init_class_args(self):    
    #     for group in SemaServer.sema.args_parser.args_parser_class.parser._mutually_exclusive_groups:
    #         #SemaServer.log.info(group.title)
    #         if len(SemaServer.actions_classifier[-1]) == 3:
    #             SemaServer.actions_classifier.append({})
                
    #         for action in group._group_actions:
    #             # TODO add group_name in new dictionary
    #             group_name = group.title
    #             #SemaServer.log.info(action)
    #             if group_name not in SemaServer.actions_classifier[-1]:
    #                 SemaServer.actions_classifier[-1][group_name] = []
    #             if isinstance(action, argparse._StoreTrueAction):
    #                 SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": True})
    #             elif isinstance(action, argparse._StoreFalseAction):
    #                 SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True, "is_mutually_exclusive": True})
    #             elif not isinstance(action, argparse._HelpAction):
    #                 SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": True})
        
    #     for group in SemaServer.sema.args_parser.args_parser_class.parser._action_groups:
    #         if group.title == "positional arguments":
    #             continue
    #         if group.title == "optional arguments":
    #             continue
    #         #SemaServer.log.info(group.title)
            
    #         if len(SemaServer.actions_classifier[-1]) == 3:
    #             SemaServer.actions_classifier.append({})
                
    #         for action in group._group_actions:
    #             # TODO add group_name in new dictionary
    #             group_name = group.title
                
    #             #SemaServer.log.info(action)
    #             if group_name not in SemaServer.actions_classifier[-1]:
    #                 SemaServer.actions_classifier[-1][group_name] = []
    #             if isinstance(action, argparse._StoreTrueAction):
    #                 SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": False})
    #             elif isinstance(action, argparse._StoreFalseAction):
    #                 SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True, "is_mutually_exclusive": False})
    #             elif not isinstance(action, argparse._HelpAction):
    #                 SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": False})
        
    #Ask the SCDG microservice for available parameters and returns them
    def init_scdg_args(self):  
        """Do an API call to the sema-scdg container to get the arguments to put on the index page"""
        response = requests.get('http://sema-scdg:5001/scdg_args')
        return response.json()
          
    def __init__(self):
        self.log = SemaServer.app.logger
        
        # List that contains a dictionary containing all the arguments, it is then used
        # to generate dynamically the UI
        # Each element of the list is a HTML row that contains as element the associated dictionary
        
        # Init actions_scdg with current arguments available in ArgParser
        SemaServer.actions_scdg = self.init_scdg_args()
        self.log.info("SCDG arguments retreived")
        
        # Init actions_classifier with current arguments available in ArgParser
        SemaServer.actions_classifier = [{}]
        # #self.init_class_args()
        # self.log.info("Classifier arguments: ")
        # self.log.info(SemaServer.actions_classifier)
        
        SemaServer.exps = []
        SemaServer.download_thread = None
        SemaServer.malware_to_download = 0
        SemaServer.malware_to_downloaded = 0
        SemaServer.sema_res_dir = "database/runs/" # TODO dynamic
        SemaServer.current_exp = 0


    @app.after_request
    def add_header(r):
        """
        It sets the cache control headers to prevent caching
        
        :param r: The response object
        :return: the response object with the headers added.
        """
        r.headers["Cache-Control"] =  "no-cache, no-store, must-revalidate"
        r.headers["Pragma"] = "no-cache"
        r.headers["Expires"] = "0"
        r.headers['Cache-Control'] = 'public, max-age=0'
        r.headers.add("Access-Control-Allow-Headers", "authorization,content-type")
        r.headers.add("Access-Control-Allow-Methods", "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT")
        r.headers.add("Access-Control-Allow-Origin", "*")
        return r

    @app.route('/')
    def redirection():
        """
        It redirects the user to the index.html page
        :return: a redirect to the index.html page.
        """
        return redirect('index.html', code =302)
    
    #TODO
    @app.route('/progress-scdg', methods = ['GET', 'POST'])
    def progress():
        response = requests.get('http://sema-scdg:5001/progress')
        return str(response.content)
        return str(SemaServer.sema.tool_scdg.current_exps)
    
    # @app.route('/iteration-scdg', methods = ['GET', 'POST'])
    # def iteration():
    #     return
    #     return str(SemaServer.sema.tool_scdg.nb_exps)
    
    # @app.route('/progress-dl', methods = ['GET', 'POST'])
    # def progress_dl():
    #     return str(SemaServer.malware_to_downloaded) ## TODO
    
    # @app.route('/iteration-dl', methods = ['GET', 'POST'])
    # def iteration_dl():
    #     return str(SemaServer.malware_to_download) ## TODO
    
    
    #Get the parameters entered on the page to transmit them to the classifier
    # def get_class_args(request):
    #     # The above code is initializing an empty dictionary `class_args` and two empty lists
    #     # `exp_args` and `exp_args_str`. It is not doing anything else with these variables.
    #     class_args = {}
    #     exp_args = []
    #     exp_args_str = ""
    #     for group in SemaServer.sema.args_parser.args_parser_class.parser._mutually_exclusive_groups:
    #         #SemaServer.log.info(group.title)
    #         if group.title in request.form:
    #             exp_args.append("--" + request.form[group.title])
    #             class_args[request.form[group.title]] = True
    #     for group in SemaServer.sema.args_parser.args_parser_class.parser._action_groups:
    #         for action in group._group_actions:
    #             if action.dest == "binaries":
    #                 pass
    #             elif action.dest in request.form:
    #                 # TODO add group_name in new dictionary
    #                 group_name = group.title
    #                 if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction):
    #                     exp_args.append("--" + action.dest)
    #                     class_args[action.dest] = True
    #                 else:
    #                     exp_args.append("--" + action.dest)
    #                     exp_args.append(request.form[action.dest])
    #                     class_args[action.dest] = request.form[action.dest]
                
    #     if len(request.form["binaries"]) > 0:
    #         binaries = request.form["binaries"]
    #         binary_split = binaries.split("/src")
    #         SemaServer.log.info(binary_split)
    #         #exit()
    #         if len(binary_split) > 1:
    #             binaries = "/app/src/" + binary_split[1]
    #         else:
    #             binaries = "/app/src/" + binary_split[0]
    #         exp_args.append(binaries)
    #         class_args["binaries"] = binaries        
    #         #exp_args.append(request.files["binaries"].split("/")[0])
    #     else:
    #         exp_args.append("None")
    #     return class_args, exp_args, exp_args_str

    @app.route('/index.html', methods = ['GET', 'POST'])
    def serve_index():
        """
        It creates a folder for the project, and then calls the upload function
        :return: the upload function.
        """

        if request.method == 'POST':
            scdg_args = {}
            class_args = {}
            fl_args = {}

            #Separate the different arguments of the different part of the toolchain
            exp_number = 1
            arguments = dict(request.form)
            for key,value in arguments.items():
                if (key,value) == ('boundary', 'experiment separation'):
                    exp_number += 1
                if exp_number == 1:
                    scdg_args[key] = value
                elif exp_number == 2:
                    class_args[key] = value
                elif exp_number == 3:
                    fl_args[key] = value

            ##
            # Here we start the experiments
            ##  
            if "scdg_enable" in request.form:
                #Send request to SCDG microservices to start an SCDG with the parameters specified in scdg_args
                response = requests.post('http://sema-scdg:5001/run_scdg', json=scdg_args)
                SemaServer.app.logger.info(response.content)

            #TODO replace by API call
            if "class_enable" in request.form:
                pass
            #     SemaServer.sema.tool_classifier.args = args
            #     SemaServer.sema.args_parser.args_parser_class.update_tool(args)
            #     csv_class_file =  "src/output/runs/"+str(SemaServer.sema.current_exp_dir)+"/" + "classifier.csv"
            #     SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.init, args=([args.exp_dir, [], csv_class_file]))) # TODO family
            #     SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.save_conf,args=([class_args,"src/output/runs/"+str(SemaServer.sema.current_exp_dir)+"/"])))
            #     if SemaServer.sema.tool_classifier.args.train:
            #         SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.train, args=()))
            #     elif SemaServer.sema.tool_classifier.mode == "classification":
            #         SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.classify, args=()))
            #     elif SemaServer.sema.tool_classifier.mode == "detection":
            #         SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.detect, args=()))
            #     SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.save_csv, args=()))
            
        return render_template('index.html', 
                            actions_scdg=SemaServer.actions_scdg, 
                            actions_classifier=SemaServer.actions_classifier,
                            progress=0)
            
    # def manage_exps(args):
    #     while len(SemaServer.exps) > 0:
    #         elem = SemaServer.exps.pop(0)
    #         elem.start()  
    #         elem.join()  
    
    # @app.route('/directory/<int:directory>/file/<path:file>')
    # def send_file(directory,file):
    #     return send_from_directory(SemaServer.sema_res_dir + str(directory), file)
    
    # @app.route('/key/<string:implem>')
    # def send_key(implem):
    #     return send_from_directory(SemaServer.key_path, implem)
    
    # def download_malware(tags, limit, db):
    #     SemaServer.malware_to_download = 0
    #     for tag in tags:
    #         res = requests.post("https://mb-api.abuse.ch/api/v1/", data = {'query': 'get_siginfo', 'signature': tag, 'limit': limit})
    #         #SemaServer.log.info(res.json())
    #         if res and "data" in res.json():
    #             #SemaServer.log.info(res.json()['data'])
    #             for i in res.json()['data']:
    #                 #SemaServer.log.info(i)
    #                 try:
    #                     if "exe" in i["tags"] or "elf" in i["tags"]:
    #                         SemaServer.malware_to_download += 1
    #                 except:
    #                     pass
    #     SemaServer.malware_to_downloaded = 0      
    #     for tag in tags:
    #         db_path = "src/" + db + '/' + tag +  "/"
    #         try:
    #             os.mkdir(db_path)
    #         except:
    #             pass
    #         res = requests.post("https://mb-api.abuse.ch/api/v1/", data = {'query': 'get_siginfo', 'signature': tag, 'limit': limit})
    #         #SemaServer.log.info(res.json())
    #         try:
    #             for i in res.json()['data']: 
    #                 try:
    #                     if "exe" in i["tags"] or "elf" in i["tags"]:
    #                         SemaServer.malware_to_downloaded += 1
    #                         SemaServer.log.info(i)
    #                         SemaServer.log.info(i['sha256_hash'])
    #                         res_file = requests.post("https://mb-api.abuse.ch/api/v1/", data = {'query': 'get_file', 'sha256_hash': i['sha256_hash']})
    #                         #SemaServer.log.info(res_file.json())
    #                         #SemaServer.log.info(res_file.content)
    #                         with open(db_path + i['sha256_hash'], 'wb') as s:
    #                             s.write(res_file.content)
    #                         try:
    #                             with pyzipper.AESZipFile(db_path + i['sha256_hash'],"r", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zip_ref:
    #                                 zip_ref.extractall(db_path + i['sha256_hash'] + "_dir",pwd=bytes("infected", 'utf-8'))
    #                             os.remove(db_path + i['sha256_hash'])
    #                             for file in glob.glob(db_path + i['sha256_hash'] + "_dir/*"):
    #                                 SemaServer.log.info(file)
    #                                 # out = os.popen('file ' + file + " | grep PE32").read()
    #                                 # SemaServer.log.info(out)
    #                                 out = os.popen('file ' + file + " | grep Nullsoft").read()
    #                                 SemaServer.log.info(out)
    #                                 if len(out) > 0:
    #                                     SemaServer.log.info("Removed Nullsoft")
    #                                     os.remove(file)
    #                                     continue
    #                                 out = os.popen('file ' + file + " | grep Mono/.Net").read()
    #                                 if len(out) > 0:
    #                                     SemaServer.log.info("Removed Mono/.Net")
    #                                     os.remove(file)
    #                                     continue                        
    #                                 SemaServer.log.info(out)
    #                                 out = os.popen('file ' + file + " | grep \"RAR self-extracting archive\"").read()
    #                                 if len(out) > 0:
    #                                     SemaServer.log.info("Removed RAR self-extracting archive")
    #                                     os.remove(file)
    #                                     continue                        
    #                                 SemaServer.log.info(out)
    #                                 out = os.popen('file ' + file + " | grep PE32+").read()
    #                                 if len(out) > 0:
    #                                     SemaServer.log.info("Removed PE32+") # TODO parameter
    #                                     os.remove(file)
    #                                     continue                        
    #                                 SemaServer.log.info(out)
    #                                 with open(file, 'rb') as f:
    #                                     # matches = SemaServer.rules_pe_x86.match(data=f.read())
    #                                     # SemaServer.log.info(matches)
    #                                     # # for ii in len(matches):
    #                                     # #     if "msvc" in matches[ii]:
    #                                     # if "msvc" in str(matches) or "mingw" in str(matches):
    #                                     #     os.remove(file)
    #                                     #     SemaServer.log.info("Removed msvc")
    #                                     #     continue
    #                                     # matches = SemaServer.rules_pe_x64.match(data=f.read())
    #                                     # SemaServer.log.info(matches)
    #                                     # #for ii in len(matches):
    #                                     # if "msvc" in str(matches) or "mingw" in str(matches):
    #                                     #     #if "msvc" in matches[ii]:
    #                                     #     os.remove(file)
    #                                     #     SemaServer.log.info("Removed msvc")
    #                                     #     continue
    #                                     matches = SemaServer.rules_serena.match(data=f.read())
    #                                     SemaServer.log.info(matches)
    #                                     #for ii in len(matches):
    #                                     if "FlsAlloc" in str(matches):
    #                                         #if "msvc" in matches[ii]:
    #                                         os.remove(file)
    #                                         SemaServer.log.info("Removed msvc")
    #                                         continue
    #                                 shutil.copyfile(file, db_path + file.split("/")[-1])
    #                             shutil.rmtree(db_path + i['sha256_hash'] + "_dir")
    #                         except Exception as e:
    #                             SemaServer.log.info(e)
    #                         if os.path.exists(db_path + i['sha256_hash']+ "_dir"):
    #                             shutil.rmtree(db_path + i['sha256_hash'] + "_dir")
    #                             pass
    #                 except Exception as e:
    #                     SemaServer.log.info(e)
    #         except Exception as e:
    #             SemaServer.log.info(e) # TODO
    #     SemaServer.malware_to_downloaded = 0 
    #     SemaServer.malware_to_download = 0 
    #     if SemaServer.download_thread:
    #         SemaServer.download_thread.join()
        
    # @app.route('/downloader.html', methods = ['GET', 'POST'])
    # def serve_download():
    #     if request.method == 'POST':
    #         SemaServer.download_thread = threading.Thread(target=SemaServer.download_malware, args=([request.form['TAG'].split(' '), request.form['max_sample'], request.form['db']])).start()
    #     return render_template('downloader.html')
    
    # @app.route('/results.html', methods = ['GET', 'POST'])
    # def serve_results():
    #     """
    #     It creates a folder for the project, and then calls the upload function
    #     :return: the upload function.
    #     """
    #     # TODO
    #     SemaServer.log.info(SemaServer.sema_res_dir)
    #     SemaServer.log.info(os.listdir(SemaServer.sema_res_dir))
    #     nb_exp = len(os.listdir(SemaServer.sema_res_dir))
        
    #     summary = {}
    #     default_page = 0
    #     page = request.args.get('page', default_page)
    #     try:
    #         page = page.number
    #     except:
    #         pass
    #     # Get queryset of items to paginate
    #     rge = range(nb_exp,0,-1)
    #     SemaServer.log.info([i for i in rge])
    #     SemaServer.log.info(page)
    #     items = [i for i in rge]

    #     # Paginate items
    #     items_per_page = 1
    #     paginator = Paginator(items, per_page=items_per_page)

    #     try:
    #         items_page = paginator.page(page)
    #     except PageNotAnInteger:
    #         items_page = paginator.page(default_page)
    #     except EmptyPage:
    #         items_page = paginator.page(paginator.num_pages)
        
    #     scdgs = {}
        
    #     try:
    #         scdg_params = json.loads(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg_conf.json').read())
    #         summary["scdg_used"] = True
    #         summary["date"] = os.path.getctime(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg_conf.json')
    #     except:
    #         scdg_params = {}
    #         summary["scdg_used"] = False
        
    #     try:    
    #         class_params = json.loads(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/class_conf.json').read())
    #         summary["class_used"] = True
    #         summary["date"] = os.path.getctime(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/class_conf.json')
    #     except:
    #         class_params = {}
    #         summary["class_used"] = False
        
    #     summary["family_cnt"] = 0
    #     summary["sample_cnt"] = 0
    #     for subdir in os.listdir(SemaServer.sema_res_dir + str(nb_exp-int(page))):
    #         if os.path.isdir(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir):
    #             summary["family_cnt"] += 1
    #             scdgs[subdir] = {}
    #             for malware in os.listdir(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir):
    #                 summary["sample_cnt"] += 1
    #                 if os.path.isdir(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir + '/' + malware):
    #                     malware_id = malware.split(".")[0]
    #                     scdgs[subdir][malware_id] = {}
    #                     for file in os.listdir(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir + '/' + malware):
    #                         if file.endswith(".json"):
    #                             scdgs[subdir][malware_id]["json"] = json.dumps(json.load(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir  + '/' + malware + '/' + file)), indent=2)
    #                         elif file.endswith("commands.log"):
    #                             scdgs[subdir][malware_id]["command"] = open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir + '/' + malware  + '/' + file,"r").read() #.close()
    #                         elif file.endswith(".log"):
    #                             scdgs[subdir][malware_id]["log"] = open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir + '/' + malware  + '/' + file,"r").read() #.close()
    #     # scdg_logs = json.loads(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg_conf.json').read())
    #     # class_logs = json.loads(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.json').read())
        
    #     if os.path.isfile(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg.csv'):
    #         df_csv_scdg = pd.read_csv(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg.csv',sep=";")
                  
    #         print(list(df_csv_scdg.drop("filename", axis=1).drop("Syscall found", axis=1).drop("Libraries", axis=1).columns))
    #         print(df_csv_scdg.drop("filename", axis=1).drop("Syscall found", axis=1).drop("Libraries", axis=1).to_csv())
    #         print(df_csv_scdg[["filename", "CPU architecture"]].to_csv(index=False))
    #         output = "df_csv.html"
    #         # TODO change the label
    #         configurationData = [
    #             {
    #             "id": str(uuid.uuid4()), # Must be unique TODO df_csv_scdg['filename']
    #             "name": "Experiences coverage view",
    #             "parameters": ["filename", "family"],
    #             "measurements": ["Total number of instr", 'Number of instr visited'], # , "Total number of blocks",'Number Syscall found' , 'Number Address found', 'Number of blocks visited', "Total number of blocks","time"
    #             "data": df_csv_scdg.drop("Syscall found", axis=1).drop("Libraries", axis=1).to_csv(index=False)
    #             },
    #             {
    #             "id": str(uuid.uuid4()), 
    #             "name": "Experiences syscall view",
    #             "parameters": ["filename", "family"], 
    #             "measurements": ["Number Syscall found"], # , "Total number of blocks",'Number Syscall found'
    #             "data": df_csv_scdg.drop("Syscall found", axis=1).drop("Libraries", axis=1).to_csv(index=False)
    #             },
    #             {
    #             "id": str(uuid.uuid4()), 
    #             "name": "Dataset view",
    #             "parameters": ["filename"], 
    #             "measurements": ["OS", "CPU architecture", "family","Binary position-independent"], # , "Total number of blocks",'Number Syscall found'
    #             "data": df_csv_scdg[["filename", "CPU architecture","OS", "family", "Binary position-independent"]].to_csv(index=False)
    #             },
    #         ]
    #         # configurationData = {
    #             # "id": "1234567-1234567894567878241-12456", # Must be unique
    #             # "name": "Quickstart example",
    #             # "parameters": ["N", "algorithm", "num_cpus", "cpu_brand"],
    #             # "measurements": ["efficiency"],
    #             # "data": """algorithm,N,num_cpus,efficiency,cpu_brand
    #             # Algorithm 1,10,1,0.75,Ryzen
    #             # Algorithm 1,10,4,0.85,Ryzen
    #             # Algorithm 1,10,8,0.90,Ryzen
    #             # Algorithm 2,10,1,0.65,Ryzen
    #             # Algorithm 2,10,4,0.80,Ryzen
    #             # Algorithm 2,10,8,0.87,Ryzen
    #             # """, # Raw data in csv format
    #         # }
    #         export(configurationData, output)
        
    #         with open(output, 'r') as f:
    #             df_csv_content = f.read()
                
    #         # configurationData = {
    #         #     "id": df_csv_scdg['Syscall found'], # Must be unique
    #         #     "name": "Experience Syscall found global view",
    #         #     "parameters": ["Count"], #["N", "algorithm", "num_cpus", "cpu_brand"],
    #         #     "measurements": ["efficiency"],
    #         #     "data": ""
    #         # }
    #         # export(configurationData, output)
        
    #         # with open(output, 'r') as f:
    #         #     df_csv_content = f.read()
                
    #     else:
    #         df_csv_scdg = pd.DataFrame()
    #         df_csv_content = ""
            
    #     if os.path.isfile(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.csv'):
    #         df_csv_classifier = pd.read_csv(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.csv',sep=";") 
    #     else:
    #         df_csv_classifier = pd.DataFrame()
            
    #     if os.path.isfile(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.log'):
    #         log_csv_classifier = open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.log').read()
    #     else:
    #         log_csv_classifier = ""
        
    #     SemaServer.current_exp = SemaServer.sema_res_dir + str(nb_exp-int(page))
    #     exp_dir = os.listdir(SemaServer.current_exp)
       
    #     # Get page number from request, 
    #     # default to first page
    #     # try:
    #     #     binary_fc       = open(plantuml_file_png, 'rb').read()  # fc aka file_content
    #     #     base64_utf8_str = b64encode(binary_fc).decode('utf-8')

    #     #     ext     = plantuml_file_png.split('.')[-1]
    #     # except:
    #     #     base64_utf8_str = ''
    #     #     ext = 'png'
    #     # dataurl = f'data:image/{ext};base64,{base64_utf8_str}'
        
    #     SemaServer.log.info(items_page)
    #     SemaServer.log.info(paginator)
    
        
    #     return render_template('results.html', 
    #                        items_page=items_page,
    #                        nb_exp=nb_exp,
    #                        page=int(page),
    #                        current_exp=SemaServer.current_exp,
    #                        scdg_params=scdg_params,
    #                        class_params=class_params,
    #                        scdgs=scdgs,
    #                        summary=summary,
    #                        log_csv_classifier=log_csv_classifier,
    #                        df_csv_scdg=df_csv_scdg.to_csv(),
    #                        df_csv_classifier=df_csv_classifier.to_csv(),
    #                        exp_dir="src/output/runs/", # "http://"+SemaServer.vizualiser_ip+":80/?file=http://"
    #                        df_csv_content=df_csv_content,
                        # )

    # @app.route('/results-global.html', methods = ['GET', 'POST'])
    # def serve_results_global():
    #     """
    #     It creates a folder for the project, and then calls the upload function
    #     :return: the upload function.
    #     """
    #     nb_exp = len(os.listdir(SemaServer.sema_res_dir)) - 2
        
    #     SemaServer.log.info(request.form)
        
    #     summary = {}
    #     df_csv = pd.read_csv(SemaServer.sema_res_dir + 'data.csv',parse_dates=['date'])
        
    #     df_simplify_date = df_csv
    #     df_simplify_date['date'] = df_csv['date'].dt.strftime('%d/%m/%Y')
    #     df_date_min_max = df_simplify_date['date'].agg(['min', 'max'])
    #     df_nb_date = df_simplify_date['date'].nunique()
    #     df_dates = df_simplify_date['date'].unique()
    #     SemaServer.log.info(list(df_dates))
    #     SemaServer.log.info(df_date_min_max)
    #     SemaServer.log.info(df_nb_date)
    #     minimum_date = df_date_min_max["min"]
    #     maximum_date = df_date_min_max["max"]
                
    #     subdf = None
    #     #if len(request.form) >= 0:
    #     for key in request.form:
    #         pass
        
    #     if subdf is not None:
    #         df_csv = subdf
            
    #     # csv_text = df_csv.to_csv()
        
    #     output = "df_csv.html"
    #     export(df_csv, output)
            
    #     return render_template('result-global.html', 
    #                        nb_exp=nb_exp,
    #                        current_exp=SemaServer.current_exp,
    #                        summary=summary,
    #                        csv_text=csv_text,
    #                        server_tests=SemaServer.server_tests, 
    #                        client_tests=SemaServer.client_tests,
    #                        implems=SemaServer.implems,
    #                        min_date=None,
    #                        max_date=None,
    #                        df_nb_date=df_nb_date,
    #                        df_dates=list(df_dates))


 
    def run(self):
        SemaServer.app.run(host='0.0.0.0', port=5000, use_reloader=True, threaded=True)  #, processes=4
        
def main():
    sema = SemaServer()
    sema.run()
    
if __name__ == '__main__':
    main()
