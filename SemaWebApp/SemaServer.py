#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-


# TODO add logs
# TODO https://www.mongodb.com/docs/manual/core/geospatial-indexes/

import argparse
from cgitb import html
import json
import os
import socket
import threading
import sys
import requests
# from tkinter import N
from flask import Flask, flash, request, redirect, url_for, send_from_directory, Response, session, render_template, Markup
from werkzeug.utils import secure_filename
from base64 import b64encode
from django.core.paginator import (
    Paginator,
    EmptyPage,
    PageNotAnInteger,
)
import json
import datetime
from flask_cors import CORS
import pathlib
import pandas as pd

from src.Sema import *
import threading
import yara

import dill
import pyzipper
import shutil

class SemaServer:
    log = logging.getLogger("SemaServer")
    log.setLevel("INFO")
    ROOTPATH = os.getcwd()
    #SemaServer.log.info(ROOTPATH)
    
    app = Flask(__name__, static_folder=ROOTPATH + '/SemaWebApp/static/')
    app.secret_key = 'super secret key' # TODO
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['APPLICATION_ROOT'] = ROOTPATH + '/SemaWebApp/templates/'
    app.debug = True
    app.jinja_env.filters['json'] = lambda v: Markup(json.dumps(v)) # not safe
    
    # Use to filter valid binaries downloaded from VT
    rules_pe_x86 = yara.compile(filepaths={
        "compilers" : ROOTPATH+'/yara/pe/x86/compilers.yara',
        "installers": ROOTPATH+'/yara/pe/x86/installers.yara'
        # "packers"  : ROOTPATH+'/yara/pe/x86/packers.yara'
    })
    rules_pe_x64 = yara.compile(filepaths={
        "compilers" : ROOTPATH+'/yara/pe/x64/compilers.yara',
        "installers": ROOTPATH+'/yara/pe/x64/installers.yara'
        # "packers"  : ROOTPATH+'/yara/pe/x64/packers.yara' #yara.SyntaxError: /app/yara/pe/x86/packers.yara(151): invalid field name "number_of_user_strings"
    })
    rules_serena = yara.compile(filepath=ROOTPATH+'/yara/pe/serena.yara')
    
    
    # enable CORS
    CORS(app, resources={r'/*': {'origins': '*'}})
    
    def init_class_args(self):    
        for group in SemaServer.sema.args_parser.args_parser_class.parser._mutually_exclusive_groups:
            #SemaServer.log.info(group.title)
            if len(SemaServer.actions_classifier[-1]) == 3:
                SemaServer.actions_classifier.append({})
                
            for action in group._group_actions:
                # TODO add group_name in new dictionary
                group_name = group.title
                #SemaServer.log.info(action)
                if group_name not in SemaServer.actions_classifier[-1]:
                    SemaServer.actions_classifier[-1][group_name] = []
                if isinstance(action, argparse._StoreTrueAction):
                    SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": True})
                elif isinstance(action, argparse._StoreFalseAction):
                    SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True, "is_mutually_exclusive": True})
                elif not isinstance(action, argparse._HelpAction):
                    SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": True})
        
        for group in SemaServer.sema.args_parser.args_parser_class.parser._action_groups:
            if group.title == "positional arguments":
                continue
            if group.title == "optional arguments":
                continue
            #SemaServer.log.info(group.title)
            
            if len(SemaServer.actions_classifier[-1]) == 3:
                SemaServer.actions_classifier.append({})
                
            for action in group._group_actions:
                # TODO add group_name in new dictionary
                group_name = group.title
                
                #SemaServer.log.info(action)
                if group_name not in SemaServer.actions_classifier[-1]:
                    SemaServer.actions_classifier[-1][group_name] = []
                if isinstance(action, argparse._StoreTrueAction):
                    SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": False})
                elif isinstance(action, argparse._StoreFalseAction):
                    SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True, "is_mutually_exclusive": False})
                elif not isinstance(action, argparse._HelpAction):
                    SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": False})
        

    def init_scdg_args(self):    
        for group in SemaServer.sema.args_parser.args_parser_scdg.parser._mutually_exclusive_groups:
            if group.title == "positional arguments":
                continue
            if group.title == "optional arguments":
                continue
            
            if len(SemaServer.actions_scdg[-1]) == 3:
                SemaServer.actions_scdg.append({})
                
            for action in group._group_actions:
                # TODO add group_name in new dictionary
                group_name = group.title
                if group_name not in SemaServer.actions_scdg[-1]:
                    SemaServer.actions_scdg[-1][group_name] = []
                if isinstance(action, argparse._StoreTrueAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": True})
                elif isinstance(action, argparse._StoreFalseAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True,  "is_mutually_exclusive": True})
                elif not isinstance(action, argparse._HelpAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": True})
            
        for group in SemaServer.sema.args_parser.args_parser_scdg.parser._action_groups:
            if group.title == "positional arguments":
                continue
            if group.title == "optional arguments":
                continue
            
            if len(SemaServer.actions_scdg[-1]) == 3:
                SemaServer.actions_scdg.append({})
                
            for action in group._group_actions:
                # TODO add group_name in new dictionary
                group_name = group.title
                # SemaServer.log.info(action)
                if group_name not in SemaServer.actions_scdg[-1]:
                    SemaServer.actions_scdg[-1][group_name] = []
                if isinstance(action, argparse._StoreTrueAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": False})
                elif isinstance(action, argparse._StoreFalseAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True, "is_mutually_exclusive": False})
                elif not isinstance(action, argparse._HelpAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": False})
            # SemaServer.log.info(SemaServer.actions_scdg)
            # exit(0)
          
    
    # TODO refactor
    def __init__(self,dir_path=None,experiments=None):
        SemaServer.sema = Sema(is_from_tc=False, is_from_web=True)
        
        self.log = logging.getLogger('SemaServer')
        
        # List that contains a dictionary containing all the arguments, it is then used
        # to generate dynamically the UI
        # Each element of the list is a HTML row that contains as element the associated dictionary
        
        # Init actions_scdg with current arguments available in ArgParser
        SemaServer.actions_scdg = [{}]
        self.init_scdg_args()
        self.log.info("SCDG arguments: ")
        self.log.info(SemaServer.actions_scdg)
        
        # Init actions_classifier with current arguments available in ArgParser
        SemaServer.actions_classifier = [{}]
        self.init_class_args()
        self.log.info("SCDG arguments: ")
        self.log.info(SemaServer.actions_scdg)
        
        # Useless now
        hostname = socket.gethostname() 
        local_ip = socket.gethostbyname(hostname)
        SemaServer.local_ip = local_ip
        self.log.info(local_ip)
        # vizualiser_ip = socket.gethostbyname("ivy-visualizer")
        # SemaServer.vizualiser_ip = vizualiser_ip
        
        SemaServer.exps = []
        SemaServer.download_thread = None
        SemaServer.malware_to_download = 0
        SemaServer.malware_to_downloaded = 0
        SemaServer.sema_res_dir = "src/output/runs/" # TODO dynamic
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
    
    @app.route('/progress-scdg', methods = ['GET', 'POST'])
    def progress():
        return str(SemaServer.sema.tool_scdg.current_exps)
    
    @app.route('/iteration-scdg', methods = ['GET', 'POST'])
    def iteration():
        return str(SemaServer.sema.tool_scdg.nb_exps)
    
    @app.route('/progress-dl', methods = ['GET', 'POST'])
    def progress_dl():
        return str(SemaServer.malware_to_downloaded) ## TODO
    
    @app.route('/iteration-dl', methods = ['GET', 'POST'])
    def iteration_dl():
        return str(SemaServer.malware_to_download) ## TODO
    
    def get_fl_args(self,request):
        fl_args = {}
        exp_args = []
        exp_args_str = ""
        for group in SemaServer.sema.args_parser.args_parser_scdg.parser._mutually_exclusive_groups:
            if group.title in request.form:
                exp_args.append("--" + request.form[group.title])
        for group in SemaServer.sema.args_parser.args_parser_scdg.parser._action_groups:
            for action in group._group_actions:
                if action.dest in request.form:
                    # TODO add group_name in new dictionary
                    group_name = group.title
                    if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction):
                        exp_args.append("--" + action.dest)
                    else:
                        exp_args.append("--" + action.dest)
                        exp_args.append(request.form[action.dest])
        return fl_args, exp_args, exp_args_str
    
    def get_mutator_args(self,request):
        pass # TODO bastien
    
    def get_class_args(self,request):
        # The above code is initializing an empty dictionary `class_args` and two empty lists
        # `exp_args` and `exp_args_str`. It is not doing anything else with these variables.
        class_args = {}
        exp_args = []
        exp_args_str = ""
        for group in SemaServer.sema.args_parser.args_parser_class.parser._mutually_exclusive_groups:
            #SemaServer.log.info(group.title)
            if group.title in request.form:
                exp_args.append("--" + request.form[group.title])
                class_args[request.form[group.title]] = True
        for group in SemaServer.sema.args_parser.args_parser_class.parser._action_groups:
            for action in group._group_actions:
                if action.dest == "binaries":
                    pass
                elif action.dest in request.form:
                    # TODO add group_name in new dictionary
                    group_name = group.title
                    if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction):
                        exp_args.append("--" + action.dest)
                        class_args[action.dest] = True
                    else:
                        exp_args.append("--" + action.dest)
                        exp_args.append(request.form[action.dest])
                        class_args[action.dest] = request.form[action.dest]
                
        if len(request.form["binaries"]) > 0:
            binaries = request.form["binaries"]
            binary_split = binaries.split("/src")
            SemaServer.log.info(binary_split)
            #exit()
            if len(binary_split) > 1:
                binaries = "/app/src/" + binary_split[1]
            else:
                binaries = "/app/src/" + binary_split[0]
            exp_args.append(binaries)
            class_args["binaries"] = binaries        
            #exp_args.append(request.files["binaries"].split("/")[0])
        else:
            exp_args.append("None")
        return class_args, exp_args, exp_args_str

    
    def get_scdg_args(self,request):
        scdg_args = {}
        exp_args = []
        exp_args_str = ""
        # Start with _mutually_exclusive_groups
        for group in SemaServer.sema.args_parser.args_parser_scdg.parser._mutually_exclusive_groups:
            if group.title in request.form:
                exp_args.append("--" + request.form[group.title])
                scdg_args[request.form[group.title]] = True
        
        for group in SemaServer.sema.args_parser.args_parser_scdg.parser._action_groups:
            for action in group._group_actions:
                if action.dest == "binary":
                    pass
                ##
                # About folder & path used
                ##
                elif action.dest == "exp_dir":
                    if len(request.files["exp_dir"].filename) > 0:
                        exp_args.append("--" + action.dest)
                        exp_args.append(request.files["exp_dir"].split("/")[0])
                    else:
                        exp_args.append("--" + action.dest)
                        exp_args.append(request.form[action.dest])
                        scdg_args[action.dest] = request.form[action.dest]
                elif action.dest == "dir":
                    if len(request.files["dir"].filename) > 0:
                        exp_args.append("--" + action.dest)
                        exp_args.append(request.form[action.dest].split("/")[0])
                    else:
                        exp_args.append("--" + action.dest)
                        exp_args.append(request.form[action.dest])
                        scdg_args[action.dest] = request.form[action.dest]
                ##
                # The rest of the arguments
                ##
                elif action.dest in request.form:
                    # TODO add group_name in new dictionary
                    group_name = group.title
                    # For boolean arguments
                    if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction):
                        exp_args.append("--" + action.dest)
                        exp_args_str += "--" + action.dest + " "
                        scdg_args[action.dest] = True
                    else:
                        exp_args.append("--" + action.dest)
                        exp_args.append(request.form[action.dest])
                        exp_args_str += "--" + action.dest + " " + request.form[action.dest] + " "  
                        scdg_args[action.dest] = request.form[action.dest]     
        if len(request.form["binary"]) > 0:
            # If there is a specified path in the binary field, we refacor the input to point toward the right path in the docker
            binary = request.form["binary"]
            binary_split = binary.split("/src")
            SemaServer.log.info(binary_split)
            binary = "/app/src" + binary_split[1]
            exp_args.append(binary)
            scdg_args["binary"] = binary
        else: # TODO
            # To implement: when the binary is uploaded -> Do we want to "upload" since it is only local for now
            exp_args.append(str(request.files["binary"].filename))
            exp_args_str += str(request.files["binary"].filename)  
        return scdg_args, exp_args, exp_args_str

    @app.route('/index.html', methods = ['GET', 'POST'])
    def serve_index():
        """
        It creates a folder for the project, and then calls the upload function
        :return: the upload function.
        """
        if request.method == 'POST':
            SemaServer.log.info(request.form)
            
            scdg_args = {}
            class_args = {}
            fl_args = {}
            exp_args = []
            
            # TODO dir per malware
            scdg_args, exp_args_scdg, exp_args_scdg_str = SemaServer.get_scdg_args(request)   
            exp_args += scdg_args   
            class_args, exp_args_class, exp_args_class_str = SemaServer.get_class_args(request)
            exp_args += class_args  
            if "fl_enable" in request.form: # TODO refactor + implement
                fl_args, exp_args_fl, exp_args_fl_str = SemaServer.get_fl_args(request)
                exp_args += fl_args               
            muta_args, exp_args_muta, exp_args_muta_str = SemaServer.get_mutator_args(request)
            exp_args += muta_args
                
            SemaServer.log.info(exp_args)

            args = SemaServer.sema.args_parser.parse_arguments(args_list=exp_args,allow_unk=False) # TODO
            
            SemaServer.log.info(args)

            ##
            # Here we link the individual argument about input/output folder so they match
            # Typically: [mutator] -> [scdg] -> [class] 
            ##
            if args.exp_dir == "output/runs/" and "scdg_enable" in request.form:
                SemaServer.sema.current_exp_dir = len(glob.glob("src/" + args.exp_dir + "/*")) + 1
                args.exp_dir = "src/" + args.exp_dir + str(SemaServer.sema.current_exp_dir) + "/"
                args.dir = "src/" + args.dir + str(SemaServer.sema.current_exp_dir) + "/"
                args.binaries = args.exp_dir
            elif args.binaries == "output/runs/" and "class_enable" in request.form:
                SemaServer.sema.current_exp_dir = len(glob.glob("src/" + args.exp_dir + "/*")) + 1
                exp_dir = "src/" + args.exp_dir + str(SemaServer.sema.current_exp_dir) + "/"
                args.binaries = exp_dir
            elif args.binaries_mutated == "output/runs/" and "mutator_enable" in request.form:
                pass # TODO bastien
            else:
                SemaServer.sema.current_exp_dir = int(args.binaries.split("/")[-1]) # TODO
                  
            ##
            # Here we start the experiments
            ##  
            if "scdg_enable" in request.form:
                SemaServer.sema.tool_classifier.args = args
                SemaServer.sema.args_parser.args_parser_scdg.update_tool(args)
                csv_scdg_file = "src/output/runs/"+str(SemaServer.sema.current_exp_dir)+"/" + "scdg.csv"
                SemaServer.log.info(csv_scdg_file)
                SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_scdg.save_conf, args=([scdg_args,"src/output/runs/"+str(SemaServer.sema.current_exp_dir)+"/"])))
                SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_scdg.start_scdg, args=([args, False, csv_scdg_file])))
            
            if "class_enable" in request.form:
                SemaServer.sema.tool_classifier.args = args
                SemaServer.sema.args_parser.args_parser_class.update_tool(args)
                csv_class_file =  "src/output/runs/"+str(SemaServer.sema.current_exp_dir)+"/" + "classifier.csv"
                SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.init, args=([args.exp_dir, [], csv_class_file]))) # TODO familly
                SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.save_conf,args=([class_args,"src/output/runs/"+str(SemaServer.sema.current_exp_dir)+"/"])))
                SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.train, args=()))
                if SemaServer.sema.tool_classifier.mode == "classification":
                    SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.classify, args=()))
                else:
                    SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.detect, args=()))
                SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.save_csv, args=()))
            
            if "fl_enable" in request.form:
                pass
            
            if "mutator_enable" in request.form:
                pass # TODO bastien
            
            try:
                os.mkdir("src/output/runs/"+str(SemaServer.sema.current_exp_dir)+"/")
                SemaServer.sema.tool_scdg.current_exp_dir =SemaServer.sema.current_exp_dir
            except:
                pass
            threading.Thread(target=SemaServer.manage_exps, args=([args])).start()
            
            return render_template('index.html', 
                                actions_scdg=SemaServer.actions_scdg, 
                                actions_classifier=SemaServer.actions_classifier,
                                progress=0) # TODO 0rtt
        else:
            return render_template('index.html', 
                                actions_scdg=SemaServer.actions_scdg, 
                                actions_classifier=SemaServer.actions_classifier,
                                progress=0)
            
    def manage_exps(args):
        while len(SemaServer.exps) > 0:
            elem = SemaServer.exps.pop(0)
            elem.start()  
            elem.join()  
    
    @app.route('/start-scdg', methods = ['GET', 'POST'])
    def start_scdg():
        """
        :return: the upload function.
        """
        SemaServer.sema.args_parser.args_parser_scdg = 0 # TODO
        SemaServer.sema.tool_scdg.start_scdg(SemaServer.sema.args_parser.args_parser_scdg)
        
    @app.route('/start-classify', methods = ['GET', 'POST'])
    def start_classifier():
        """
        :return: the upload function.
        """
        SemaServer.sema.args = 0 # TODO
        SemaServer.sema.tool_classifier.init(exp_dir=SemaServer.sema.args.exp_dir)
        SemaServer.sema.tool_classifier.train()

        if SemaServer.sema.tool_classifier.mode == "classification":
            SemaServer.sema.tool_classifier.classify()
        else:
            SemaServer.sema.tool_classifier.detect()

        elapsed_time = time.time() - SemaServer.sema.start_time
        SemaServer.sema.log.info("Total execution time: " + str(elapsed_time))

        if SemaServer.sema.args.train: # TODO
            args_res = {}
            if SemaServer.sema.tool_classifier.classifier_name == "gspan":
                args_res["target"] = SemaServer.sema.mode
            SemaServer.sema.log.info(SemaServer.sema.tool_classifier.classifier.get_stat_classifier(**args_res))
        
    
    @app.route('/directory/<int:directory>/file/<path:file>')
    def send_file(directory,file):
        return send_from_directory(SemaServer.sema_res_dir + str(directory), file)
    
    @app.route('/key/<string:implem>')
    def send_key(implem):
        return send_from_directory(SemaServer.key_path, implem)
    
    def download_malware(tags, limit, db):
        SemaServer.malware_to_download = 0
        for tag in tags:
            res = requests.post("https://mb-api.abuse.ch/api/v1/", data = {'query': 'get_siginfo', 'signature': tag, 'limit': limit})
            #SemaServer.log.info(res.json())
            if res and "data" in res.json():
                #SemaServer.log.info(res.json()['data'])
                for i in res.json()['data']:
                    #SemaServer.log.info(i)
                    try:
                        if "exe" in i["tags"] or "elf" in i["tags"]:
                            SemaServer.malware_to_download += 1
                    except:
                        pass
        SemaServer.malware_to_downloaded = 0      
        for tag in tags:
            db_path = "src/" + db + '/' + tag +  "/"
            try:
                os.mkdir(db_path)
            except:
                pass
            res = requests.post("https://mb-api.abuse.ch/api/v1/", data = {'query': 'get_siginfo', 'signature': tag, 'limit': limit})
            #SemaServer.log.info(res.json())
            try:
                for i in res.json()['data']: 
                    try:
                        if "exe" in i["tags"] or "elf" in i["tags"]:
                            SemaServer.malware_to_downloaded += 1
                            SemaServer.log.info(i)
                            SemaServer.log.info(i['sha256_hash'])
                            res_file = requests.post("https://mb-api.abuse.ch/api/v1/", data = {'query': 'get_file', 'sha256_hash': i['sha256_hash']})
                            #SemaServer.log.info(res_file.json())
                            #SemaServer.log.info(res_file.content)
                            with open(db_path + i['sha256_hash'], 'wb') as s:
                                s.write(res_file.content)
                            try:
                                with pyzipper.AESZipFile(db_path + i['sha256_hash'],"r", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zip_ref:
                                    zip_ref.extractall(db_path + i['sha256_hash'] + "_dir",pwd=bytes("infected", 'utf-8'))
                                os.remove(db_path + i['sha256_hash'])
                                for file in glob.glob(db_path + i['sha256_hash'] + "_dir/*"):
                                    SemaServer.log.info(file)
                                    # out = os.popen('file ' + file + " | grep PE32").read()
                                    # SemaServer.log.info(out)
                                    out = os.popen('file ' + file + " | grep Nullsoft").read()
                                    SemaServer.log.info(out)
                                    if len(out) > 0:
                                        SemaServer.log.info("Removed Nullsoft")
                                        os.remove(file)
                                        continue
                                    out = os.popen('file ' + file + " | grep Mono/.Net").read()
                                    if len(out) > 0:
                                        SemaServer.log.info("Removed Mono/.Net")
                                        os.remove(file)
                                        continue                        
                                    SemaServer.log.info(out)
                                    out = os.popen('file ' + file + " | grep \"RAR self-extracting archive\"").read()
                                    if len(out) > 0:
                                        SemaServer.log.info("Removed RAR self-extracting archive")
                                        os.remove(file)
                                        continue                        
                                    SemaServer.log.info(out)
                                    out = os.popen('file ' + file + " | grep PE32+").read()
                                    if len(out) > 0:
                                        SemaServer.log.info("Removed PE32+") # TODO parameter
                                        os.remove(file)
                                        continue                        
                                    SemaServer.log.info(out)
                                    with open(file, 'rb') as f:
                                        # matches = SemaServer.rules_pe_x86.match(data=f.read())
                                        # SemaServer.log.info(matches)
                                        # # for ii in len(matches):
                                        # #     if "msvc" in matches[ii]:
                                        # if "msvc" in str(matches) or "mingw" in str(matches):
                                        #     os.remove(file)
                                        #     SemaServer.log.info("Removed msvc")
                                        #     continue
                                        # matches = SemaServer.rules_pe_x64.match(data=f.read())
                                        # SemaServer.log.info(matches)
                                        # #for ii in len(matches):
                                        # if "msvc" in str(matches) or "mingw" in str(matches):
                                        #     #if "msvc" in matches[ii]:
                                        #     os.remove(file)
                                        #     SemaServer.log.info("Removed msvc")
                                        #     continue
                                        matches = SemaServer.rules_serena.match(data=f.read())
                                        SemaServer.log.info(matches)
                                        #for ii in len(matches):
                                        if "FlsAlloc" in str(matches):
                                            #if "msvc" in matches[ii]:
                                            os.remove(file)
                                            SemaServer.log.info("Removed msvc")
                                            continue
                                    shutil.copyfile(file, db_path + file.split("/")[-1])
                                shutil.rmtree(db_path + i['sha256_hash'] + "_dir")
                            except Exception as e:
                                SemaServer.log.info(e)
                            if os.path.exists(db_path + i['sha256_hash']+ "_dir"):
                                shutil.rmtree(db_path + i['sha256_hash'] + "_dir")
                                pass
                    except Exception as e:
                        SemaServer.log.info(e)
            except Exception as e:
                SemaServer.log.info(e) # TODO
        SemaServer.malware_to_downloaded = 0 
        SemaServer.malware_to_download = 0 
        if SemaServer.download_thread:
            SemaServer.download_thread.join()
        
    @app.route('/downloader.html', methods = ['GET', 'POST'])
    def serve_download():
        if request.method == 'POST':
            SemaServer.download_thread = threading.Thread(target=SemaServer.download_malware, args=([request.form['TAG'].split(' '), request.form['max_sample'], request.form['db']])).start()
        return render_template('downloader.html')
    
    @app.route('/results.html', methods = ['GET', 'POST'])
    def serve_results():
        """
        It creates a folder for the project, and then calls the upload function
        :return: the upload function.
        """
        # TODO
        SemaServer.log.info(SemaServer.sema_res_dir)
        SemaServer.log.info(os.listdir(SemaServer.sema_res_dir))
        nb_exp = len(os.listdir(SemaServer.sema_res_dir))
        
        summary = {}
        default_page = 0
        page = request.args.get('page', default_page)
        try:
            page = page.number
        except:
            pass
        # Get queryset of items to paginate
        rge = range(nb_exp,0,-1)
        SemaServer.log.info([i for i in rge])
        SemaServer.log.info(page)
        items = [i for i in rge]

        # Paginate items
        items_per_page = 1
        paginator = Paginator(items, per_page=items_per_page)

        try:
            items_page = paginator.page(page)
        except PageNotAnInteger:
            items_page = paginator.page(default_page)
        except EmptyPage:
            items_page = paginator.page(paginator.num_pages)
        
        scdgs = {}
        
        try:
            scdg_params = json.loads(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg_conf.json').read())
            summary["scdg_used"] = True
            summary["date"] = os.path.getctime(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg_conf.json')
        except:
            scdg_params = {}
            summary["scdg_used"] = False
        
        try:    
            class_params = json.loads(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/class_conf.json').read())
            summary["class_used"] = True
            summary["date"] = os.path.getctime(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/class_conf.json')
        except:
            class_params = {}
            summary["class_used"] = False
        
        summary["familly_cnt"] = 0
        summary["sample_cnt"] = 0
        for subdir in os.listdir(SemaServer.sema_res_dir + str(nb_exp-int(page))):
            if os.path.isdir(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir):
                summary["familly_cnt"] += 1
                scdgs[subdir] = {}
                for malware in os.listdir(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir):
                    summary["sample_cnt"] += 1
                    if os.path.isdir(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir + '/' + malware):
                        malware_id = malware.split(".")[0]
                        scdgs[subdir][malware_id] = {}
                        for file in os.listdir(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir + '/' + malware):
                            if file.endswith(".json"):
                                scdgs[subdir][malware_id]["json"] = json.dumps(json.load(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir  + '/' + malware + '/' + file)), indent=2)
                            elif file.endswith("commands.log"):
                                scdgs[subdir][malware_id]["command"] = open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir + '/' + malware  + '/' + file,"r").read() #.close()
                            elif file.endswith(".log"):
                                scdgs[subdir][malware_id]["log"] = open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/' + subdir + '/' + malware  + '/' + file,"r").read() #.close()
        # scdg_logs = json.loads(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg_conf.json').read())
        # class_logs = json.loads(open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.json').read())
        
        if os.path.isfile(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg.csv'):
            df_csv_scdg = pd.read_csv(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/scdg.csv',sep=";")
        else:
            df_csv_scdg = pd.DataFrame()
            
        if os.path.isfile(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.csv'):
            df_csv_classifier = pd.read_csv(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.csv',sep=";") 
        else:
            df_csv_classifier = pd.DataFrame()
            
        if os.path.isfile(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.log'):
            log_csv_classifier = open(SemaServer.sema_res_dir + str(nb_exp-int(page)) + '/classifier.log').read()
        else:
            log_csv_classifier = ""
        
        SemaServer.current_exp = SemaServer.sema_res_dir + str(nb_exp-int(page))
        exp_dir = os.listdir(SemaServer.current_exp)
       
        # Get page number from request, 
        # default to first page
        # try:
        #     binary_fc       = open(plantuml_file_png, 'rb').read()  # fc aka file_content
        #     base64_utf8_str = b64encode(binary_fc).decode('utf-8')

        #     ext     = plantuml_file_png.split('.')[-1]
        # except:
        #     base64_utf8_str = ''
        #     ext = 'png'
        # dataurl = f'data:image/{ext};base64,{base64_utf8_str}'
        
        SemaServer.log.info(items_page)
        SemaServer.log.info(paginator)
    
        
        return render_template('results.html', 
                           items_page=items_page,
                           nb_exp=nb_exp,
                           page=int(page),
                           current_exp=SemaServer.current_exp,
                           scdg_params=scdg_params,
                           class_params=class_params,
                           scdgs=scdgs,
                           summary=summary,
                           log_csv_classifier=log_csv_classifier,
                           df_csv_scdg=df_csv_scdg.to_csv(),
                           df_csv_classifier=df_csv_classifier.to_csv(),
                           exp_dir="src/output/runs/", # "http://"+SemaServer.vizualiser_ip+":80/?file=http://"
                        )

    @app.route('/results-global.html', methods = ['GET', 'POST'])
    def serve_results_global():
        """
        It creates a folder for the project, and then calls the upload function
        :return: the upload function.
        """
        nb_exp = len(os.listdir(SemaServer.sema_res_dir)) - 2
        
        SemaServer.log.info(request.form)
        
        summary = {}
        df_csv = pd.read_csv(SemaServer.sema_res_dir + 'data.csv',parse_dates=['date'])
        
        df_simplify_date = df_csv
        df_simplify_date['date'] = df_csv['date'].dt.strftime('%d/%m/%Y')
        df_date_min_max = df_simplify_date['date'].agg(['min', 'max'])
        df_nb_date = df_simplify_date['date'].nunique()
        df_dates = df_simplify_date['date'].unique()
        SemaServer.log.info(list(df_dates))
        SemaServer.log.info(df_date_min_max)
        SemaServer.log.info(df_nb_date)
        minimum_date = df_date_min_max["min"]
        maximum_date = df_date_min_max["max"]
                
        subdf = None
        #if len(request.form) >= 0:
        for key in request.form:
            pass
        
        if subdf is not None:
            df_csv = subdf
            
        csv_text = df_csv.to_csv()
            
        return render_template('result-global.html', 
                           nb_exp=nb_exp,
                           current_exp=SemaServer.current_exp,
                           summary=summary,
                           csv_text=csv_text,
                           server_tests=SemaServer.server_tests, 
                           client_tests=SemaServer.client_tests,
                           implems=SemaServer.implems,
                           min_date=None,
                           max_date=None,
                           df_nb_date=df_nb_date,
                           df_dates=list(df_dates))



    def run(self):
        SemaServer.log.info("fuck")
        SemaServer.app.run(host='0.0.0.0', port=80, use_reloader=True, threaded=True)  #, processes=4
        
def main():
    sema = SemaServer()
    sema.run()
    sys.exit(sema.exec_())
    
if __name__ == '__main__':
    main()
