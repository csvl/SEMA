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
from flask import Flask, flash, request, redirect, url_for, send_from_directory, Response, session, render_template
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

class SemaServer:
    ROOTPATH = os.getcwd()
    print(ROOTPATH)
    app = Flask(__name__, static_folder=ROOTPATH + '/SemaWebApp/static/')
    app.secret_key = 'super secret key' # TODO
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['APPLICATION_ROOT'] = ROOTPATH + '/SemaWebApp/templates/'
    app.debug = True
    
    # enable CORS
    CORS(app, resources={r'/*': {'origins': '*'}})
    
    # TODO refactor
    def __init__(self,dir_path=None,experiments=None):
        SemaServer.sema = Sema(is_from_tc=False, is_from_web=True)
        
        SemaServer.actions_scdg = [{}]
        
        for group in SemaServer.sema.args_parser.args_parser_scdg.parser._mutually_exclusive_groups:
            #print(group.title)
            if group.title == "positional arguments":
                continue
            if group.title == "optional arguments":
                continue
            
            if len(SemaServer.actions_scdg[-1]) == 3:
                SemaServer.actions_scdg.append({})
                
            for action in group._group_actions:
                # TODO add group_name in new dictionary
                group_name = group.title
                print(action)
                if group_name not in SemaServer.actions_scdg[-1]:
                    SemaServer.actions_scdg[-1][group_name] = []
                if isinstance(action, argparse._StoreTrueAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": True})
                elif isinstance(action, argparse._StoreFalseAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True, "is_mutually_exclusive": True})
                elif not isinstance(action, argparse._HelpAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": True})
            # print(SemaServer.actions_scdg)
            # exit(0)
            
        for group in SemaServer.sema.args_parser.args_parser_scdg.parser._action_groups:
            #print(group.title)
            if group.title == "positional arguments":
                continue
            if group.title == "optional arguments":
                continue
            
            if len(SemaServer.actions_scdg[-1]) == 3:
                SemaServer.actions_scdg.append({})
                
            for action in group._group_actions:
                # TODO add group_name in new dictionary
                group_name = group.title
                print(action)
                if group_name not in SemaServer.actions_scdg[-1]:
                    SemaServer.actions_scdg[-1][group_name] = []
                if isinstance(action, argparse._StoreTrueAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": False})
                elif isinstance(action, argparse._StoreFalseAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True, "is_mutually_exclusive": False})
                elif not isinstance(action, argparse._HelpAction):
                    SemaServer.actions_scdg[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": False})
            # print(SemaServer.actions_scdg)
            # exit(0)
            
        print(SemaServer.actions_scdg)
        
        SemaServer.actions_classifier = [{}]
        for group in SemaServer.sema.args_parser.args_parser_class.parser._mutually_exclusive_groups:
            #print(group.title)
            
            if len(SemaServer.actions_classifier[-1]) == 3:
                SemaServer.actions_classifier.append({})
                
            for action in group._group_actions:
                # TODO add group_name in new dictionary
                group_name = group.title
                #print(action)
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
            #print(group.title)
            
            if len(SemaServer.actions_classifier[-1]) == 3:
                SemaServer.actions_classifier.append({})
                
            for action in group._group_actions:
                # TODO add group_name in new dictionary
                group_name = group.title
                
                #print(action)
                if group_name not in SemaServer.actions_classifier[-1]:
                    SemaServer.actions_classifier[-1][group_name] = []
                if isinstance(action, argparse._StoreTrueAction):
                    SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": False})
                elif isinstance(action, argparse._StoreFalseAction):
                    SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True, "is_mutually_exclusive": False})
                elif not isinstance(action, argparse._HelpAction):
                    SemaServer.actions_classifier[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": False})
        

        print(SemaServer.actions_classifier)
        
        hostname = socket.gethostname() 
        local_ip = socket.gethostbyname(hostname)
        SemaServer.local_ip = local_ip
        print(local_ip)
        # vizualiser_ip = socket.gethostbyname("ivy-visualizer")
        # SemaServer.vizualiser_ip = vizualiser_ip
        
        SemaServer.exps = []


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

    @app.route('/index.html', methods = ['GET', 'POST'])
    def serve_index():
        """
        It creates a folder for the project, and then calls the upload function
        :return: the upload function.
        """
        if request.method == 'POST':
            print(request.form)
            
            if "scdg_enable" in request.form or True: # TODO refactor
                exp_args = []
                exp_args_str = ""
                for group in SemaServer.sema.args_parser.args_parser_scdg.parser._mutually_exclusive_groups:
                    if group.title in request.form:
                        exp_args.append("--" + request.form[group.title])
                for group in SemaServer.sema.args_parser.args_parser_scdg.parser._action_groups:
                    for action in group._group_actions:
                        if action.dest == "binary":
                            pass
                        elif action.dest == "exp_dir":
                            if len(request.files["exp_dir"].filename) > 0:
                                exp_args.append("--" + action.dest)
                                exp_args.append(request.files["exp_dir"].split("/")[0])
                            else:
                                exp_args.append("--" + action.dest)
                                exp_args.append(request.form[action.dest])
                        elif action.dest == "dir":
                            if len(request.files["dir"].filename) > 0:
                                exp_args.append("--" + action.dest)
                                exp_args.append(request.form[action.dest].split("/")[0])
                            else:
                                exp_args.append("--" + action.dest)
                                exp_args.append(request.form[action.dest])
                        elif action.dest in request.form:
                            # TODO add group_name in new dictionary
                            group_name = group.title
                            if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction):
                                exp_args.append("--" + action.dest)
                                exp_args_str += "--" + action.dest + " "
                            else:
                                exp_args.append("--" + action.dest)
                                exp_args.append(request.form[action.dest])
                                exp_args_str += "--" + action.dest + " " + request.form[action.dest] + " "       
                if len(request.form["binary"]) > 0:
                    binary = request.form["binary"]
                    binary_split = binary.split("/src")
                    print(binary_split)
                    #exit()
                    binary = "/app/src" + binary_split[1]
                    exp_args.append(binary)
                else: # TODO
                    exp_args.append(str(request.files["binary"].filename))
                    exp_args_str += str(request.files["binary"].filename)        
            if "classifier_enable" in request.form or True: # TODO refactor
                for group in SemaServer.sema.args_parser.args_parser_class.parser._mutually_exclusive_groups:
                    if group.title in request.form:
                        exp_args.append("--" + request.form[group.title])
                for group in SemaServer.sema.args_parser.args_parser_class.parser._action_groups:
                    for action in group._group_actions:
                        if action.dest == "binaries":
                            pass
                        elif action.dest in request.form:
                            # TODO add group_name in new dictionary
                            group_name = group.title
                            if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction):
                                exp_args.append("--" + action.dest)
                            else:
                                exp_args.append("--" + action.dest)
                                exp_args.append(request.form[action.dest])
                
                if len(request.files["binaries"].filename) > 0:
                    exp_args.append(request.files["binaries"].split("/")[0])
                else:
                    exp_args.append("None")
            if "fl_enable" in request.form  or True: # TODO refactor + implement
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
        

            print(exp_args)
            print(exp_args_str.split())
            #exit(0)
            #sys.argv = exp_args_str.split()
            args = SemaServer.sema.args_parser.parse_arguments(args_list=exp_args,allow_unk=True) # TODO
            print(args)
            #exit(0)
            # print(unknow)
            if "scdg_enable" in request.form:
                SemaServer.sema.args_parser.args_parser_scdg.update_tool(args)
                SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_scdg.start_scdg, args=([args])))
            
            if "classifier_enable" in request.form:
                SemaServer.sema.args = 0 # TODO
                SemaServer.sema.tool_classifier.init(exp_dir=SemaServer.sema.args.exp_dir)
                
                SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.train, args=()))

                if SemaServer.sema.tool_classifier.mode == "classification":
                    SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.classify, args=()))
                    
                else:
                    SemaServer.exps.append(threading.Thread(target=SemaServer.sema.tool_classifier.detect, args=()))
            
            if "fl_enable" in request.form:
                pass
            
            threading.Thread(target=SemaServer.manage_exps, args=()).start()
            
            return render_template('index.html', 
                                actions_scdg=SemaServer.actions_scdg, 
                                actions_classifier=SemaServer.actions_classifier,
                                progress=0) # TODO 0rtt
        else:
            return render_template('index.html', 
                                actions_scdg=SemaServer.actions_scdg, 
                                actions_classifier=SemaServer.actions_classifier,
                                progress=0)
            
    def manage_exps():
        for x in range(len(SemaServer.exps)):
            elem = SemaServer.exps.pop(x)
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
        return send_from_directory(SemaServer.ivy_temps_path + str(directory), file)
    
    @app.route('/key/<string:implem>')
    def send_key(implem):
        return send_from_directory(SemaServer.key_path, implem)
    
    @app.route('/results.html', methods = ['GET', 'POST'])
    def serve_results():
        """
        It creates a folder for the project, and then calls the upload function
        :return: the upload function.
        """
        # TODO
        print(SemaServer.ivy_temps_path)
        print(os.listdir(SemaServer.ivy_temps_path))
        SemaServer.nb_exp = len(os.listdir(SemaServer.ivy_temps_path)) - 2
        
        
        default_page = 0
        page = request.args.get('page', default_page)
        try:
            page = page.number
        except:
            pass
        # Get queryset of items to paginate
        rge = range(SemaServer.nb_exp,0,-1)
        print([i for i in rge])
        print(page)
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
            
        df_csv = pd.read_csv(SemaServer.ivy_temps_path + 'data.csv').set_index('Run')
        result_row = df_csv.iloc[SemaServer.nb_exp-int(page)-1]
        summary = {}
        summary["nb_pkt"] = result_row["NbPktSend"]
        summary["initial_version"] = result_row["initial_version"]
    
        SemaServer.current_exp = SemaServer.ivy_temps_path + str(SemaServer.nb_exp-int(page))
        SemaServer.local_exp = SemaServer.local_path + str(SemaServer.nb_exp-int(page))
        exp_dir = os.listdir(SemaServer.current_exp)
        ivy_stderr = "No output"
        ivy_stdout = "No output"
        implem_err = "No output" 
        implem_out = "No output"
        iev_out = "No output"
        qlog_file=""
        pcap_file=""
        for file in exp_dir:
            print(file)
            if 'ivy_stderr.txt' in file:
                with open(SemaServer.current_exp + '/' + file, 'r') as f:
                    content = f.read()
                    if content == '':
                        pass
                    else:
                        ivy_stderr = content
            elif 'ivy_stdout.txt' in file:
                with open(SemaServer.current_exp + '/' + file, 'r') as f:
                    content = f.read()
                    if content == '':
                        pass
                    else:
                        ivy_stdout = content
            elif '.err' in file:
                with open(SemaServer.current_exp + '/' + file, 'r') as f:
                    content = f.read()
                    if content == '':
                        pass
                    else:
                        implem_err =content
            elif '.out' in file:
                with open(SemaServer.current_exp + '/' + file, 'r') as f:
                    content = f.read()
                    if content == '':
                        pass
                    else:
                        implem_out = content
            elif '.iev' in file:
                # TODO use csv file
                # file creation timestamp in float
                c_time = os.path.getctime(SemaServer.current_exp + '/' + file)
                # convert creation timestamp into DateTime object
                dt_c = datetime.datetime.fromtimestamp(c_time)
                print('Created on:', dt_c)
                summary["date"] = dt_c
                test_name = file.replace('.iev', '')[0:-1]
                summary["test_name"] = test_name
                with open(SemaServer.current_exp + '/' + file, 'r') as f:
                    content = f.read()
                    summary["test_result"] = "Pass" if "test_completed" in content else "Fail"
                    
                try:
                    plantuml_file = SemaServer.current_exp + "/plantuml.puml"
                    generate_graph_input(SemaServer.current_exp + '/' + file, plantuml_file)
                    plantuml_obj = PlantUML(url="http://www.plantuml.com/plantuml/img/",  basic_auth={}, form_auth={}, http_opts={}, request_opts={})

                    plantuml_file_png = plantuml_file.replace('.puml', '.png') #"media/" + str(nb_exp) + "_plantuml.png"
                    plantuml_obj.processes_file(plantuml_file,  plantuml_file_png)
                    
                    with open(SemaServer.current_exp + '/' + file, 'r') as f:
                        content = f.read()
                        if content == '':
                            pass
                        else:
                            iev_out = content
                except:
                    pass
            elif '.pcap' in file:
                pcap_file = file
                # Now we need qlogs and pcap informations
                summary["implementation"] = file.split('_')[0] 
                summary["test_type"] = file.split('_')[2]
          
            elif ".qlog" in file:
                qlog_file = file
            
        # Get page number from request, 
        # default to first page
        try:
            binary_fc       = open(plantuml_file_png, 'rb').read()  # fc aka file_content
            base64_utf8_str = b64encode(binary_fc).decode('utf-8')

            ext     = plantuml_file_png.split('.')[-1]
        except:
            base64_utf8_str = ''
            ext = 'png'
        dataurl = f'data:image/{ext};base64,{base64_utf8_str}'
        print(items_page)
        print(paginator)
    
        
        return render_template('results.html', 
                           items_page=items_page,
                           nb_exp=SemaServer.nb_exp,
                           page=int(page),
                           current_exp=SemaServer.current_exp,
                           ivy_stderr=ivy_stderr,
                           ivy_stdout=ivy_stdout,
                           implem_err=implem_err,
                           implem_out=implem_out,
                           iev_out=iev_out,
                           plantuml_file_png=dataurl,
                           summary=summary, # "http://"+SemaServer.vizualiser_ip+":80/?file=http://"
                           pcap_frame_link="http://ivy-visualizer:80/?file=http://ivy-standalone:80/directory/" +  str(SemaServer.nb_exp-int(page)) + "/file/" + pcap_file + "&secrets=http://ivy-standalone:80/key/" + summary["implementation"] +'_key.log' if pcap_file != '' else None,
                           qlog_frame_link="http://ivy-visualizer:80/?file=http://ivy-standalone:80/directory/" +  str(SemaServer.nb_exp-int(page)) + "/file/" + qlog_file if qlog_file != '' else None,)

    @app.route('/results-global.html', methods = ['GET', 'POST'])
    def serve_results_global():
        """
        It creates a folder for the project, and then calls the upload function
        :return: the upload function.
        """
        SemaServer.nb_exp = len(os.listdir(SemaServer.ivy_temps_path)) - 2
        
        print(request.form)
        
        summary = {}
        df_csv = pd.read_csv(SemaServer.ivy_temps_path + 'data.csv',parse_dates=['date'])
        
        df_simplify_date = df_csv
        df_simplify_date['date'] = df_csv['date'].dt.strftime('%d/%m/%Y')
        df_date_min_max = df_simplify_date['date'].agg(['min', 'max'])
        df_nb_date = df_simplify_date['date'].nunique()
        df_dates = df_simplify_date['date'].unique()
        print(list(df_dates))
        print(df_date_min_max)
        print(df_nb_date)
        minimum_date = df_date_min_max["min"]
        maximum_date = df_date_min_max["max"]
                
        subdf = None
        #if len(request.form) >= 0:
        for key in request.form:
            if key == "date_range":
                minimum = df_dates[int(request.form.get("date_range").split(',')[0])]
                maximum = df_dates[int(request.form.get("date_range").split(',')[1])]
                if subdf is None:
                    subdf = df_csv.query('date >= @minimum and date <= @maximum')
                else:
                    subdf = subdf.query('date >= @minimum and date <= @maximum')
            elif key == "iter_range":
                minimum = request.form.get("iter_range").split(',')[0]
                maximum = request.form.get("iter_range").split(',')[1]
                if subdf is None: # TOODO
                    subdf = df_csv.loc[df_csv['Run'] >= int(minimum)]
                    subdf = subdf.loc[subdf['Run'] <= int(maximum)]
                else:
                    subdf = subdf.loc[subdf['Run'] >= int(minimum)]
                    subdf = subdf.loc[subdf['Run'] <= int(maximum)]
            elif key == "version":
                if request.form.get("version") != "all":
                    if subdf is None: # TOODO
                        subdf = df_csv.loc[df_csv['initial_version'] == request.form.get("version")]
                    else: 
                        subdf = subdf.loc[subdf['initial_version'] == request.form.get("version")]
            elif key == "ALPN":
                if request.form.get("ALPN") != "all":
                    if subdf is None: # TOODO
                        subdf = df_csv.loc[df_csv['Mode'] == request.form.get("test_type")]
                    else: 
                        subdf = subdf.loc[subdf['Mode'] == request.form.get("test_type")]
            elif key == "test_type":
                if request.form.get("test_type") != "all":
                    if subdf is None:
                        subdf = df_csv.loc[df_csv['Mode'] == request.form.get("test_type")]
                    else: 
                        subdf = subdf.loc[subdf['Mode'] == request.form.get("test_type")]
            elif key == "isPass":
                ispass = True if "True" in request.form.get("isPass") else False
                if request.form.get("isPass") != "all":
                    if subdf is None:
                        subdf = df_csv.loc[df_csv['isPass'] == ispass]
                    else: 
                        subdf = subdf.loc[subdf['isPass'] == ispass]
            elif key == "implem":
                for i in request.form.getlist("implem"):
                    print(i)
                    if subdf is None:
                        subdf = df_csv.loc[df_csv['Implementation'] == i]
                    else: 
                        subdf = subdf.loc[subdf['Implementation'] == i]
            elif key == "server_test":
                for i in request.form.getlist("server_test"):
                    if subdf is None:
                        subdf = df_csv.loc[df_csv['TestName'] == i]
                    else: 
                        subdf = subdf.loc[subdf['TestName'] == i]
            elif key == "client_test":
                for i in request.form.getlist("client_test"):
                    if subdf is None:
                        subdf = df_csv.loc[df_csv['TestName'] == i]
                    else: 
                        subdf = subdf.loc[subdf['TestName'] == i]
        
        if subdf is not None:
            df_csv = subdf
            
        csv_text = df_csv.to_csv()
            
        return render_template('result-global.html', 
                           nb_exp=SemaServer.nb_exp,
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
        print("fuck")
        SemaServer.app.run(host='0.0.0.0', port=80, use_reloader=True, threaded=True)  #, processes=4
        
def main():
    sema = SemaServer()
    sema.run()
    sys.exit(sema.exec_())
    
if __name__ == '__main__':
    main()