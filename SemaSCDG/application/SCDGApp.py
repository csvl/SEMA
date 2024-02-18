from flask import Flask, request, jsonify
import argparse
import configparser

from scdg_helper.ArgumentParserSCDG import ArgumentParserSCDG
from SemaSCDG import SemaSCDG


app = Flask(__name__)
app.debug = True

config = configparser.ConfigParser()
config.read('config.ini')

#Parse the parameters received in the request and launch the SCDG
@app.route('/run_scdg', methods=['POST'])
def run_scdg():
    #Modify config file with the args provided in web app
    user_data = request.json
    for arg in user_data:
        if arg in config['explorer_arg']:
            config.set('explorer_arg', arg, user_data[arg])
        if arg in config['SCDG_arg']:
            config.set('SCDG_arg', arg, user_data[arg])
        if arg in config['build_graph_arg']:
            config.set('build_graph_arg', arg, user_data[arg])
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    toolc = SemaSCDG()
    try:
        toolc.start_scdg()
        return "Request successful"
    except:
        return "Something went wrong"
    
# Return a json object containing all the available parameters of the SCDG as well as their group, default value and help message
@app.route('/scdg_args', methods=['GET'])
def get_args():
    args_parser = ArgumentParserSCDG().parser
    args_list = [{}]
    is_mutually_exclusive = True
    for group_type in [args_parser._mutually_exclusive_groups, args_parser._action_groups]:
        for group in group_type:
            if group.title == "positional arguments":
                continue
            if group.title == "optional arguments":
                continue
            if len(args_list[-1]) == 3:
                args_list.append({})
            
            for action in group._group_actions:
                group_name = group.title
                if group_name not in args_list[-1]:
                    args_list[-1][group_name] = []
                if isinstance(action, argparse._StoreTrueAction):
                    args_list[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": False, "is_mutually_exclusive": is_mutually_exclusive})
                elif isinstance(action, argparse._StoreFalseAction):
                    args_list[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True,  "is_mutually_exclusive": is_mutually_exclusive})
                elif not isinstance(action, argparse._HelpAction):
                    args_list[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": is_mutually_exclusive})
        is_mutually_exclusive = False
    return jsonify(args_list)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, use_reloader=True)