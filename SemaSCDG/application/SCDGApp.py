from flask import Flask, request, jsonify
import requests
import argparse

from SCDGHelper.ArgumentParserSCDG import ArgumentParserSCDG
from SemaSCDG import SemaSCDG


app = Flask(__name__)
app.debug = True

#Parse the parameters received in the request and launch the SCDG
@app.route('/run_scdg', methods=['POST'])
def run_scdg():
    scdg_parser = ArgumentParserSCDG()
    args_parser = scdg_parser.parser
    user_data = request.json
    exp_args = []
    # Start with _mutually_exclusive_groups
    for group in args_parser._mutually_exclusive_groups:
        if group.title in user_data:
            exp_args.append("--" + user_data[group.title])

    # For action groups
    for group in args_parser._action_groups:
        for action in group._group_actions:
            #Handle after since mandatory arguments
            if action.dest == "binary" or action.dest == "exp_dir":
                pass
            elif action.dest in user_data:
                # TODO add group_name in new dictionary
                group_name = group.title
                # For boolean arguments
                if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction):
                    exp_args.append("--" + action.dest)
                else:
                    exp_args.append("--" + action.dest)
                    exp_args.append(user_data[action.dest])  
    exp_args.append(user_data["exp_dir"]) 
    if len(user_data["binary"]) > 0:
        exp_args.append(user_data["binary"])
    else: # TODO
        # To implement: when the binary is uploaded -> Do we want to "upload" since it is only local for now
        exp_args.append(str(user_data["binary"]))

    toolc = SemaSCDG(
        print_sm_step=True,
        print_syscall=True,
        debug_error=True,
        debug_string=True,
        print_on=True
    )
    args = scdg_parser.parse_arguments(args_list=exp_args, allow_unk=True)
    scdg_parser = scdg_parser.update_tool(args, toolc)
    try:
        toolc.start_scdg(args, is_fl=False,csv_file=None)
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