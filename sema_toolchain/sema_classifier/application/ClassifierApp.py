import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from flask import Flask, request, jsonify
import argparse
import traceback
import threading

from helper.ArgumentParserClassifier import ArgumentParserClassifier
from SemaClassifier import SemaClassifier

app = Flask(__name__)
app.debug = True

#Parse the parameters received in the request and launch the classifier
@app.route('/run_classifier', methods=['POST'])
def run_classifier():
    user_data = request.json
    parser = ArgumentParserClassifier()
    args_parser = parser.parser
    class_args, exp_args = parse_class_args(user_data, args_parser)

    toolc = SemaClassifier()
    toolc.args = parser.parse_arguments(args_list=exp_args)
    parser.update_tool(toolc, toolc.args)
    toolc.init()

    if class_args.get("operation_mode", False) == "classification":
        thread = threading.Thread(target=toolc.classify)
    elif class_args.get("operation_mode", False) == "detection":
        thread = threading.Thread(target=toolc.detect)
    else :
        thread = threading.Thread(target=toolc.train)
    thread.start()
    return {"Classifier request": "Accepted"}, 202

# Return a json object containing all the available parameters of the Classifier as well as their group, default value and help message
@app.route('/classifier_args', methods=['GET'])
def get_args_request():
    return jsonify(get_args())


def parse_class_args(user_data, args_parser):
    class_args = {}
    exp_args = []
    for group in args_parser._mutually_exclusive_groups:
        if group.title in user_data:
            exp_args.append("--" + user_data[group.title])
            class_args[user_data[group.title]] = True
    for group in args_parser._action_groups:
        for action in group._group_actions:
            if action.dest == "binary_signatures":
                pass
            elif action.dest in user_data:
                if isinstance(action, argparse._StoreTrueAction) or isinstance(action, argparse._StoreFalseAction):
                    exp_args.append("--" + action.dest)
                    class_args[action.dest] = True
                else:
                    exp_args.append("--" + action.dest)
                    exp_args.append(user_data[action.dest])
                    class_args[action.dest] = user_data[action.dest]

    class_args["binary_signatures"] = user_data["binary_signatures"]
    exp_args.append(user_data["binary_signatures"])

    return class_args, exp_args


def get_args():
    args_parser = ArgumentParserClassifier().parser
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
                    args_list[-1][group_name].append({'name': action.dest, 'help': action.help, "type": "bool", "default": True, "is_mutually_exclusive": is_mutually_exclusive})
                elif not isinstance(action, argparse._HelpAction):
                    args_list[-1][group_name].append({'name': action.dest, 'help': action.help, "type": str(action.type), "default": action.default, "is_mutually_exclusive": is_mutually_exclusive})
        is_mutually_exclusive = False
    return args_list


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5002, use_reloader=True)
