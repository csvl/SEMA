#!/usr/bin/env python3
import claripy
from graphviz import Digraph
import os
import json
import logging

# from ToolChainWorkerExporer import ROOT_DIR


class GraphBuilder:
    def __init__(
        self,
        mapping=None,
        name=None,
        merge_call=True,
        comp_args=True,
        min_size=3,
        ignore_zero=True,
        three_edges = False,
        odir=None,
        get_info=False,
        verbose=False,
        familly="unknown"
    ):
        self.DISCARD = {
            "LoopBreaker",
            "Dummy_call",
        }  # Nodes used for debug purpose but not real syscall
        self.TAKE = {}
        self.lw = logging.getLogger("GraphBuilder")
        self.lw.setLevel("INFO")
        self.mapping = mapping
        self.id = 0
        self.graph_file = None
        self.existing_nodes = {}
        self.current_trace_nodes = {}
        self.id_map = 0
        self.tabnode = []  # Nodes in gspan format
        self.tablink = []  # Edges in gspan format
        self.nodes = {}  # mapping Node ID --> node name (addr.callname args)
        self.mapping = {}
        self.on_flight = False
        self.dico_addr = {}

        # Metrics about traces which add information in the graph (or not)
        self.uselessTraces = 0
        self.usefullTraces = 0
        self.totTrace = 0

        # Default value of parameters
        self.MERGE_CALL = merge_call
        self.COMP_ARGS = comp_args
        self.MIN_SIZE = min_size
        self.IGNORE_ZERO = ignore_zero
        self.three_edges = three_edges
        ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        ROOT_DIR = ROOT_DIR.replace("/helper", "")

        self.get_info = get_info

        self.verbose = verbose

        self.create_mapping(mapping)

        if not name:
            self.name = "test"
        else:
            self.name = name

        if odir:
            self.odir = odir + "/" + familly
            if not os.path.exists(self.odir):
                os.makedirs(self.odir)
        else:
            self.odir = "output/save-SCDG/"  + "/" + familly # ROOT_DIR +
        self.lw.info("Output dir :" + self.odir)

    # Create a mapping for the different syscall name and an unique identifier.
    # args : mapping = name of the file for the mapping to use (format : id syscallname\n)
    def create_mapping(self, mapping):
        try:
            map_file = open(mapping, "r")
            for line in map_file:
                tab = line.split("\n")[0].split(" ")
                self.mapping[tab[1]] = tab[0]
                self.id_map = self.id_map + 1
        except:
            pass # todo
        

    def build_links(self, trace, graph, dico={}):
        # self.lw.info("Building links between calls")
        # Dictionnary used to build link between args
        # Variable to check if this trace has added some content to the graph
        contribution = False

        for i in range(len(trace)):
            call = trace[i]

            # Call was already present in the mapping. We need to add it.
            if (call["name"] not in self.DISCARD) and (
                call["name"] not in self.mapping
            ):
                self.mapping[call["name"]] = self.id_map
                self.id_map = self.id_map + 1
                self.on_flight = True

            # Check if a similar node already exists
            if call["name"] in self.DISCARD:
                is_present = True
            else:
                is_present = self.check_duplicate(call)

            if not is_present:
                contribution = True
                graph.node(
                    str(self.id),
                    str(call["addr"])
                    + "."
                    + call["name"]
                    + "\n"
                    + self.args_to_strings(call["args"]),
                )
                self.nodes[str(self.id)] = (
                    str(call["addr"])
                    + "."
                    + call["name"]
                    + " "
                    + self.args_to_strings(call["args"])
                )
                if call["name"] in self.mapping:
                    label = self.mapping[call["name"]]
                    self.tabnode.append("v " + str(self.id) + " " + str(label) + "\n")

                arg_id = 1
                if call["args"]:
                    for j in call["args"]:

                        if (
                            str(j) in dico
                            and str(j) != " "
                            and str(j) != ""
                            and str(j) != "None"
                            and str(j) != "0"
                        ):
                            self.create_link(
                                (str(self.id), arg_id), dico[str(j)], graph
                            )
                            dico[str(j)].append((self.id, arg_id))
                        elif str(j) in dico and str(j) == "0" and not self.IGNORE_ZERO:
                            self.create_link(
                                (str(self.id), arg_id), dico[str(j)], graph
                            )
                            dico[str(j)].append((self.id, arg_id))
                        else:
                            try:
                                if (
                                    str(j) == ""
                                    or str(j) == " "
                                    or str(j) == "None"
                                    or (self.IGNORE_ZERO and int(str(j)) == 0)
                                ):
                                    pass
                                else:
                                    dico[str(j)] = [(self.id, arg_id, j)]
                            except Exception:
                                dico[str(j)] = [(self.id, arg_id, j)]

                        arg_id = arg_id + 1

                if "ref_str" in call and False:
                    self.lw.info("ref_str")
                    for j in call["ref_str"]:
                        ref = call["ref_str"][j]
                        if str(ref) in dico:
                            self.create_link((str(self.id), j), dico[str(ref)], graph)
                            dico[str(ref)].append((self.id, j))
                        else:
                            try:
                                if self.IGNORE_ZERO and int(str(ref)) == 0:
                                    pass
                                else:
                                    dico[str(ref)] = [(self.id, j, str(ref))]
                            except Exception:
                                dico[str(ref)] = [(self.id, j, str(ref))]

                ret = str(call["ret"])

                if call["ret"] != None and ret != "symbolic":
                    try:
                        if (
                            str(j) == ""
                            or str(j) == " "
                            or str(j) == "None"
                            or (self.IGNORE_ZERO and int(ret) == 0)
                        ):
                            pass
                        else:
                            if ret in dico:
                                self.create_link((str(self.id), 0), dico[ret], graph)
                                dico[ret].append((self.id, 0))

                            else:
                                dico[ret] = [(self.id, 0)]
                    except Exception:
                        if ret in dico:
                            self.create_link((str(self.id), 0), dico[ret], graph)
                            dico[ret].append((self.id, 0))
                        else:
                            dico[ret] = [(self.id, 0)]
                if self.three_edges:
                    addr = str(call["addr_func"])
                    if addr not in self.dico_addr:
                        self.dico_addr[addr] = (str(self.id), 0)
                    if addr in dico:
                        self.create_link((str(self.id), 0), dico[addr], graph, lab_type="2")

                self.id = self.id + 1
        if self.totTrace < 500:
            if contribution:
                self.usefullTraces = self.usefullTraces + 1
            else:
                self.uselessTraces = self.uselessTraces + 1
            self.totTrace = self.totTrace + 1
        return dico

    def create_link(self, node1, node_list, dot, lab_type="1"):
        for i in node_list:
            check = True
            if self.MERGE_CALL and not self.is_in_curr_nodes(i[0]):
                check = False
            label2 = lab_type + "9" + str(i[1]) + "9" + str(node1[1])
            check2 = "e " + str(i[0]) + " " + str(node1[0]) + " " + label2 + "\n"
            label3 = lab_type + "9" + str(node1[1]) + "9" + str(i[1])
            check3 = "e " + str(node1[0]) + " " + str(i[0]) + " " + label3 + "\n"
            selfie = str(i[0]) == str(node1[0])

            if (
                check
                and (check2 not in self.tablink)
                and (check3 not in self.tablink)
                and not selfie
            ):
                dot.edge(
                    str(i[0]),
                    str(node1[0]),
                    label="(" + str(i[1]) + "-->" + str(node1[1]) + ")",
                )
                label = lab_type + "9" + str(i[1]) + "9" + str(node1[1])
                self.tablink.append(
                    "e " + str(i[0]) + " " + str(node1[0]) + " " + label + "\n"
                )

    def build_graph(self, SCDG, format_out="gs"):
        json_content = {}
        if format_out != "json":
            self.graph_file = open(self.odir + "/SCDG_" + self.name + ".gs", "w")
            self.graph_file.write("t # 0\n")
        else:
            self.graph_file = open(self.odir + "/SCDG_" + self.name + ".json", "w")

        if self.MERGE_CALL:
            json_content["nodes"] = []
            json_content["links"] = []

            dico = {}
            dot = Digraph(comment="Global SCDG with merge call", format="dot")

            for i in range(len(SCDG)):
                if self.verbose:
                    self.lw.info("Using SCDG " + str(i + 1) + " over " + str(len(SCDG)))

                if len(SCDG[i]) >= self.MIN_SIZE:
                    # import pdb; pdb.set_trace()
                    self.build_links(SCDG[i], dot, dico)
                else:
                    if self.verbose:
                        self.lw.info(
                            "The SCDG "
                            + str(i)
                            + " was too small, smaller than "
                            + str(self.MIN_SIZE)
                            + " calls."
                        )
                self.current_trace_nodes.clear()

            # Save data parts
            for n in self.tabnode:
                if format_out == "json":
                    # json_content['nodes'].append(n)
                    id_node = n.replace("\n", "").split(" ")[1]
                    node_name = self.nodes[id_node].split(" ")[0]
                    arg_node = self.nodes[id_node].split(" ")[1].split("\n")
                    content = self.existing_nodes[node_name]
                    newnode = {
                        "id": id_node,
                        "name": content["name"],
                        "addr": node_name.split(".")[0],
                        "args": arg_node,
                    }
                    json_content["nodes"].append(newnode)
                else:
                    self.graph_file.write(n)
            for l in self.tablink:
                if format_out == "json":
                    tab_split = l.split(" ")
                    newlink = {
                        "id1": tab_split[1],
                        "id2": tab_split[2],
                        "label": tab_split[3].replace("\n", ""),
                    }
                    json_content["links"].append(newlink)
                else:
                    self.graph_file.write(l)

            # dot.render(self.odir+'/SCDG_'+self.name+'.dot', view=False,nslimit=2)
            dot.save(self.odir + "/SCDG_" + self.name + ".gv")
            if format_out == "json":
                json.dump(json_content, self.graph_file)
        else:
            dot = Digraph(comment="SCDG with disjoint union", format="dot")
            for i in range(len(SCDG)):
                if len(SCDG[i]) >= self.MIN_SIZE:
                    json_content["graph_" + str(i)] = {}
                    json_content["graph_" + str(i)]["nodes"] = []
                    json_content["graph_" + str(i)]["links"] = []
                    self.build_links(SCDG[i], dot)

                    for n in self.tabnode:
                        if format_out == "json":
                            # json_content['nodes'].append(n)
                            id_node = n.replace("\n", "").split(" ")[1]
                            node_name = self.nodes[id_node].split(" ")[0]
                            arg_node = self.nodes[id_node].split(" ")[1].split("\n")
                            content = self.existing_nodes[node_name]
                            newnode = {
                                "id": id_node,
                                "name": content["name"],
                                "addr": node_name.split(".")[0],
                                "args": arg_node,
                            }
                            json_content["graph_" + str(i)]["nodes"].append(newnode)
                        else:
                            self.graph_file.write(n)
                    for l in self.tablink:
                        if format_out == "json":
                            tab_split = l.split(" ")
                            newlink = {
                                "id1": tab_split[1],
                                "id2": tab_split[2],
                                "label": tab_split[3],
                            }
                            json_content["graph_" + str(i)]["links"].append(newlink)
                        else:
                            self.graph_file.write(l)

                    dot.save("../output/test-output/disjoint_union" + str(i) + ".gv")
                    self.id = 0
                    self.tabnode = []
                    self.tablink = []
                    self.dico_addr.clear()
                    self.existing_nodes.clear()
                    self.current_trace_nodes.clear()
                    self.nodes.clear()
                    dot.clear()

            dot.save("../output/test-output/disjoint_union.gv")
            if format_out == "json":
                json.dump(json_content, self.graph_file)
        self.graph_file.close()
        # dot.render('output/test-output/disjoint_union.gv', view=False) # really heavy could crash

        if self.on_flight:
            out_map = open("mapping.txt", "w")
            for key in self.mapping:
                out_map.write(str(self.mapping[key]) + " " + str(key) + "\n")
            out_map.close()

    # Check if a call is already present in the graph
    # If COMP_ARGS : a call is considered present if it had same addr,name and all of its args
    #                corresponding to a node already present
    # If not COMP_ARGS : a call is considered present if it had same addr and name corresponding to a node already present
    # Add the call to existing_node if relevant and return Boolean
    def check_duplicate(self, call):
        name_node = str(call["addr"]) + "." + str(call["name"])
        if name_node in self.existing_nodes:
            if not self.COMP_ARGS:
                # We just care about call name and address, since node already exists, we add it to current_traces_nodes (to authorize creation of new link)
                # But we return True since node already exists
                if name_node not in self.current_trace_nodes:
                    self.current_trace_nodes[name_node] = {
                        "name": call["name"],
                        "args": [call["args"]],
                    }
                    return True

            self.existing_nodes[name_node]["name"]
            args = self.existing_nodes[name_node]["args"]

            if name_node not in self.current_trace_nodes:
                self.current_trace_nodes[name_node] = {
                    "name": call["name"],
                    "args": [call["args"]],
                }
            else:
                flag = True
                for test_args in self.current_trace_nodes[name_node]["args"]:
                    # Check if a node exist with exactly the same args
                    if self.is_match(test_args, call["args"]):
                        flag = False
                if flag:
                    self.current_trace_nodes[name_node]["args"].append(call["args"])
                    self.current_trace_nodes[name_node] = {
                        "name": call["name"],
                        "args": self.current_trace_nodes[name_node]["args"],
                    }

            # For each possible set of arguments already observed
            for test_args in args:
                if self.is_match(test_args, call["args"]):
                    return True
            # If it's a new set of arguments
            args.append(call["args"])
            self.existing_nodes[name_node] = {"name": call["name"], "args": args}
            return False

        # The node has never been seen before in another trace, add it !
        self.existing_nodes[name_node] = {"name": call["name"], "args": [call["args"]]}
        self.current_trace_nodes[name_node] = {
            "name": call["name"],
            "args": [call["args"]],
        }
        return False

    # Check if two list of args match
    def is_match(self, test_list, new_list):
        if not test_list or not new_list:
            return True
        if isinstance(test_list, int) and isinstance(new_list, int):
            return test_list == new_list

        for i in range(len(test_list)):
            ## TODO: Change Handler of symbolic Value
            if isinstance(test_list[i], claripy.ast.bv.BV) or isinstance(
                new_list[i], claripy.ast.bv.BV
            ):
                return False
            if str(test_list[i]) != str(new_list[i]):
                return False
        return True

    def args_to_strings(self, args):
        if not args:
            return ""
        ret = ""
        for a in args:
            test = str(a)
            ret = ret + str(test)
            ret = ret + "\n"
        ret = ret[:-1]
        return ret

    def is_in_curr_nodes(self, ID):
        str_test = self.nodes[str(ID)]
        str_name = str_test.split(" ")[0]
        if str_name in self.current_trace_nodes:
            for args in self.current_trace_nodes[str_name]["args"]:
                temp = str_name + " " + self.args_to_strings(args)
                if temp == str_test:
                    return True
        return False
