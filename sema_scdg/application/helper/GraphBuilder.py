#!/usr/bin/env python3
import claripy
import os
import json
import logging
import configparser
import sys

from graphviz import Digraph
from clogging.CustomFormatter import CustomFormatter

log_level = os.environ["LOG_LEVEL"]
logger = logging.getLogger("GraphBuilder")
ch = logging.StreamHandler()
ch.setLevel(log_level)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)
logger.propagate = False
logger.setLevel(log_level)

class GraphBuilder:
    def __init__(self):
        """
        Initialize GraphBuilder with configuration settings and logger.
        """
        config = configparser.ConfigParser()
        config.read(sys.argv[1])
        self.config = config

        self.DISCARD = {
            "LoopBreaker",
            "Dummy_call",
        }  # Nodes used for debug purpose but not real syscall
        self.TAKE = {}
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
        self.graph_output = self.config['build_graph_arg']['graph_output']
        self.MERGE_CALL = not self.config['build_graph_arg'].getboolean('disjoint_union')
        self.COMP_ARGS = not self.config['build_graph_arg'].getboolean('not_comp_args')
        self.MIN_SIZE = int(self.config['build_graph_arg']['min_size'])
        self.IGNORE_ZERO = not self.config['build_graph_arg'].getboolean('not_ignore_zero')
        self.three_edges = self.config['build_graph_arg'].getboolean('three_edges')
        ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        ROOT_DIR = ROOT_DIR.replace("/helper", "")

        self.__config_logger()

    def __set_graph_parameters(self, mapping, odir, family):
        """
        Set parameters for the next graph to be built.
        
        Args:
            mapping: Name of the file for the mapping to use.
            odir: Output directory for the graph.
            family: Family of the graph.
        """
        self.odir = odir
        self.mapping_dir = mapping
        self.family = family
        self.__create_mapping(mapping)

    def clear(self):
        """
        Reset all lists and dictionaries of the object.

        Metrics about traces which add information in the graph (or not) are reset to zero.
        """
        self.TAKE.clear()
        self.id = 0
        self.graph_file = None
        self.existing_nodes.clear()
        self.current_trace_nodes.clear()
        self.id_map = 0
        self.tabnode.clear()  # Nodes in gspan format
        self.tablink.clear()  # Edges in gspan format
        self.nodes.clear()  # mapping Node ID --> node name (addr.callname args)
        self.mapping.clear()
        self.on_flight = False
        self.dico_addr.clear()

        # Metrics about traces which add information in the graph (or not)
        self.uselessTraces = 0
        self.usefullTraces = 0
        self.totTrace = 0

    def __config_logger(self):
        """
        Setup the logger.

        Sets the log level and logger for the object.
        """
        self.log_level = log_level
        self.log = logger

    def __create_mapping(self, mapping):
        """
        Create a mapping for the different syscall name and an unique identifier.

        Args:
            mapping: Name of the file for the mapping to use (format: id syscallname\n).
        """
        try:
            map_file = open(mapping, "r")
            for line in map_file:
                tab = line.split("\n")[0].split(" ")
                self.mapping[tab[1]] = tab[0]
                self.id_map = self.id_map + 1
        except:
            pass # todo
        
    def build(self, stashes_content, mapping, odir, family):
        """
        Build the system call dependency graph using the list representing the syscalls and the mapping.
        
        Args:
            stashes_content: Content of the stashes.
            mapping: Name of the file for the mapping to use.
            odir: Output directory for the graph.
            family: Family of the graph.
        """
        self.__set_graph_parameters(mapping, odir, family)
        if self.graph_output == "":
            self.__build_graph(stashes_content, graph_output="gs")
            self.__build_graph(stashes_content, graph_output="json", gv = False)
        else :
            self.__build_graph(stashes_content, graph_output=self.graph_output)        


    def __build_links(self, trace, graph, dico={}):
        """
        Build links between calls in the graph.

        Args:
            trace: List representing syscalls.
            graph: Graph representation.
            dico: Dictionary used to build links between args.

        Returns:
            Updated dictionary with links between calls.
        """
        contribution = False

        for i in range(len(trace)):
            call = trace[i]
            if call["name"] in self.DISCARD:
                continue

            # Call was already present in the mapping. We need to add it.
            if call["name"] not in self.mapping:
                self.mapping[call["name"]] = self.id_map
                self.id_map = self.id_map + 1
                self.on_flight = True

            is_present = self.__check_duplicate(call)

            if not is_present:
                contribution = True
                graph.node(str(self.id),str(call["addr"]) + "." + call["name"]+ "\n" + self.__args_to_strings(call["args"]),)
                self.nodes[str(self.id)] = (str(call["addr"]) + "." + call["name"] + " " + self.__args_to_strings(call["args"]))
                if call["name"] in self.mapping:
                    label = self.mapping[call["name"]]
                    self.tabnode.append(f"v {str(self.id)} {str(label)}" + "\n")

                dico = self.add_link(graph, dico, call)
                if self.three_edges:
                    addr = str(call["addr_func"])
                    if addr not in self.dico_addr:
                        self.dico_addr[addr] = (str(self.id), 0)
                    if addr in dico:
                        self.__create_link((str(self.id), 0), dico[addr], graph, lab_type="2")

                self.id = self.id + 1
        self.__update_trace(contribution)
        return dico
    
    def __update_trace(self, contribution):
        """
        Update trace metrics based on the contribution.

        Args:
            contribution: Boolean indicating if the trace has added content to the graph.
        """
        if self.totTrace < 500:
            if contribution:
                self.usefullTraces += 1
            else:
                self.uselessTraces += 1
            self.totTrace += 1

    def add_link(self, graph, dico, call):
        """
        Add links between calls in the graph based on call arguments and return value.

        Args:
            graph: Graph representation.
            dico: Dictionary used to build links between args.
            call: Call information containing args and return value.
        """
        arg_id = 1
        if call["args"]:
            for j in call["args"]:
                if str(j) in dico and str(j) not in [" ", "", "None", "0"]:
                    self.__create_link((str(self.id), arg_id), dico[str(j)], graph)
                    dico[str(j)].append((self.id, arg_id))
                elif str(j) in dico and str(j) == "0" and not self.IGNORE_ZERO:
                    self.__create_link((str(self.id), arg_id), dico[str(j)], graph)
                    dico[str(j)].append((self.id, arg_id))
                else:
                    try:
                        if (str(j) not in ["", " ", "None"] and (not self.IGNORE_ZERO or int(str(j)) != 0)):
                            dico[str(j)] = [(self.id, arg_id, j)]
                    except Exception:
                        dico[str(j)] = [(self.id, arg_id, j)]
                arg_id = arg_id + 1

        ret = str(call["ret"])

        if call["ret"] != None and ret != "symbolic":
            try:
                if (str(j) not in ["", " ", "None"] and (not self.IGNORE_ZERO or int(ret) != 0)):
                    if ret in dico:
                        self.__create_link((str(self.id), 0), dico[ret], graph)
                        dico[ret].append((self.id, 0))
                    else:
                        dico[ret] = [(self.id, 0)]
            except Exception:
                if ret in dico:
                    self.__create_link((str(self.id), 0), dico[ret], graph)
                    dico[ret].append((self.id, 0))
                else:
                    dico[ret] = [(self.id, 0)]
        return dico

    def __create_link(self, node1, node_list, dot, lab_type="1"):
        """
        Create a link between nodes in the graph based on specific conditions.

        Args:
            node1: First node to link.
            node_list: List of nodes to link.
            dot: Graph representation.
            lab_type: Type of link.
        """
        for i in node_list:
            check = True
            if self.MERGE_CALL and not self.__is_in_curr_nodes(i[0]):
                check = False
            label2 = f"{lab_type}9{str(i[1])}9{str(node1[1])}"
            check2 = f"e {str(i[0])} {str(node1[0])} {label2}" + "\n"
            label3 = f"{lab_type}9{str(node1[1])}9{str(i[1])}"
            check3 = f"e {str(node1[0])} {str(i[0])} {label3}" + "\n"
            selfie = str(i[0]) == str(node1[0])

            if (check
                and (check2 not in self.tablink)
                and (check3 not in self.tablink)
                and not selfie
            ):
                dot.edge(str(i[0]), str(node1[0]), label=f"({str(i[1])}-->{str(node1[1])})")
                label = f"{lab_type}9{str(i[1])}9{str(node1[1])}"
                self.tablink.append(f"e {str(i[0])} {str(node1[0])} {label}" + "\n")

    def __build_graph(self, SCDG, graph_output="gs", gv = True):
        """
        Build the system call dependency graph using the given content.

        Args:
            SCDG: List representing syscalls.
            graph_output: Output format for the graph.
            gv: Boolean to determine if the function should also provide the gv graph.
        """
        if not os.path.exists(self.odir):
            os.makedirs(self.odir)
        self.log.info(f"Output dir :{self.odir}")
        json_content = {}
        if graph_output == "gs":
            self.graph_file = open(f"{self.odir}/final_SCDG.gs", "w")
            self.graph_file.write("t # 0\n")
        else:
            self.graph_file = open(f"{self.odir}/final_SCDG.json", "w")

        if self.MERGE_CALL:
            self.scdg_with_merge_calls(SCDG, graph_output, gv, json_content)
        else:
            self.scdg_with_disjoint_union(SCDG, graph_output, json_content)
        self.save_result(graph_output, json_content)

    def reset_attributes(self):
        """
        Reset attributes used in the graph building process.

        Clears various attributes to prepare for building a new graph.
        """
        self.id = 0
        self.tabnode = []
        self.tablink = []
        self.dico_addr.clear()
        self.existing_nodes.clear()
        self.current_trace_nodes.clear()
        self.nodes.clear()

    def scdg_with_disjoint_union(self, SCDG, graph_output, json_content):
        """
        Build the system call dependency graph with disjoint union.

        Args:
            SCDG: List representing syscalls.
            graph_output: Output format for the graph.
            json_content: Dictionary to store JSON content.

        Returns:
            None
        """
        dot = Digraph(comment="SCDG with disjoint union", format="dot")
        for i in range(len(SCDG)):
            if len(SCDG[i]) >= self.MIN_SIZE:
                json_content[f"graph_{str(i)}"] = {"nodes": [], "links": []}
                self.__build_links(SCDG[i], dot)

                for n in self.tabnode:
                    if graph_output == "json":
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
                        json_content[f"graph_{str(i)}"]["nodes"].append(newnode)
                    else:
                        self.graph_file.write(n)
                for l in self.tablink:
                    if graph_output == "json":
                        tab_split = l.split(" ")
                        newlink = {
                                "id1": tab_split[1],
                                "id2": tab_split[2],
                                "label": tab_split[3],
                            }
                        json_content[f"graph_{str(i)}"]["links"].append(newlink)
                    else:
                        self.graph_file.write(l)

                dot.save(f"{self.odir}/test-output/disjoint_union{str(i)}.gv")
                self.reset_attributes()
                dot.clear()
        dot.save(f"{self.odir}/test-output/disjoint_union.gv")

    def scdg_with_merge_calls(self, SCDG, graph_output, gv, json_content):
        """
        Build the system call dependency graph with merge calls.

        Args:
            SCDG: List representing syscalls.
            graph_output: Output format for the graph.
            gv: Boolean to determine if the function should also provide the gv graph.
            json_content: Dictionary to store JSON content.
        """
        json_content["nodes"] = []
        json_content["links"] = []

        dico = {}
        dot = Digraph(comment="Global SCDG with merge call", format="dot")

        for i in range(len(SCDG)):
            self.log.info(f"Using SCDG {str(i + 1)} over {len(SCDG)}")

            if len(SCDG[i]) >= self.MIN_SIZE:
                self.__build_links(SCDG[i], dot, dico)
            else:
                self.log.info(
                    f"The SCDG {str(i)} was too small, smaller than {str(self.MIN_SIZE)} calls."
                )
            self.current_trace_nodes.clear()

        # Save data parts
        for n in self.tabnode:
            if graph_output == "json":
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
            if graph_output == "json":
                tab_split = l.split(" ")
                newlink = {
                        "id1": tab_split[1],
                        "id2": tab_split[2],
                        "label": tab_split[3].replace("\n", ""),
                    }
                json_content["links"].append(newlink)
            else:
                self.graph_file.write(l)
        if gv:
            dot.save(f"{self.odir}/final_SCDG.gv")

    def save_result(self, graph_output, json_content):
        """
        Save the result of the graph building process.

        Args:
            graph_output: Output format for the graph.
            json_content: JSON content to be saved.
        """
        if graph_output == "json":
            json.dump(json_content, self.graph_file)
        self.graph_file.close()

        if self.on_flight:
            with open(self.mapping_dir, "w") as out_map:
                for key in self.mapping:
                    out_map.write(f"{str(self.mapping[key])} {str(key)}" + "\n")

    def __check_duplicate(self, call):
        """
        Check if a call node is a duplicate in the graph.

        Args:
            call: Information about the call node.

        Returns:
            Boolean indicating if the call node is a duplicate.
        """
        name_node = str(call["addr"]) + "." + str(call["name"])
        if name_node in self.existing_nodes:
            if not self.COMP_ARGS and name_node not in self.current_trace_nodes:
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
                    if self.__is_match(test_args, call["args"]):
                        flag = False
                if flag:
                    self.current_trace_nodes[name_node]["args"].append(call["args"])
                    self.current_trace_nodes[name_node] = {
                        "name": call["name"],
                        "args": self.current_trace_nodes[name_node]["args"],
                    }

            # For each possible set of arguments already observed
            for test_args in args:
                if self.__is_match(test_args, call["args"]):
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

    def __is_match(self, test_list, new_list):
        """
        Check if two lists match element-wise.

        Args:
            test_list (list): The list to compare elements from.
            new_list (list): The list to compare elements to.

        Returns:
            bool: True if the lists match element-wise, False otherwise.
        """
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

    def __args_to_strings(self, args):
        """
        Convert a list of arguments to a formatted string.

        Args:
            args (list): The list of arguments to convert to strings.

        Returns:
            str: A formatted string containing the arguments.
        """
        if not args:
            return ""
        ret = ""
        for a in args:
            test = str(a)
            ret = ret + test
            ret = ret + "\n"
        return ret[:-1]

    def __is_in_curr_nodes(self, ID):
        """
        Check if a given ID is in the current trace nodes.

        Args:
            ID: The ID to check for in the current trace nodes.

        Returns:
            bool: True if the ID is found in the current trace nodes, False otherwise.
        """
        str_test = self.nodes[str(ID)]
        str_name = str_test.split(" ")[0]
        if str_name in self.current_trace_nodes:
            for args in self.current_trace_nodes[str_name]["args"]:
                temp = f"{str_name} {self.__args_to_strings(args)}"
                if temp == str_test:
                    return True
        return False
