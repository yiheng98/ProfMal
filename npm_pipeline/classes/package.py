from __future__ import annotations

import csv
import re
import os
import sys
import copy
import llm
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from base_classes.cpg_node import CPGNode
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.program_context import ProgramContext
from base_classes.cpg_pdg_edge import Edge
from npm_pipeline.classes.object import Object
from npm_pipeline.classes.identifier import Identifier
from npm_pipeline.classes.api_call import APICallCollection
from base_classes.pbg import PBG
from ast_parser import ASTParser
from base_classes.report import Report
from sensitive_op import sensitive_property_access_finder
from sensitive_op import sensitive_call_finder
from loguru import logger
from object_type_dict import GLOBAL_OBJECT, FUNCTION_REF, FILE_LEVEL_MODULE, PARAMETER, REST_PARAMETER, OBJECT
from call_type_dict import ASSIGNMENT, FIELD_ACCESS, FUNCTION_CALL, NORMAL_CALL, INDEX_ACCESS, NEW_CALL
import static_helper
import dynamic_helper
import networkx as nx
from custom_exception import DynamicRunningException
from custom_exception import DynamicCallGraphEmptyException
from custom_exception import JoernGenerationExceptionInDynamic
from networkx.drawing.nx_agraph import write_dot
from instance_method import is_instance_method
from detector.mal_detector import detect
import shlex
import sensitive_degree_helper
from status import STATUS_BENIGN, STATUS_CODE_MALICIOUS
import glob
import traceback
import json

sys.setrecursionlimit(20000)


def merge_pbg(pbg: PBG, sub_pbg: PBG):
    sub_result_entrance = sub_pbg.get_entrance_node()
    if not pbg.pdg_node_is_in(sub_result_entrance):
        sub_result_nodes = sub_pbg.get_pdg_nodes()
        sub_result_in_edges = sub_pbg.get_pdg_in_edges()
        sub_result_out_edges = sub_pbg.get_pdg_out_edges()
        sub_result_edges = sub_pbg.get_pdg_edges()
        pbg.add_batch_pdg_nodes(sub_result_nodes)
        pbg.add_batch_pdg_in_edges(sub_result_in_edges)
        pbg.add_batch_pdg_out_edges(sub_result_out_edges)
        pbg.add_batch_pdg_edges(sub_result_edges)

        sub_result_object_nodes = sub_pbg.get_object_nodes()
        sub_result_pdg_to_object_edge = sub_pbg.get_pdg_object_data_edge()
        sub_result_object_to_pdg_edge = sub_pbg.get_object_pdg_data_edge()
        pbg.add_batch_object_nodes(sub_result_object_nodes)
        pbg.add_batch_pdg_object_data_edge(sub_result_pdg_to_object_edge)
        pbg.add_batch_object_pdg_data_edge(sub_result_object_to_pdg_edge)


class Package:
    def __init__(self, package_name, original_package_dir, workspace_dir, package_json):
        self.package_name: str = package_name
        self.workspace_dir: str = workspace_dir
        self.original_package_dir: str = original_package_dir
        self.package_json = package_json
        self.need_dynamic = False
        self.graph_only = False
        self.install_time_behavior = None
        self.import_time_behavior = None
        self.package_report = Report()  # Package behavior collection
        self.program_context_backup: dict[int, ProgramContext] = {}  # Store program state for branch handling
        self.program_context = None
        self.static_code_info = None
        self.dynamic_code_info = None
        self.current_code_info = None
        self.analyzed_script = set()
        self.need_dynamic_entry = set()
        self.loaded_history = set()
        self.global_visited = set()
        self.file_in_cg = set()

    # Currently only analyze install & import scripts
    def analyse(self, overwrite: bool, dynamic_support: bool, graph_only: bool):
        """
        Analyze the behavior of installation and import phases
        :return: behaviors
        """

        def check_existence(entry_script_set: set[str], format_dir):
            new_set = set()
            for sc in entry_script_set:
                if os.path.exists(os.path.join(format_dir, "package", sc)):
                    new_set.add(sc)
            return new_set

        def generate_static_info(entry_script_set: set[str]):
            # Joern and Jelly under static analysis
            formatted_package_dir = os.path.join(self.workspace_dir, self.package_name, "static", "format")
            joern_dir = os.path.join(self.workspace_dir, self.package_name, "static", "joern")
            pdg_dir = os.path.join(joern_dir, "pdg")
            cfg_dir = os.path.join(joern_dir, "cfg")
            cpg_dir = os.path.join(joern_dir, "cpg")
            jelly_cg_path = os.path.join(self.workspace_dir, self.package_name, "static", "jelly", "cg.json")
            pickle_path = os.path.join(self.workspace_dir, self.package_name, "static", "static-pickle")
            self.static_code_info = static_helper.generate_static_info(
                cfg_dir,
                cpg_dir,
                formatted_package_dir,
                jelly_cg_path,
                joern_dir,
                pickle_path,
                overwrite,
                self.original_package_dir,
                pdg_dir,
                entry_script_set,
            )

        def generate_program_behavior(entry_script_: str, condition: str):
            if condition == "static":
                self.current_code_info = self.static_code_info
            else:
                self.current_code_info = self.dynamic_code_info
            file_relative_path = os.path.normpath(os.path.join("package", entry_script_))
            if not (
                file_relative_path.endswith(".js")
                or file_relative_path.endswith(".mjs")
                or file_relative_path.endswith(".cjs")
            ):
                file_relative_path = file_relative_path + ".js"

            if file_relative_path in self.analyzed_script:
                return None
            else:
                self.analyzed_script.add(file_relative_path)
            # find the implicit main of the script
            self.file_in_cg.add(file_relative_path)
            pdg_of_script = self.find_pdg_by_file(file_relative_path)
            if pdg_of_script is None:
                logger.info(f"Can not find the pdg of the script: {entry_script_} in abs path: {file_relative_path}")
                self.need_dynamic = True
                return None

            logger.info(f"▶️{condition.upper()} ANALYSIS OF {entry_script_}")
            program_behavior = PBG(
                self.current_code_info.cpg,
                self.current_code_info.pdg_dict,
                self.current_code_info.formatted_package_dir,
                self.package_name,
            )
            self.program_context = ProgramContext(self.current_code_info.js_file_list)  # init the program context
            self.add_global_object(program_behavior)
            script_behavior = self.gen_behavior(
                file_relative_path, pdg_of_script, "implicit main", program_behavior, None
            )
            logger.info(f"🆗{condition.upper()} FINISHED OF {entry_script_}")
            return script_behavior

        def output_graph_from_pbg(program_behavior: PBG, folder_name: str, graph_prefix: str):
            pbg_dot = program_behavior.pdg_to_dot()
            dot_name = os.path.join(self.workspace_dir, self.package_name, folder_name, "dot", f"{graph_prefix}.dot")
            parent_dir = os.path.dirname(dot_name)
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)
            write_dot(pbg_dot, dot_name)
            sensitive_pbg = program_behavior.extract_sensitive_subgraph(self.current_code_info)
            dot_name = os.path.join(
                self.workspace_dir, self.package_name, folder_name, "dot", f"{graph_prefix}-sen.dot"
            )
            write_dot(sensitive_pbg, dot_name)

        def output_graph_from_api_collections(api_call_collection: APICallCollection, graph_prefix: str):
            graph = self.generate_program_behavior_by_api_call(api_call_collection)
            dot_name = os.path.join(self.workspace_dir, self.package_name, "dynamic", "dot", f"{graph_prefix}-sen.dot")
            parent_dir = os.path.dirname(dot_name)
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)
            write_dot(graph, dot_name)

        def generate_dynamic_info(entry_file: str):
            formatted_package_dir = os.path.join(self.workspace_dir, self.package_name, "dynamic", "format")
            joern_dir = os.path.join(self.workspace_dir, self.package_name, "dynamic", "joern")
            pdg_dir = os.path.join(joern_dir, "pdg")
            cfg_dir = os.path.join(joern_dir, "cfg")
            cpg_dir = os.path.join(joern_dir, "cpg")
            jelly_cg_dir = os.path.join(self.workspace_dir, self.package_name, "dynamic", "jelly")
            api_info_dir = os.path.join(self.workspace_dir, self.package_name, "dynamic", "api")
            normalized_path_ = os.path.normpath(entry_file)
            safe_entry_ = re.sub(r'[\\/:*?"<>|]', "-", normalized_path_)
            pickle_file_path = os.path.join(self.workspace_dir, self.package_name, "dynamic", f"{safe_entry_}-pickle")

            self.dynamic_code_info = dynamic_helper.generate_dynamic_info(
                self.original_package_dir,
                formatted_package_dir,
                joern_dir,
                pdg_dir,
                cfg_dir,
                cpg_dir,
                jelly_cg_dir,
                api_info_dir,
                overwrite,
                entry_file,
                pickle_file_path,
                self.static_code_info,
                self.file_in_cg,
            )

        # ------START------
        self.graph_only = graph_only
        entry_script = self.package_json.get_install_script()
        if self.package_json.get_main():
            entry_script.add(self.package_json.get_main())
        if self.package_json.get_bin_scrip():
            entry_script.update(self.package_json.get_bin_scrip())

        # check the script is exist or not
        entry_script = check_existence(entry_script, self.original_package_dir)

        # ------STATIC------
        if entry_script:
            try:
                generate_static_info(entry_script)
            except TimeoutError:
                # raise the timeout error
                raise TimeoutError
            except Exception as e:
                logger.info(f"Exception caught in generate_static_info: {e}. Switching to dynamic pipeline.")
                logger.warning("Execution trace:\n" + traceback.format_exc())
                # Switch to dynamic pipeline by adding all entry scripts.
                for entry in entry_script:
                    self.need_dynamic_entry.add(entry)
            else:
                # ------STATIC PIPELINE------
                for entry in entry_script:
                    self.global_visited.clear()
                    self.need_dynamic = False
                    self.loaded_history.clear()
                    static_program_behavior = generate_program_behavior(entry, "static")
                    if static_program_behavior:
                        normalized_path = os.path.normpath(entry)
                        safe_entry = re.sub(r'[\\/:*?"<>|]', "-", normalized_path)
                        output_graph_from_pbg(static_program_behavior, "static", safe_entry)
                    if self.need_dynamic:
                        self.need_dynamic_entry.add(entry)

        if self.need_dynamic_entry:
            logger.info(f"Dynamic Analysis Needed of {','.join(self.need_dynamic_entry)}")

        # ------DYNAMIC PIPELINE------
        if dynamic_support:
            self.analyzed_script.clear()
            for entry in self.need_dynamic_entry:
                normalized_path = os.path.normpath(entry)
                safe_entry = re.sub(r'[\\/:*?"<>|]', "-", normalized_path)
                try:
                    self.global_visited.clear()
                    self.loaded_history.clear()
                    self.file_in_cg.add(os.path.join("package", normalized_path))
                    generate_dynamic_info(entry)
                    dynamic_program_behavior = generate_program_behavior(entry, "dynamic")
                    if dynamic_program_behavior:
                        output_graph_from_pbg(dynamic_program_behavior, "dynamic", safe_entry)
                    else:
                        # if the behavior is none, generate by the API Info
                        api_call_info = self.dynamic_code_info.api_call_info
                        if api_call_info:
                            output_graph_from_api_collections(api_call_info, safe_entry)
                except DynamicRunningException as e:
                    logger.warning(f"Dynamic Analysis Failed: {e}")
                except JoernGenerationExceptionInDynamic as e:
                    logger.warning(f"Joern Generation Failed in Dynamic: {e}")
                    api_call_info = e.api_call_info
                    if api_call_info:
                        output_graph_from_api_collections(api_call_info, safe_entry)
                except DynamicCallGraphEmptyException as e:
                    logger.info("Dynamic Call Graph Generation Failed")
                    api_call_info = e.api_call_info
                    if api_call_info:
                        output_graph_from_api_collections(api_call_info, safe_entry)
                except Exception as e:
                    logger.warning(f"Exception caught in dynamic analysis: {e}")
                    logger.warning("Execution trace:\n" + traceback.format_exc())

        self.merge_sensitive_graph()

        if not self.graph_only:
            return self.detect_maliciousness()
        else:
            return STATUS_BENIGN

    def merge_sensitive_graph(self):
        static_folder = os.path.join(self.workspace_dir, self.package_name, "static", "dot")
        dynamic_folder = os.path.join(self.workspace_dir, self.package_name, "dynamic", "dot")
        static_sen_files = glob.glob(os.path.join(static_folder, "*-sen.dot"))
        dynamic_sen_files = glob.glob(os.path.join(dynamic_folder, "*-sen.dot"))

        all_files = static_sen_files + dynamic_sen_files
        merged_graph = nx.MultiDiGraph()

        for dot_file in all_files:
            graph = nx.nx_agraph.read_dot(dot_file)
            merged_graph = nx.compose(merged_graph, graph)

        if merged_graph.number_of_nodes() > 0:
            write_dot(merged_graph, os.path.join(self.workspace_dir, self.package_name, "sensitive.dot"))

    def detect_maliciousness(self):
        logger.info("Start Detecting Maliciousness")
        dot_path = os.path.join(self.workspace_dir, self.package_name, "sensitive.dot")
        if not os.path.exists(dot_path):
            return STATUS_BENIGN
        else:
            if detect(dot_path):
                logger.info("Find malicious code")
                return STATUS_CODE_MALICIOUS
            else:
                logger.info("Not find malicious code")
                return STATUS_BENIGN

    @staticmethod
    def generate_program_behavior_by_api_call(api_collection: APICallCollection):
        G = nx.MultiDiGraph()
        node_ids = []
        for idx, api_call in enumerate(api_collection.collections):
            # Use index as node id
            if api_call.type == "function":
                sensitive_info = sensitive_call_finder.query(f"{api_call.module}.{api_call.function}")
                if sensitive_info["domain"] == "Process":
                    degree = sensitive_degree_helper.get_subprocess_sensitivity_degree(
                        sensitive_info["full_name"], api_call.arguments
                    )
                elif sensitive_info["domain"] == "File":
                    degree = sensitive_degree_helper.get_file_sensitivity_degree(
                        sensitive_info["full_name"], api_call.arguments, api_call.result
                    )
                else:
                    degree = 0.5
                node_id = idx
                G.add_node(
                    node_id,
                    label=f"{api_call.module}.{api_call.function}",
                    color="black",
                    full_name=sensitive_info["full_name"],
                    domain=sensitive_info["domain"],
                    degree=degree,
                )
                node_ids.append(node_id)

        for i in range(len(node_ids) - 1):
            source = node_ids[i]
            target = node_ids[i + 1]

            # Ensure the nodes exist in the graph before adding edges
            if source in G and target in G:
                # Add control_flow edge
                G.add_edge(source, target, label="Control_Flow")
        return G

    def add_global_object(self, program_behavior):
        global_object_list = self.program_context.get_global_object_list()
        for global_object in global_object_list:
            program_behavior.add_object(global_object)

    def find_pdg_by_file(self, file_name: str) -> PDG | None:
        """
        find the pdg by file name
        """
        for key, value in self.current_code_info.pdg_dict.items():
            if value.get_name() == ":program" and value.get_file_name() == file_name:
                # find the pdg of the file
                return value
        return None

    def find_pdg_by_method_full_name(self, method_full_name: str):
        """
        find the pdg by the method full name
        """
        for key, value in self.current_code_info.pdg_dict.items():
            if value.get_full_name().strip() == method_full_name:
                # find the pdg of the file
                return value
        return None

    def find_pdg_by_file_and_loc(
        self, file_name: str, line_number: int, column_number: int, end_line_number: int, end_column_number: int
    ):
        """
        find the pdg by the file name and the loc
        """
        for key, value in self.current_code_info.pdg_dict.items():
            if (
                value.get_file_name() == file_name
                and value.get_line_number() == line_number
                and value.get_column_number() == column_number
                and value.get_line_number_end() == end_line_number
                and value.get_column_number_end() == end_column_number
            ):
                # find the pdg of the given file and loc
                return value
        return None

    def add_previous_util(self, current_node: int, background: PBG, result: PBG, visited: set):
        if current_node not in visited:
            visited.add(current_node)
            if current_node in background.get_pdg_in_edges():
                # Current node has incoming edges
                heads = background.get_pdg_in_edges()[current_node]
                for head in heads:
                    result.add_pdg_node(background.get_pdg_nodes()[head])
                    edge = background.get_pdg_edges()[(head, current_node)]
                    result.add_pdg_edge(head, current_node, edge.get_attr())
                    self.add_previous_util(head, background, result, visited)

    def gen_behavior(self, filename: str, pdg: PDG, pdg_type: str, program_behavior: PBG, parameter_list: list | None):
        """
        generate the behavior of the given pdg in [filename]
        :param filename: file of the pdg
        :param pdg: pdg
        :param pdg_type: the type of pdg, e.g. program, function
        :param program_behavior: the behavior of the program
        :param parameter_list: the parameter to the function
        :return: the behavior of the pdg
        """
        self.file_in_cg.add(filename)
        nodes = pdg.get_nodes()

        # the first node is the entrance of the pdg
        first_node = nodes[pdg.get_first_node_id()]
        visited = self.global_visited
        program_behavior.add_pdg_node(first_node)
        program_behavior.set_entrance_node(first_node)
        out_edges = pdg.get_out_edges()
        if first_node.get_id() in out_edges:
            successive_node_ids = out_edges[first_node.get_id()]
            if pdg_type == "function" or pdg_type == "lambda":
                if first_node.get_id() in out_edges:
                    is_rest = False
                    parameter_send_index = 0
                    for index, successive_node_id in enumerate(successive_node_ids):
                        successive_node = pdg.get_nodes()[successive_node_id]
                        if successive_node.get_node_type() == "METHOD_PARAMETER_IN":
                            # the node is parameter
                            parameter_name = successive_node.get_name()
                            parameter_code = successive_node.get_code()
                            if parameter_name != "this":
                                if parameter_code.startswith("..."):
                                    is_rest = True
                                    parameter = Identifier(
                                        name=parameter_name,
                                        line_number=successive_node.get_line_number(),
                                        column_number=successive_node.get_column_number(),
                                        node_id=successive_node.get_id(),
                                        file=filename,
                                        source_pdg=pdg.get_first_node_id(),
                                        identifier_type=REST_PARAMETER,
                                    )
                                else:
                                    parameter = Identifier(
                                        name=parameter_name,
                                        line_number=successive_node.get_line_number(),
                                        column_number=successive_node.get_column_number(),
                                        node_id=successive_node.get_id(),
                                        source_pdg=pdg.get_first_node_id(),
                                        file=filename,
                                        identifier_type=PARAMETER,
                                    )
                                parameter_object = Object(
                                    name=f"{parameter_name}-{successive_node.get_id()}",
                                    object_type=PARAMETER,
                                    source_pdg=pdg.get_first_node_id(),
                                )
                                parameter.set_ref_object(parameter_object)
                                self.program_context.get_file_context(filename).add_identifier(parameter)
                                self.program_context.get_file_context(filename).add_object(parameter_object)
                                program_behavior.add_pdg_to_object_data_edge(successive_node.get_id(), parameter_object)
                                if parameter_list:
                                    if is_rest:
                                        # the rest parameter should be the last one
                                        parameter.get_ref_object().set_full_name(None)
                                        break
                                    if 0 <= parameter_send_index < len(parameter_list):
                                        send_parameter = parameter_list[parameter_send_index]
                                    else:
                                        send_parameter = None
                                    if send_parameter is None:
                                        parameter.get_ref_object().set_full_name(None)
                                    elif isinstance(parameter_list[parameter_send_index], Object):
                                        parameter.set_ref_object(parameter_list[parameter_send_index])
                                        program_behavior.add_object_to_pdg_edge(
                                            parameter_list[parameter_send_index], successive_node.get_id()
                                        )
                                    elif isinstance(parameter_list[parameter_send_index], tuple):
                                        base_object = parameter_list[parameter_send_index][0]
                                        property_list = list(parameter_list[parameter_send_index][1])
                                        actual_value = self.get_actual_value(base_object, property_list)
                                        if isinstance(actual_value, Object):
                                            # Points to Object
                                            parameter.set_ref_object(actual_value)
                                            program_behavior.add_object_to_pdg_edge(
                                                actual_value, successive_node.get_id()
                                            )
                                        else:
                                            parameter.get_ref_object().set_full_name(actual_value)
                                        pass
                                    else:
                                        parameter.get_ref_object().set_full_name(None)
                                    parameter_send_index += 1

        current_node = first_node
        self.behavior_gen_util(
            former_node=first_node,
            current_node=current_node,
            pdg=pdg,
            filename=filename,
            visited=visited,
            program_behavior=program_behavior,
            pdg_type=pdg_type,
        )
        return program_behavior

    @staticmethod
    def get_actual_value(ref_object: Object, property_list: list[str]):
        """
        Get the actual return value, which can be an object or string
        """
        if len(property_list) == 0:
            return ref_object
        else:
            return ref_object.get_property_actual_value(property_list)

    @staticmethod
    def resolve_full_name(ref_object: Object, property_list: list[str]):
        """
        Resolve the current full name, keeping cases where list length is 1
        """
        if not property_list or len(property_list) == 0:
            return ref_object, property_list
        elif len(property_list) == 1:
            # keep the one property access remain unchanged
            return ref_object, property_list
        else:
            return ref_object.resolve(property_list)

    def behavior_gen_util(
        self,
        former_node: PDGNode,
        current_node: PDGNode,
        pdg: PDG,
        filename: str,
        visited: set,
        program_behavior: PBG,
        pdg_type: str,
    ):
        """
        the behavior generation func for implicit main, function and anonymous function
        """
        in_edge = None
        if current_node != former_node:
            # not the first node
            in_edge = pdg.get_edges()[(former_node.get_id(), current_node.get_id())]
            program_behavior.add_pdg_edge(former_node.get_id(), current_node.get_id(), in_edge.get_attr())
        if current_node.get_id() not in visited:
            # Check if the previous node is a branch
            if former_node.is_branch() and former_node.get_id() in self.program_context_backup:
                self.program_context = copy.deepcopy(self.program_context_backup[former_node.get_id()])
            program_behavior.add_pdg_node(current_node)
            visited.add(current_node.get_id())
            if current_node == former_node:
                pass
            elif current_node.get_node_type() == "RETURN":
                self.process_return_node(current_node, filename, pdg, program_behavior)
            elif current_node.get_node_type() == "METHOD_PARAMETER_IN":
                # the current node is parameter, just add edge here
                pass
            elif current_node.get_node_type() == "CALL":
                # `call type` node
                # the edge is not added before the call_node_process func
                self.call_node_process(
                    former_node=former_node,
                    current_node=current_node,
                    pdg=pdg,
                    filename=filename,
                    program_behavior=program_behavior,
                    in_edge=in_edge,
                )
            else:
                # other types
                pass

            out_edges = pdg.get_out_edges()
            if current_node.get_id() in out_edges:
                # judge current node contains branch
                is_branch = self.is_branch(current_node, pdg)
                if is_branch:
                    # save the context
                    current_node.set_the_branch()
                    self.program_context_backup[current_node.get_id()] = copy.deepcopy(self.program_context)

                successive_node_ids = out_edges[current_node.get_id()]
                node_id_list = []
                for successive_node_id in successive_node_ids:
                    out_edge = pdg.get_edges()[(current_node.get_id(), successive_node_id)]

                    # Determine the type of connecting edges, prioritize CFG edges and add them first
                    if self.edge_attr_contain_cfg(out_edge):
                        node_id_list.insert(0, ("CFG", successive_node_id))
                    if self.edge_attr_contain_ddg(out_edge):
                        node_id_list.append(("DDG", successive_node_id))

                # Recursive call to behavior_gen_util
                for node_id in node_id_list:
                    self.behavior_gen_util(
                        former_node=current_node,
                        current_node=pdg.get_nodes()[node_id[1]],
                        pdg=pdg,
                        filename=filename,
                        visited=visited,
                        program_behavior=program_behavior,
                        pdg_type=pdg_type,
                    )
        else:
            # the node is already accessed
            if in_edge:
                type_of_in_edge = self.get_type_of_edge(in_edge)
                if type_of_in_edge == "DDG":
                    # the former node has data dependency with current node
                    if former_node.get_call_type() == "FUNCTION_CALL":
                        # the former node is function call, add the return value to the node
                        self.add_the_return_value_to_current_node(former_node, current_node, in_edge, program_behavior)

    def is_branch(self, pdg_node: PDGNode, pdg: PDG):
        current_node_id = pdg_node.get_id()
        successive_node_ids = pdg.get_out_edges()[current_node_id]
        branch_size = 0
        for successive_node_id in successive_node_ids:
            out_edge = pdg.get_edges()[(current_node_id, successive_node_id)]
            if self.edge_attr_contain_cfg(out_edge) == "CFG":
                branch_size += 1
        if branch_size > 2:
            return True
        else:
            return False

    def process_return_node(self, current_node, filename, pdg, program_behavior):
        # return object of the function
        program_behavior.add_return_node(current_node)
        current_node.set_is_return(True)
        ast = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        if len(ast) == 0:
            logger.warning(f"The AST children size is zero in return node. Node id: {current_node.get_id()}")
        else:
            first_return_value = ast[0]
            first_return_value_pdg_node = (
                pdg.get_node(first_return_value.get_id()) if first_return_value.get_id() in pdg.get_nodes() else None
            )
            if first_return_value_pdg_node:
                if first_return_value_pdg_node.get_node_type() == "IDENTIFIER":
                    found_identifier = self.program_context.get_file_context(filename).find_identifier(
                        first_return_value_pdg_node.get_code(), current_node.get_line_number()
                    )
                    if found_identifier:
                        current_node.set_return_value(found_identifier.get_ref_object())
                        ref_object = found_identifier.get_ref_object()
                        program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())
                else:
                    current_node.set_return_value(first_return_value_pdg_node.get_node_full_name())
                program_behavior.add_pdg_edge(first_return_value_pdg_node.get_id(), current_node.get_id(), ["DDG"])

    def add_the_return_value_to_current_node(
        self, former_node: PDGNode, current_node: PDGNode, in_edge: Edge, program_behavior: PBG
    ):
        """
        the former node is function call, which have return value
        """
        function_behavior = former_node.get_behavior_of_call()
        if function_behavior:
            return_value_list = function_behavior.get_return_value()
            if return_value_list and len(return_value_list) > 0:
                # exist return value
                type_of_in_edge = self.get_type_of_edge(in_edge)
                if type_of_in_edge == "DDG":
                    attr_list = in_edge.get_attr()
                else:
                    attr_list = ["DDG"]
                for return_value in return_value_list:
                    program_behavior.add_pdg_edge(return_value.get_id(), current_node.get_id(), attr_list)

    @staticmethod
    def get_type_of_edge(edge: Edge):
        """
        if the DDG exists in the edge's attr, the edge is DDG
        """
        attr_list = edge.get_attr()
        for attr in attr_list:
            if "DDG" in attr:
                return "DDG"
        return "CFG"

    @staticmethod
    def edge_attr_contain_cfg(edge: Edge):
        """
        If the CFG exists in the edge's attr, the edge is CFG
        """
        attr_list = edge.get_attr()
        for attr in attr_list:
            if "CFG" in attr:
                return True
        return False

    @staticmethod
    def edge_attr_contain_ddg(edge: Edge):
        """
        If the DDG exists in the edge's attr, the edge is DDG
        """
        attr_list = edge.get_attr()
        for attr in attr_list:
            if "DDG" in attr:
                return True
        return False

    def call_node_process(
        self, former_node: PDGNode, current_node: PDGNode, pdg: PDG, filename: str, program_behavior: PBG, in_edge: Edge
    ):
        file_context = self.program_context.get_file_context(filename)
        call_name = current_node.get_name()
        if call_name == "__ecma.Array.factory":
            # array creation
            return
        if call_name == "<operator>.assignment":
            # the node is assignment
            self.process_assignment(current_node, pdg, filename, file_context, program_behavior)
        else:
            if former_node.get_call_type() == "FUNCTION_CALL":
                # the former node is function call but not in the assignment mode
                self.add_the_return_value_to_current_node(former_node, current_node, in_edge, program_behavior)
            if call_name == "<operator>.fieldAccess":
                self.process_field_access(current_node, pdg, file_context, program_behavior)
            elif call_name == "<operator>.indexAccess":
                self.process_index_access(current_node, pdg, file_context, program_behavior)
            elif call_name == "<operator>.new":
                self.process_new_operation(current_node, pdg, file_context, program_behavior)
            elif call_name == "<operator>.iterator":
                self.process_iterator(current_node, pdg, file_context, program_behavior)
            elif call_name == "require":
                # process module require
                self.process_require(current_node, file_context, program_behavior)
            elif call_name == "<operator>.addition":
                # A + B + C
                self.process_addition(current_node, pdg, program_behavior)
            elif call_name == "<operator>.assignmentPlus":
                self.process_assignment_plus(current_node, pdg, program_behavior, file_context)
            elif call_name == "<operator>.formatString":
                self.process_format_string(current_node, pdg, program_behavior, file_context)
            elif call_name == "<operator>.await":
                self.process_await_call(current_node, pdg, program_behavior)
            elif call_name is not None and re.search(r"<lambda>\d*", call_name):
                # Immediately invoked function
                callee = self.get_callee(current_node)
                if callee:
                    self.lambda_function(current_node, file_context, callee, program_behavior)

            # function or method call
            elif (
                call_name is not None and "<operator>" not in call_name and re.search(r"<lambda>\d*", call_name) is None
            ):
                self.function_call(current_node, pdg, call_name, file_context, program_behavior)
            elif call_name is None:
                self.function_call(current_node, pdg, "None", file_context, program_behavior)
            else:
                pass

    def process_assignment(
        self,
        current_node: PDGNode,
        pdg: PDG,
        filename: str,
        file_context: FileContext,
        program_behavior: PBG,
    ):
        ast = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        current_node.set_call_type(ASSIGNMENT)

        left_ast_node = ast[0]  # left side of the assignment
        right_ast_node = ast[1]  # right side of the assignment

        left_base_object, left_full_name, left_identifier, left_ast_pdg_node = None, None, None, None
        left_ast_node_label = left_ast_node.get_value("label")
        right_ast_node_label = right_ast_node.get_value("label")

        if left_ast_node_label == "IDENTIFIER":
            # the left side is identifier, create an identifier
            left_is_identifier = True
            identifier_name = left_ast_node.get_value("CODE")
            left_identifier = Identifier(
                name=identifier_name,
                line_number=current_node.get_line_number(),
                column_number=current_node.get_column_number(),
                identifier_type="IDENTIFIER",
                node_id=current_node.get_id(),
                source_pdg=pdg.get_first_node_id(),
                file=filename,
            )

            left_base_object = Object(
                name=f"{identifier_name}-{current_node.get_id()}",
                object_type=OBJECT,
                source_pdg=pdg.get_first_node_id(),
            )
            left_identifier.set_ref_object(left_base_object)
            program_behavior.add_object(left_base_object)
            program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_base_object)
            file_context.add_identifier(left_identifier)
            file_context.add_object(left_base_object)

        else:
            left_is_identifier = False
            left_ast_pdg_node = (
                pdg.get_node(left_ast_node.get_id()) if left_ast_node.get_id() in pdg.get_nodes() else None
            )
            if left_ast_pdg_node:
                left_full_name = left_ast_pdg_node.get_node_full_name()
                if left_full_name:
                    base_object = left_full_name[0]
                    property_list = list(left_full_name[1])
                    if base_object.get_object_type() == "THIS_OBJECT" and len(property_list) == 1:
                        # the left side of the assignment is like this.a
                        _object = Object(
                            name=f"{property_list[0]}-{current_node.get_id()}",
                            object_type=OBJECT,
                            source_pdg=pdg.get_first_node_id(),
                        )
                        # add the variable to the `this` object's property
                        base_object.set_property(".".join(property_list), _object)
                        program_behavior.add_object(_object)
                        program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), _object)
                    else:
                        program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), base_object)

        # Process right-side node based on its type
        if right_ast_node_label == "IDENTIFIER":
            self._handle_right_identifier(
                current_node,
                left_is_identifier,
                left_identifier,
                left_full_name,
                right_ast_node,
                pdg,
                program_behavior,
                file_context,
            )
        elif right_ast_node_label == "LITERAL":
            self._handle_right_literal(
                current_node, left_is_identifier, left_identifier, left_full_name, right_ast_node
            )
        elif right_ast_node_label == "BLOCK":
            self._handle_right_block(
                current_node,
                left_is_identifier,
                left_identifier,
                left_full_name,
                right_ast_node,
                pdg,
                program_behavior,
                file_context,
            )
        else:
            self._handle_right(
                current_node, left_is_identifier, left_identifier, left_full_name, right_ast_node, pdg, program_behavior
            )

    def process_await_call(self, current_node, pdg, program_behavior):
        ast = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        if ast:
            first_ast_node = ast[0]
            if first_ast_node.get_id() in pdg.get_nodes():
                first_ast_pdg_node = pdg.get_node(first_ast_node.get_id())
                if first_ast_pdg_node.get_call_type() == FUNCTION_CALL:
                    current_node.set_behavior_of_call(first_ast_pdg_node.get_behavior_of_call())
                else:
                    current_node.set_node_full_name(first_ast_pdg_node.get_node_full_name())
                program_behavior.add_pdg_edge(first_ast_pdg_node.get_id(), current_node.get_id(), ["DDG: await"])

        else:
            logger.warning(f"The AST children size is empty in await process. Node id: {current_node.get_id()}")
            return

    def _handle_right_literal(self, current_node, left_is_identifier, left_identifier, left_full_name, right_ast_node):
        if left_is_identifier and left_identifier:
            # Left side is identifier, right side is literal
            left_identifier.get_ref_object().set_full_name(right_ast_node.get_value("CODE").strip("\"'"))
            current_node.set_node_full_name((left_identifier.get_ref_object(), []))
        else:
            if left_full_name:
                left_ref_object = left_full_name[0]
                property_list = list(left_full_name[1])
                actual_value = self.get_actual_value(left_ref_object, property_list)
                if isinstance(actual_value, Object):
                    actual_value.set_full_name(right_ast_node.get_value("CODE").strip("\"'"))
                else:
                    left_ref_object.set_property(".".join(property_list), right_ast_node.get_value("CODE").strip("\"'"))
                current_node.set_node_full_name((left_ref_object, property_list))

    def _handle_right_block(
        self,
        current_node,
        left_is_identifier,
        left_identifier,
        left_full_name,
        right_ast_node,
        pdg,
        program_behavior,
        file_context,
    ):
        right_block_full_name = None
        # get the ast of the right block
        ast_list = self.current_code_info.cpg.get_children_ast(right_ast_node.get_id())
        for ast_node in ast_list:
            if ast_node.get_value("NAME") == "<operator>.assignment":
                if not self.has_ddg_line_of_two_nodes(current_node.get_id(), ast_node.get_id(), pdg):
                    program_behavior.add_pdg_edge(
                        ast_node.get_id(), current_node.get_id(), [f"DDG: {ast_node.get_value('CODE')}"]
                    )
            elif ast_node.get_value("label") == "LOCAL":
                local_name = ast_node.get_value("NAME")
                if local_name:
                    found_identifier = file_context.find_identifier(local_name, current_node.get_line_number())
                    if found_identifier:
                        program_behavior.add_object_to_pdg_edge(
                            found_identifier.get_ref_object(), current_node.get_id()
                        )
            elif ast_node.get_value("label") == "CALL":
                if ast_node.get_id() in pdg.get_nodes():
                    right_block_full_name = pdg.get_node(ast_node.get_id()).get_node_full_name()

        if left_is_identifier and left_identifier:
            # Left side is identifier, right side is block
            if right_block_full_name:
                actual_value = self.get_actual_value(right_block_full_name[0], right_block_full_name[1])
                if isinstance(actual_value, Object):
                    left_identifier.set_ref_object(actual_value)
                    program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
                    current_node.set_node_full_name((actual_value, []))
                else:
                    left_identifier.get_ref_object().set_full_name(actual_value)
                    current_node.set_node_full_name((right_block_full_name[0], right_block_full_name[1]))
            else:
                left_identifier.get_ref_object().set_full_name(None)
                current_node.set_node_full_name((left_identifier.get_ref_object(), []))
        else:
            if left_full_name:
                left_ref_object = left_full_name[0]
                property_list = list(left_full_name[1])
                if property_list:
                    if right_block_full_name:
                        actual_value = self.get_actual_value(right_block_full_name[0], right_block_full_name[1])
                        left_ref_object.set_property(".".join(property_list), actual_value)
                        if isinstance(actual_value, Object):
                            program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
                    else:
                        left_ref_object.set_property(".".join(property_list), None)
                current_node.set_node_full_name((left_ref_object, property_list))

    def _handle_right(
        self, current_node, left_is_identifier, left_identifier, left_full_name, right_ast_node, pdg, program_behavior
    ):
        """
        Handle cases when right side is not IDENTIFIER, with different processing based on function calls and left side IDENTIFIER status.
        """
        right_ast_pdg_node = (
            pdg.get_node(right_ast_node.get_id()) if right_ast_node.get_id() in pdg.get_nodes() else None
        )
        if right_ast_pdg_node:
            if right_ast_pdg_node.get_call_type() == "FUNCTION_CALL":
                function_behavior = right_ast_pdg_node.get_behavior_of_call()
                # Right side is user-defined function call
                if left_is_identifier and left_identifier:
                    # case-1: Left side is identifier, right side is function call
                    self._handle_call_return_for_left_identifier(
                        current_node, left_identifier, program_behavior, function_behavior
                    )
                else:
                    # case-2: Left side is not identifier, right side is function call
                    self._handle_call_return_for_left_non_identifier(
                        current_node, left_full_name, program_behavior, function_behavior
                    )
            else:
                # Right side is CALL, but not a function call (possibly built-in or other cases)
                self._handle_non_function_call(
                    current_node,
                    left_is_identifier,
                    left_identifier,
                    left_full_name,
                    right_ast_node,
                    pdg,
                    program_behavior,
                )
        else:
            # right ast pdg node not found
            if left_is_identifier and left_identifier:
                current_node.set_node_full_name((left_identifier.get_ref_object(), []))

    def _handle_call_return_for_left_identifier(
        self, current_node, left_identifier, program_behavior, function_behavior
    ):
        """
        case-1: Left side is identifier, right side is function call
        """
        if function_behavior:
            return_value_list = function_behavior.get_return_value()
            if return_value_list:
                # If there are multiple return values, cannot bind a definite full_name to the left side
                if len(return_value_list) != 1:
                    left_identifier.get_ref_object().set_full_name(None)
                else:
                    value = return_value_list[0]
                    self._bind_left_identifier_to_value(current_node, left_identifier, value, program_behavior)

                # Add DDG edges for all return values
                for value in return_value_list:
                    program_behavior.add_pdg_edge(value.get_id(), current_node.get_id(), [f"DDG: {value.get_code()}"])
            else:
                left_identifier.get_ref_object().set_full_name(None)
        else:
            left_identifier.get_ref_object().set_full_name(None)

        program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_identifier.get_ref_object())

    def _handle_call_return_for_left_non_identifier(
        self,
        current_node,
        left_full_name,
        program_behavior,
        function_behavior,
    ):
        """
        case-2: Left side is not identifier, right side is function call
        """
        if left_full_name:
            # the left full is not None
            left_base_object = left_full_name[0]
            property_list = list(left_full_name[1])
            if function_behavior:
                return_value_list = function_behavior.get_return_value()
                if return_value_list:
                    if len(return_value_list) != 1:
                        # Multiple return values
                        if property_list:
                            left_base_object.set_property(".".join(property_list), None)
                    else:
                        # Only one return value
                        value = return_value_list[0]
                        self._bind_left_object_property(current_node, left_base_object, property_list, value)

                    # Add DDG edges for all return values
                    for value in return_value_list:
                        program_behavior.add_pdg_edge(
                            value.get_id(), current_node.get_id(), [f"DDG: {value.get_code()}"]
                        )
                else:
                    # Function has no return value
                    if property_list:
                        left_base_object.set_property(".".join(property_list), None)

            else:
                # function_behavior does not exist
                if property_list:
                    left_base_object.set_property(".".join(property_list), None)

            actual_value = self.get_actual_value(left_base_object, property_list)
            if isinstance(actual_value, Object):
                program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), actual_value)
            else:
                program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_base_object)
        else:
            if function_behavior:
                return_value_list = function_behavior.get_return_value()
                if return_value_list:
                    # Add DDG edges for all return values
                    for value in return_value_list:
                        program_behavior.add_pdg_edge(
                            value.get_id(), current_node.get_id(), [f"DDG: {value.get_code()}"]
                        )

    def _handle_non_function_call(
        self, current_node, left_is_identifier, left_identifier, left_full_name, right_ast_node, pdg, program_behavior
    ):
        """
        Handle cases when self.is_function_call() returns False, i.e., right side is not a function call
        """
        right_id = right_ast_node.get_id()
        if right_id not in pdg.get_nodes():
            logger.warning(f"Cannot find the pdg node in assignment. Node id: {current_node.get_id()}")
            return

        right_ast_pdg_node = pdg.get_node(right_id)
        # Add DDG edge
        program_behavior.add_pdg_edge(
            right_ast_pdg_node.get_id(), current_node.get_id(), [f"DDG: {right_ast_pdg_node.get_code()}"]
        )

        # Only process subsequent logic when left side has identifier or full_name
        if not ((left_is_identifier and left_identifier) or left_full_name):
            return

        right_node_type = right_ast_pdg_node.get_node_type()
        if right_node_type == "METHOD_REF":
            # case-1: Right side is function definition, if left side is identifier, mark it as function reference
            if left_is_identifier:
                left_identifier.set_identifier_type(FUNCTION_REF)
            return

        right_node_full_name = right_ast_pdg_node.get_node_full_name()
        if right_node_full_name:
            # Right side resolved to full_name
            if left_is_identifier:
                # case-3: Left side is identifier, right side is non-function call node
                actual_value = self.get_actual_value(right_node_full_name[0], right_node_full_name[1])
                if isinstance(actual_value, Object):
                    left_identifier.set_ref_object(actual_value)
                    program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
                    current_node.set_node_full_name((actual_value, []))
                else:
                    left_identifier.get_ref_object().set_full_name(actual_value)
                    current_node.set_node_full_name((right_node_full_name[0], list(right_node_full_name[1])))
            else:
                # case-4: Left side is not identifier, right side is non-function call node
                left_base_object = left_full_name[0]
                left_property_list = list(left_full_name[1])
                if left_property_list:
                    actual_value = self.get_actual_value(right_node_full_name[0], right_node_full_name[1])
                    left_base_object.set_property(".".join(left_property_list), actual_value)
                current_node.set_node_full_name((right_node_full_name[0], list(right_node_full_name[1])))
                program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_base_object)
        else:
            # Right side full_name resolution failed
            if left_is_identifier:
                # case-5: Left side is identifier
                if right_ast_pdg_node.get_code() == "__ecma.Array.factory()":
                    left_identifier.get_ref_object().set_full_name("array")
                else:
                    left_identifier.get_ref_object().set_full_name(None)
            else:
                # case-6: Left side is not identifier
                left_base_object = left_full_name[0]
                left_property_list = list(left_full_name[1])
                # Handle special case __ecma.Array.factory()
                if right_ast_pdg_node.get_code() == "__ecma.Array.factory()":
                    actual_value = self.get_actual_value(left_base_object, left_property_list)
                    if isinstance(actual_value, Object):
                        actual_value.set_full_name("array")
                    elif left_property_list:
                        left_base_object.set_property(".".join(left_property_list), "array")
                program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_base_object)

    def _bind_left_identifier_to_value(self, current_node, left_identifier, value, program_behavior):
        """
        Bind the left identifier with the return value, handling Object and node full name cases differently.
        """
        if isinstance(value, Object):
            # Left side directly binds to returned Object
            left_identifier.set_ref_object(value)
            program_behavior.add_object_to_pdg_edge(value, current_node.get_id())
            current_node.set_node_full_name((value, []))
        elif isinstance(value, tuple):
            # Left side binds to right side's full name
            actual_value = self.get_actual_value(value[0], value[1])
            if isinstance(actual_value, Object):
                # Right side actually points to Object
                left_identifier.set_ref_object(actual_value)
                program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
                current_node.set_node_full_name((actual_value, []))
            else:
                left_identifier.get_ref_object().set_full_name(actual_value)
                current_node.set_node_full_name(value[0], list(value[1]))
        else:
            # Unrecognized type
            left_identifier.get_ref_object().set_full_name(None)

    def _bind_left_object_property(self, current_node, left_base_object, property_list, value):
        """
        Bind return value to the property of the left base_object.
        """
        if isinstance(value, Object):
            if property_list:
                # set the property bind to object
                left_base_object.set_property(".".join(property_list), value)
            current_node.set_node_full_name((value, []))
        elif isinstance(value, tuple):
            if property_list:
                actual_value = self.get_actual_value(value[0], value[1])
                left_base_object.set_property(".".join(property_list), actual_value)
            current_node.set_node_full_name(value[0], list(value[1]))
        else:
            # Return value is neither Object nor str
            if property_list:
                left_base_object.set_property(".".join(property_list), None)

    def _handle_right_identifier(
        self,
        current_node,
        left_is_identifier,
        left_identifier,
        left_full_name,
        right_ast_node,
        pdg,
        program_behavior,
        file_context,
    ):
        """
        Handle cases when right side is IDENTIFIER, with different processing based on whether left side is IDENTIFIER
        """
        right_identifier_name = right_ast_node.get_value("CODE")
        right_identifier = file_context.find_identifier(right_identifier_name, current_node.get_line_number())

        if left_is_identifier and left_identifier:
            # case-7: Both left and right sides of equation are identifiers
            if right_identifier:
                left_identifier.set_ref_object(right_identifier.get_ref_object())
                current_node.set_node_full_name((right_identifier.get_ref_object(), []))

                # Add edge from Object to PDG
                program_behavior.add_object_to_pdg_edge(right_identifier.get_ref_object(), current_node.get_id())

                # Add PDG edge
                if right_identifier.get_node_id() is not None:
                    if not self.has_ddg_line_of_two_nodes(current_node.get_id(), right_identifier.get_node_id(), pdg):
                        program_behavior.add_pdg_edge(
                            right_identifier.get_node_id(), current_node.get_id(), [f"DDG: {right_identifier_name}"]
                        )
                    else:
                        attr = pdg.get_edges()[(right_identifier.get_node_id(), current_node.get_id())].get_attr()
                        program_behavior.add_pdg_edge(right_identifier.get_node_id(), current_node.get_id(), attr)
            else:
                # Right side identifier does not exist
                pass

        else:
            # case-8: Left side is non-identifier, right side is identifier
            if left_full_name:
                if right_identifier:
                    left_ref_object = left_full_name[0]
                    property_list = list(left_full_name[1])

                    # the property str point an object
                    left_ref_object.set_property(".".join(property_list), right_identifier.get_ref_object())
                    current_node.set_node_full_name((right_identifier.get_ref_object(), []))

                    # Add edge from PDG node to object
                    program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_ref_object)
                    # Add edge from object to PDG
                    program_behavior.add_object_to_pdg_edge(right_identifier.get_ref_object(), current_node.get_id())

                    # Add PDG edge
                    if right_identifier.get_node_id() is not None:
                        if not self.has_ddg_line_of_two_nodes(
                            current_node.get_id(), right_identifier.get_node_id(), pdg
                        ):
                            program_behavior.add_pdg_edge(
                                right_identifier.get_node_id(), current_node.get_id(), [f"DDG: {right_identifier_name}"]
                            )
                        else:
                            attr = pdg.get_edges()[(right_identifier.get_node_id(), current_node.get_id())].get_attr()
                            program_behavior.add_pdg_edge(right_identifier.get_node_id(), current_node.get_id(), attr)
            else:
                if right_identifier:
                    program_behavior.add_object_to_pdg_edge(right_identifier.get_ref_object(), current_node.get_id())

    def process_addition(self, current_node: PDGNode, pdg: PDG, program_behavior: PBG):
        ast = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        if len(ast) < 2:
            logger.warning(f"The AST children size is smaller than 2 in Addition. node id: {current_node.get_id()}")
        else:
            left_of_addition = ast[0]
            if left_of_addition.get_id() in pdg.get_nodes():
                pdg_node = pdg.get_nodes()[left_of_addition.get_id()]
                program_behavior.add_pdg_edge(
                    left_of_addition.get_id(), current_node.get_id(), [f"DDG:{pdg_node.get_code()}"]
                )
            right_of_addition = ast[1]
            if right_of_addition.get_id() in pdg.get_nodes():
                pdg_node = pdg.get_nodes()[right_of_addition.get_id()]
                program_behavior.add_pdg_edge(
                    right_of_addition.get_id(), current_node.get_id(), [f"DDG:{pdg_node.get_code()}"]
                )

    def process_assignment_plus(
        self, current_node: PDGNode, pdg: PDG, program_behavior: PBG, file_context: FileContext
    ):
        ast = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        if len(ast) < 2:
            logger.warning(
                f"The AST children size is smaller than 2 in Assignment Plus. node id: {current_node.get_id()}"
            )
            return
        else:
            right_ast_node = ast[1]
            if right_ast_node.get_id() in pdg.get_nodes():
                pdg_node = pdg.get_nodes()[right_ast_node.get_id()]
                program_behavior.add_pdg_edge(
                    right_ast_node.get_id(), current_node.get_id(), [f"DDG:{pdg_node.get_code()}"]
                )

        left_ast_node = ast[0]
        left_ast_node_label = left_ast_node.get_value("label")

        if left_ast_node_label == "IDENTIFIER":
            identifier_name = left_ast_node.get_value("CODE")
            found_identifier = file_context.find_identifier(identifier_name, current_node.get_line_number())
            if found_identifier:
                ref_object = found_identifier.get_ref_object()
                program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), ref_object)
        else:
            left_ast_pdg_node = (
                pdg.get_node(left_ast_node.get_id()) if left_ast_node.get_id() in pdg.get_nodes() else None
            )
            if left_ast_pdg_node:
                left_ast_pdg_node_full_name = left_ast_pdg_node.get_node_full_name()
                if left_ast_pdg_node_full_name:
                    program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), left_ast_pdg_node_full_name[0])

    def process_format_string(self, current_node: PDGNode, pdg: PDG, program_behavior: PBG, file_context: FileContext):
        ast_list = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        for ast in ast_list:
            if ast.get_id() in pdg.get_nodes():
                pdg_node = pdg.get_nodes()[ast.get_id()]
                program_behavior.add_pdg_edge(ast.get_id(), current_node.get_id(), [f"DDG:{pdg_node.get_code()}"])
            if ast.get_value("label") == "IDENTIFIER":
                identifier_name = ast.get_value("CODE")
                found_identifier = file_context.find_identifier(identifier_name, current_node.get_line_number())
                if found_identifier:
                    ref_object = found_identifier.get_ref_object()
                    program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())

    def process_field_access(self, current_node: PDGNode, pdg: PDG, file_context: FileContext, program_behavior: PBG):
        """
        handle the <operator>.fieldAccess
        """
        current_node.set_call_type(FIELD_ACCESS)
        ast = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        if len(ast) < 2:
            logger.warning(f"The AST children size is smaller than 2. node id: {current_node.get_id()}")
        else:
            left_of_field_access = ast[0]
            right_of_field_access = ast[1]
            left_node_label = left_of_field_access.get_value("label")
            # the right side in filed access is field identifier
            field_identifier = right_of_field_access.get_value("CODE")
            if left_node_label == "IDENTIFIER":
                # case-1: AST left side is Identifier
                code_of_left_node = left_of_field_access.get_value("CODE")
                if code_of_left_node == "this":
                    # this.IDENTIFIER
                    this_frame = file_context.locate_this_frame(
                        pdg.get_file_name(),
                        "".join(self.current_code_info.files[pdg.get_file_name()].get_raw_code()),
                        current_node.get_line_number() - 1,
                        current_node.get_column_number(),
                    )
                    if this_frame:
                        program_behavior.add_object(this_frame.get_this_object())
                        current_node.set_node_full_name((this_frame.get_this_object(), [field_identifier]))

                else:
                    # IDENTIFIER
                    left_identifier = file_context.find_identifier(code_of_left_node, current_node.get_line_number())
                    if left_identifier:
                        left_object = left_identifier.get_ref_object()
                        if left_object:
                            current_node.set_node_full_name((left_object, [field_identifier]))

                            # connect by pdg edge
                            if (
                                left_identifier.get_identifier_type() != GLOBAL_OBJECT
                                and left_identifier.get_identifier_type() != FILE_LEVEL_MODULE
                            ):
                                if not self.has_ddg_line_of_two_nodes(
                                    current_node.get_id(), left_identifier.get_node_id(), pdg
                                ):
                                    program_behavior.add_pdg_edge(
                                        left_identifier.get_node_id(),
                                        current_node.get_id(),
                                        [f"DDG: {left_identifier.get_name()}"],
                                    )
                                else:
                                    program_behavior.add_pdg_edge(
                                        left_identifier.get_node_id(),
                                        current_node.get_id(),
                                        pdg.get_edges()[
                                            (left_identifier.get_node_id(), current_node.get_id())
                                        ].get_attr(),
                                    )
                    else:
                        pass
            else:
                # case-2: AST left side is not Identifier, check if it's a known node in PDG
                if left_of_field_access.get_id() in pdg.get_nodes():
                    left_node_pdg = pdg.get_node(left_of_field_access.get_id())
                    left_node_pdg_full_name = left_node_pdg.get_node_full_name()
                    if left_node_pdg_full_name:
                        # set the full name of the current node
                        left_base_object = left_node_pdg_full_name[0]
                        property_list = list(left_node_pdg_full_name[1])
                        property_list.append(field_identifier)
                        current_node_full_name = (left_base_object, property_list)
                        current_node.set_node_full_name(current_node_full_name)

                    # the filed access in on a non field process node
                    if left_node_pdg.get_name() != "<operator>.fieldAccess":
                        program_behavior.add_pdg_edge(
                            left_of_field_access.get_id(), current_node.get_id(), [f"DDG: {left_node_pdg.get_code()}"]
                        )
                    # the filed access in on a sensitive node
                    if left_node_pdg.is_sensitive_node():
                        program_behavior.add_pdg_edge(
                            left_node_pdg.get_id(), current_node.get_id(), [f"DDG: {left_node_pdg.get_code()}"]
                        )
                else:
                    logger.warning(
                        f"The left side pdg node is not found in field access, Code: {current_node.get_code()}. "
                        f"Node id: {current_node.get_id()}"
                    )

        actual_value = None
        if current_node.get_node_full_name() is not None:
            # resolve the full name
            resolved_full_name = self.resolve_full_name(
                current_node.get_node_full_name()[0], current_node.get_node_full_name()[1]
            )
            # update the full name of the current node
            current_node.set_node_full_name(resolved_full_name)
            actual_value = self.get_actual_value(
                current_node.get_node_full_name()[0], current_node.get_node_full_name()[1]
            )
            if isinstance(actual_value, Object):
                # the actual value is also an object
                program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
            else:
                # not an object, connect from the base object
                program_behavior.add_object_to_pdg_edge(current_node.get_node_full_name()[0], current_node.get_id())

        if self.process_property_api_call(current_node, file_context):
            return

        # sensitive op judgement based on actual value
        sensitive_property_access = sensitive_property_access_finder.query(actual_value)
        if sensitive_property_access:
            logger.debug(
                f"Find sensitive Filed Access, code: {current_node.get_code()}, full name: {sensitive_property_access['full_name']}"
            )
            current_node.set_sensitive_node(True)
            current_node.set_sensitive_dict(sensitive_property_access)

    def process_index_access(self, current_node: PDGNode, pdg: PDG, file_context: FileContext, program_behavior: PBG):
        """
        handle the <operator>.indexAccess
        """
        current_node.set_call_type(INDEX_ACCESS)
        ast = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        if len(ast) < 2:
            logger.warning(f"The AST children size is smaller than 2. node id: {current_node.get_id()}")
        else:
            left_of_index_access = ast[0]
            right_of_index_access = ast[1]
            left_node_label = left_of_index_access.get_value("label")
            index_type = right_of_index_access.get_value("label")
            left_full_name = None
            index_full_name = None
            if index_type == "LITERAL":
                # const value. direct use
                index_full_name = right_of_index_access.get_value("CODE").strip("\"'")
            elif index_type == "IDENTIFIER":
                found_identifier = file_context.find_identifier(
                    right_of_index_access.get_value("CODE"), current_node.get_line_number()
                )
                if found_identifier:
                    ref_object = found_identifier.get_ref_object()
                    index_full_name = None if ref_object is None else ref_object.get_full_name()
                    if (
                        found_identifier.get_identifier_type() != GLOBAL_OBJECT
                        and found_identifier.get_identifier_type() != FILE_LEVEL_MODULE
                    ):
                        if not self.has_ddg_line_of_two_nodes(
                            current_node.get_id(), found_identifier.get_node_id(), pdg
                        ):
                            program_behavior.add_pdg_edge(
                                found_identifier.get_node_id(),
                                current_node.get_id(),
                                [f"DDG: {found_identifier.get_name()}"],
                            )
                        else:
                            program_behavior.add_pdg_edge(
                                found_identifier.get_node_id(),
                                current_node.get_id(),
                                pdg.get_edges()[(found_identifier.get_node_id(), current_node.get_id())].get_attr(),
                            )
            else:
                right_of_index_access_pdg_node = (
                    pdg.get_node(right_of_index_access.get_id())
                    if right_of_index_access.get_id() in pdg.get_nodes()
                    else None
                )
                if right_of_index_access_pdg_node:
                    index_access_pdg_node_full_name = right_of_index_access_pdg_node.get_node_full_name()
                    if index_access_pdg_node_full_name:
                        index_actual_value = self.get_actual_value(
                            index_access_pdg_node_full_name[0], index_access_pdg_node_full_name[1]
                        )
                        if isinstance(index_actual_value, Object):
                            index_full_name = index_actual_value.get_full_name()
                        else:
                            index_full_name = index_actual_value

            # if the index full name is not exist
            if index_full_name is None:
                current_node.set_node_full_name(None)
            else:
                # Determine the type of index subject
                if left_node_label == "IDENTIFIER":
                    # Index subject is Identifier
                    found_identifier = file_context.find_identifier(
                        left_of_index_access.get_value("CODE"), current_node.get_line_number()
                    )
                    if found_identifier:
                        left_ref_object = found_identifier.get_ref_object()
                        current_node.set_node_full_name((left_ref_object, [index_full_name]))

                        # connect by pdg node
                        if (
                            found_identifier.get_identifier_type() != GLOBAL_OBJECT
                            and found_identifier.get_identifier_type() != FILE_LEVEL_MODULE
                        ):
                            if not self.has_ddg_line_of_two_nodes(
                                current_node.get_id(), found_identifier.get_node_id(), pdg
                            ):
                                program_behavior.add_pdg_edge(
                                    found_identifier.get_node_id(),
                                    current_node.get_id(),
                                    [f"DDG: {found_identifier.get_name()}"],
                                )
                            else:
                                program_behavior.add_pdg_edge(
                                    found_identifier.get_node_id(),
                                    current_node.get_id(),
                                    pdg.get_edges()[(found_identifier.get_node_id(), current_node.get_id())].get_attr(),
                                )
                else:
                    # Index subject is non-identifier
                    left_of_index_access_pdg_node = (
                        pdg.get_node(left_of_index_access.get_id())
                        if left_of_index_access.get_id() in pdg.get_nodes()
                        else None
                    )
                    if left_of_index_access_pdg_node:
                        left_full_name = left_of_index_access_pdg_node.get_node_full_name()

                        program_behavior.add_pdg_edge(
                            left_of_index_access_pdg_node.get_id(),
                            current_node.get_id(),
                            [f"DDG: {left_of_index_access_pdg_node.get_code()}"],
                        )

                if left_full_name and index_full_name:
                    left_ref_object = left_full_name[0]
                    property_list = list(left_full_name[1])
                    property_list.append(index_full_name)
                    current_node.set_node_full_name((left_ref_object, property_list))

            left_of_index_access_pdg_node = (
                pdg.get_node(left_of_index_access.get_id())
                if left_of_index_access.get_id() in pdg.get_nodes()
                else None
            )
            if left_of_index_access_pdg_node and left_of_index_access_pdg_node.is_sensitive_node():
                program_behavior.add_pdg_edge(
                    left_of_index_access_pdg_node.get_id(),
                    current_node.get_id(),
                    [f"DDG: {left_of_index_access_pdg_node.get_code()}"],
                )

        actual_value = None
        if current_node.get_node_full_name() is not None:
            resolved_full_name = self.resolve_full_name(
                current_node.get_node_full_name()[0], current_node.get_node_full_name()[1]
            )
            current_node.set_node_full_name(resolved_full_name)
            actual_value = self.get_actual_value(
                current_node.get_node_full_name()[0], current_node.get_node_full_name()[1]
            )
            if isinstance(actual_value, Object):
                program_behavior.add_object_to_pdg_edge(actual_value, current_node.get_id())
            else:
                program_behavior.add_object_to_pdg_edge(current_node.get_node_full_name()[0], current_node.get_id())

        if self.process_property_api_call(current_node, file_context):
            return

        sensitive_property_access = sensitive_property_access_finder.query(actual_value)
        if sensitive_property_access:
            logger.debug(
                f"Find sensitive Index Access, code: {current_node.get_code()}, full name: {sensitive_property_access['full_name']}"
            )
            current_node.set_sensitive_node(True)
            current_node.set_sensitive_dict(sensitive_property_access)

    def process_property_api_call(self, current_node: PDGNode, file_context: FileContext) -> bool:
        """
        Process property access API calls in current_node, update mapping and set node sensitivity based on sensitive queries if found, triggered during dynamic execution
        Returns True if processed, False if not processed.
        """
        if self.current_code_info.api_call_info:
            code = current_node.get_code().strip()
            code_lines = code.splitlines()
            line_offset = len(code_lines) - 1
            col_offset = len(code_lines[-1]) if code_lines else 0
            property_access_call = self.current_code_info.api_call_info.find_api_call(
                "property",
                current_node.get_file_name(),
                current_node.get_line_number() - 1,
                current_node.get_column_number(),
                current_node.get_line_number() - 1 + line_offset,
                current_node.get_column_number() + col_offset,
            )

            if property_access_call:
                self.current_code_info.api_call_to_pdg_node_mapping[property_access_call] = current_node.get_id()
                property_access_full_name = f"{property_access_call.module}.{property_access_call.function}"
                sensitive_property_access = sensitive_property_access_finder.query(property_access_full_name)
                if sensitive_property_access:
                    current_node.set_sensitive_node(True)
                    current_node.set_sensitive_dict(sensitive_property_access)
                    logger.debug(
                        f"Find sensitive Property Access, code: {current_node.get_code()}, full name: {sensitive_property_access['full_name']}"
                    )
                    global_object = file_context.find_global_object(property_access_call.module)
                    current_node.set_node_full_name((global_object, property_access_call.function.split(".")))
                return True
        return False

    def process_new_operation(self, current_node: PDGNode, pdg: PDG, file_context: FileContext, program_behavior: PBG):
        current_node.set_call_type(NEW_CALL)

        # get the param by the ast instead of Joern
        parameters = self.current_code_info.cpg.get_argument_from_joern(current_node.get_id())
        self.connect_ddg_by_param(current_node, parameters, file_context, program_behavior, pdg)

        # find callee
        function_pdg = self.get_callee(current_node)
        is_lambda = function_pdg and len(parameters) > 0 and "<lambda>" in parameters[-1].get_value("TYPE_FULL_NAME")
        if not function_pdg:
            if parameters:
                last_parameter = parameters[-1]
                method_full_name = last_parameter.get_value("TYPE_FULL_NAME")
                if "<lambda>" in method_full_name:
                    function_pdg = self.find_pdg_by_method_full_name(method_full_name.strip())
                    if function_pdg:
                        is_lambda = True

        if function_pdg and not is_lambda:
            # the new operation is caller
            function_behavior = self.process_function_callee(
                current_node, function_pdg, file_context, pdg, program_behavior
            )
            if function_behavior:
                current_node.set_call_type(FUNCTION_CALL)
                merge_pbg(program_behavior, function_behavior)
                current_node.set_behavior_of_call(function_behavior)
            return

        # the new operation is not a function call
        ast = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        if len(ast) < 2:
            logger.warning(f"The AST children size is smaller than 2. node id: {current_node.get_id()}")
        else:
            new_object_node = ast[0]
            label_of_new_object_node = new_object_node.get_value("label")
            if label_of_new_object_node == "IDENTIFIER":
                # New operation subject is Identifier
                found = file_context.find_identifier(new_object_node.get_value("CODE"), current_node.get_line_number())
                if found:
                    current_node.set_node_full_name((found.get_ref_object(), []))
                    if (
                        found.get_identifier_type() != GLOBAL_OBJECT
                        and found.get_identifier_type() != FILE_LEVEL_MODULE
                    ):
                        if not self.has_ddg_line_of_two_nodes(current_node.get_id(), found.get_node_id(), pdg):
                            program_behavior.add_pdg_edge(
                                found.get_node_id(), current_node.get_id(), [f"DDG: {found.get_name()}"]
                            )
                        else:
                            program_behavior.add_pdg_edge(
                                found.get_node_id(),
                                current_node.get_id(),
                                pdg.get_edges()[(found.get_node_id(), current_node.get_id())].get_attr(),
                            )
                else:
                    pass
            else:
                # New operation subject is call, e.g., `new net.Socket()`
                if new_object_node.get_id() in pdg.get_nodes():
                    new_object_pdg = pdg.get_node(new_object_node.get_id())
                    new_object_node_full_name = new_object_pdg.get_node_full_name()
                    if new_object_node_full_name:
                        ref_object = new_object_node_full_name[0]
                        property_list = list(new_object_node_full_name[1])
                        current_node.set_node_full_name((ref_object, property_list))
                    else:
                        current_node.set_node_full_name(None)
                else:
                    logger.warning(
                        f"The new object pdg node is not found in new operation. node id: {current_node.get_id()}"
                    )

        judge_by_full_name = True
        if self.current_code_info.api_call_info:
            if self._handle_api_call_in_new_expression(current_node):
                judge_by_full_name = False
        if judge_by_full_name and current_node.get_node_full_name():
            actual_value = self.get_actual_value(
                current_node.get_node_full_name()[0], current_node.get_node_full_name()[1]
            )
            if isinstance(actual_value, Object):
                actual_value = actual_value.get_full_name()
            if actual_value == "Buffer":
                actual_value = "global.Buffer"
            sensitive_call = sensitive_call_finder.query(actual_value)
            if sensitive_call:
                logger.debug(
                    f"Find sensitive New OP, code: {current_node.get_code()}, full name: {sensitive_call['full_name']}"
                )
                current_node.set_sensitive_node(True)
                current_node.set_sensitive_dict(sensitive_call)
        if is_lambda:
            lambda_behavior = self.process_function_callee(
                current_node, function_pdg, file_context, pdg, program_behavior, is_lambda=True
            )
            if lambda_behavior:
                merge_pbg(program_behavior, lambda_behavior)
                current_node.set_behavior_of_call(lambda_behavior)

    def _handle_api_call_in_new_expression(self, current_node: PDGNode):
        """
        Handle API calls that appear in new expressions
        """
        code = current_node.get_code().strip()
        code_lines = code.splitlines()
        line_offset = len(code_lines) - 1
        col_offset = len(code_lines[-1]) if code_lines else 0
        api_call = self.current_code_info.api_call_info.find_api_call(
            "function",
            current_node.get_file_name(),
            current_node.get_line_number() - 1,
            current_node.get_column_number(),
            current_node.get_line_number() - 1 + line_offset,
            current_node.get_column_number() + col_offset,
        )
        if api_call is None:
            return False

        self.current_code_info.api_call_to_pdg_node_mapping[api_call] = current_node.get_id()
        api_call_full_name = f"{api_call.module}.{api_call.function}"
        sensitive_call = sensitive_call_finder.query(api_call_full_name)
        if sensitive_call:
            logger.debug(f"Find sensitive New OP, code: {code}, full_name: {sensitive_call['full_name']}")
            current_node.set_sensitive_node(True)
            current_node.set_sensitive_dict(sensitive_call)
        return True

    def process_iterator(self, current_node: PDGNode, pdg: PDG, file_context: FileContext, program_behavior: PBG):
        # create a dummy object
        iterator_object = Object(
            name=f"{current_node.get_name()}-{current_node.get_id()}",
            object_type=OBJECT,
            source_pdg=current_node.get_source_pdg(),
        )
        file_context.add_object(iterator_object)
        current_node.set_node_full_name((iterator_object, []))
        ast = self.current_code_info.cpg.get_children_ast(current_node.get_id())
        if len(ast) > 0:
            first_ast = ast[0]
            first_ast_label = first_ast.get_value("label")
            if first_ast_label == "IDENTIFIER":
                found_identifier = file_context.find_identifier(
                    first_ast.get_value("CODE"), current_node.get_line_number()
                )
                if found_identifier:
                    ref_object = found_identifier.get_ref_object()
                    program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())
            else:
                if first_ast.get_id() in pdg.get_nodes():
                    program_behavior.add_pdg_edge(first_ast.get_id(), current_node.get_id(), ["DDG"])

    def process_require(self, current_node: PDGNode, file_context: FileContext, program_behavior: PBG):
        """
        check the `require` and base on the call graph to locate
        """
        require_code = current_node.get_code()
        file = current_node.get_file_name()
        start_line = current_node.get_line_number() - 1
        start_column = current_node.get_column_number()
        logger.info(
            f"Require Call of code: {require_code}, in file: {file}, start line: {start_line}, node id: {current_node.get_id()}"
        )
        if (
            file in self.current_code_info.call_expression_dict
            and (start_line, start_column) in self.current_code_info.call_expression_dict[file]
        ):
            # locate the call expression
            end_line, end_column = self.current_code_info.call_expression_dict[file][(start_line, start_column)]
            callee = self.current_code_info.call_graph.get_callee(file, start_line, start_column, end_line, end_column)
            if callee is not None:
                logger.info(
                    f"Find the callee in require :{require_code} in file: {current_node.get_file_name()}, line: {current_node.get_line_number()}"
                )
                file_of_callee = callee.file

                # go into the module being required and analyze it
                pdg_of_callee = self.find_pdg_by_file(file_of_callee)
                if pdg_of_callee is None:
                    logger.warning(f"Can not find the pdg of the required module: {file_of_callee} of {require_code}")
                    logger.info("Need Dynamic of unknown require")
                    self.need_dynamic = True
                    return
                else:
                    if pdg_of_callee not in self.loaded_history:
                        self.loaded_history.add(pdg_of_callee)

                        new_program_behavior = PBG(
                            self.current_code_info.cpg,
                            self.current_code_info.pdg_dict,
                            self.current_code_info.formatted_package_dir,
                            self.package_name,
                        )
                        program_behavior_of_require = self.gen_behavior(
                            file_of_callee, pdg_of_callee, "implicit main", new_program_behavior, None
                        )
                        program_behavior.add_pdg_edge(
                            current_node.get_id(), program_behavior_of_require.get_entrance_node().get_id(), ["CFG"]
                        )

                        # merge the behavior of the required module into the current behavior
                        merge_pbg(program_behavior, program_behavior_of_require)

        # get the argument of the `require` or the full name is `require`
        parameters = self.current_code_info.cpg.get_argument_from_joern(current_node.get_id())
        if parameters:
            if len(parameters) == 1 and parameters[0].get_value("label") == "LITERAL":
                argument_str = parameters[0].get_value("CODE").strip("\"'")
                pattern = r"node:(.*)"
                match = re.search(pattern, argument_str)
                if match:
                    import_module = match.group(1)
                else:
                    import_module = argument_str
                logger.info(
                    f"`require` Call with argument of {import_module} in file: {current_node.get_file_name()}, line: {current_node.get_line_number()}"
                )
                is_core_module = self.is_core_module(import_module)
                if is_core_module:
                    core_module_object = file_context.get_core_module_object(import_module)
                    current_node.set_node_full_name((core_module_object, []))
            else:
                logger.info(
                    f"The argument of the require is not a string: {require_code} in file: {current_node.get_file_name()}, line: {current_node.get_line_number()}"
                )
                logger.debug("Need Dynamic")
                self.need_dynamic = True

    def function_call(
        self, current_node: PDGNode, pdg: PDG, call_name: str, file_context: FileContext, program_behavior: PBG
    ):
        """
        handle the call expression
        find the callee based on the call graph
        """

        current_node.set_call_type(NORMAL_CALL)

        parameters = self.current_code_info.cpg.get_argument_from_joern(current_node.get_id())
        self.connect_ddg_by_param(current_node, parameters, file_context, program_behavior, pdg)

        function_pdg = self.get_callee(current_node)

        # get the lambda pdg by Joern
        lambda_pdg = None
        is_lambda = False
        if (
            len(parameters) > 0
            and parameters[-1].get_value("TYPE_FULL_NAME")
            and "<lambda>" in parameters[-1].get_value("TYPE_FULL_NAME")
        ):
            last_parameter = parameters[-1]
            method_full_name = last_parameter.get_value("METHOD_FULL_NAME")
            if method_full_name:
                lambda_pdg = self.find_pdg_by_method_full_name(method_full_name.strip())

        if function_pdg:
            # When no lambda is detected, process the function callee normally.
            if not lambda_pdg:
                if self.current_code_info.api_call_info:
                    self._handle_api_call(current_node, pdg, file_context, program_behavior, is_lambda, None)
                function_behavior = self.process_function_callee(
                    current_node, function_pdg, file_context, pdg, program_behavior
                )
                if function_behavior:
                    current_node.set_call_type(FUNCTION_CALL)
                    merge_pbg(program_behavior, function_behavior)
                    current_node.set_behavior_of_call(function_behavior)
                return

            # A lambda function is detected.
            is_lambda = True
            self.remove_some_pdg_edge(current_node, pdg)

            # Determine the target PDG: if the lambda PDG equals the function PDG, use it;
            # otherwise, use the lambda PDG.
            target_pdg = function_pdg if lambda_pdg == function_pdg else lambda_pdg

            # Attempt to handle the API call if in dynamic analysis.
            if self.current_code_info.api_call_info:
                if self._handle_api_call(current_node, pdg, file_context, program_behavior, is_lambda, target_pdg):
                    return

            # Handle the builtin or missing call.
            self._handle_builtin_or_missing_call(
                current_node, pdg, file_context, program_behavior, parameters, is_lambda, target_pdg, call_name
            )

            # Handle any special processing if the call name is 'then'.
            self._handle_then_branch(current_node, pdg, program_behavior, call_name)
        else:
            # When there is no function PDG.
            self.remove_some_pdg_edge(current_node, pdg)

            if lambda_pdg:
                is_lambda = True
                target_pdg = lambda_pdg
            else:
                is_lambda = False
                target_pdg = None
            if self.current_code_info.api_call_info:
                if self._handle_api_call(current_node, pdg, file_context, program_behavior, is_lambda, target_pdg):
                    return

            self._handle_builtin_or_missing_call(
                current_node, pdg, file_context, program_behavior, parameters, is_lambda, target_pdg, call_name
            )
            self._handle_then_branch(current_node, pdg, program_behavior, call_name)

    def _handle_then_branch(self, current_node, pdg, program_behavior, call_name):
        """
        Adds a PDG edge with the 'DDG: then' label if the call_name is 'then'
        and the first AST node is part of the PDG.
        """
        if call_name == "then":
            first_ast_node = self.current_code_info.cpg.get_first_ast_node_in_call(current_node.get_id())
            if first_ast_node and first_ast_node.get_id() in pdg.get_nodes():
                program_behavior.add_pdg_edge(first_ast_node.get_id(), current_node.get_id(), ["CFG", "DDG: then"])

    def remove_some_pdg_edge(self, current_node, pdg):
        # remove useless pdg edge
        top_argument = self.current_code_info.cpg.get_argument_from_joern_index_less_than_one(current_node.get_id())
        arg_name_list = []
        for arg in top_argument:
            arg_name_list.append(f"DDG: {arg.get_value('NAME')}")
        out_edges = pdg.get_out_edges()
        current_node_out_edges = out_edges.get(current_node.get_id(), [])
        for edge_id in current_node_out_edges:
            edge = pdg.get_edges()[(current_node.get_id(), edge_id)]
            attr_list = edge.get_attr()
            for i, attr in enumerate(attr_list):
                if attr in arg_name_list:
                    attr_list[i] = attr.replace("DDG: ", "REMOVE: ", 1)
            # Update the edge's attributes with the modified list
            edge.change_attr(attr_list)

    def _handle_builtin_or_missing_call(
        self, current_node, pdg, file_context, program_behavior, parameters, is_lambda, function_pdg, call_name
    ):
        """
        Handle built-in module calls or missing call edges:
        - Attempt to parse the full name of the call (node_full_name) from PDG or source code
        """
        code = current_node.get_code()
        first_ast_node = self.current_code_info.cpg.get_first_ast_node_in_call(current_node.get_id())
        node_full_name = None
        first_ast_pdg_node = None

        if first_ast_node and first_ast_node.get_id() in pdg.get_nodes():
            first_ast_pdg_node = pdg.get_node(first_ast_node.get_id())
            if first_ast_pdg_node.get_node_type() == "IDENTIFIER":
                found_identifier = file_context.find_identifier(
                    first_ast_pdg_node.get_name(), current_node.get_line_number()
                )
                if found_identifier:
                    node_full_name = (found_identifier.get_ref_object(), [])
            else:
                pdg_full_name = first_ast_pdg_node.get_node_full_name()
                if pdg_full_name:
                    node_full_name = (pdg_full_name[0], list(pdg_full_name[1]))
            current_node.set_node_full_name(node_full_name)
            program_behavior.add_pdg_edge(
                first_ast_pdg_node.get_id(), current_node.get_id(), [f"DDG: {first_ast_pdg_node.get_code()}"]
            )
        else:
            # the ast of the call is not at the pdg
            parser = ASTParser(code.strip())
            single_identifier = parser.get_identifier_in_call_expression()
            if single_identifier:
                found_identifier = file_context.find_identifier(single_identifier, current_node.get_line_number())
                if found_identifier:
                    ref_object = found_identifier.get_ref_object()
                    current_node.set_node_full_name((ref_object, []))
                    program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())
            else:
                # If no single identifier found, then check for identifier and property in call expression
                identifier, property_identifier = parser.get_identifier_property_in_call_expression()
                if identifier and property_identifier:
                    ref_object = file_context.find_global_object(identifier)
                    if ref_object:
                        node_full_name = (ref_object, [property_identifier])
                        current_node.set_node_full_name(node_full_name)
                else:
                    pass

        # If unable to determine the full name of the call, mark as needing dynamic analysis
        if current_node.get_node_full_name() is None:
            if call_name is None or not is_instance_method(call_name):
                self.need_dynamic = True
                logger.debug(
                    f"The full name of the call: {code} is None, need dynamic. "
                    f"Node id: {current_node.get_id()}, pdg: {pdg.pdg_path}"
                )
        else:
            actual_value = self.get_actual_value(
                current_node.get_node_full_name()[0], current_node.get_node_full_name()[1]
            )
            if isinstance(actual_value, Object):
                actual_value = actual_value.get_full_name()
            else:
                if (
                    parameters
                    and actual_value is not None
                    and (
                        actual_value.endswith("push")
                        or actual_value.endswith("unshift")
                        or actual_value.endswith("splice")
                    )
                ):
                    program_behavior.add_pdg_to_object_data_edge(current_node.get_id(), node_full_name[0])

            if actual_value is None:
                if call_name is not None and is_instance_method(call_name):
                    pass
                else:
                    self.need_dynamic = True
                    logger.debug(
                        f"The full name of the call: {code} is None, need dynamic. "
                        f"Node id: {current_node.get_id()}, pdg: {pdg.pdg_path}"
                    )
            else:
                if actual_value == "require":
                    self.process_require(current_node, file_context, program_behavior)
                elif actual_value == "eval":
                    logger.debug(
                        f"Find `eval` Call, need dynamic. Node id: {current_node.get_id()}, pdg: {pdg.pdg_path}"
                    )
                    self.need_dynamic = True
                    sensitive_call = sensitive_call_finder.query("global.eval")
                    if sensitive_call:
                        logger.debug(f"Find sensitive Call, code: {code}, full name: {sensitive_call['full_name']}")
                        current_node.set_sensitive_node(True)
                        current_node.set_sensitive_dict(sensitive_call)
                elif actual_value == "fetch":
                    sensitive_call = sensitive_call_finder.query("global.fetch")
                    if sensitive_call:
                        logger.debug(f"Find sensitive Call, code: {code}, full name: global.fetch")
                        current_node.set_sensitive_node(True)
                        current_node.set_sensitive_dict(sensitive_call)
                elif actual_value == "Function":
                    sensitive_call = sensitive_call_finder.query("global.Function")
                    if sensitive_call:
                        logger.debug(f"Find sensitive Call, code: {code}, full name: {sensitive_call['full_name']}")
                        current_node.set_sensitive_node(True)
                        current_node.set_sensitive_dict(sensitive_call)
                elif actual_value == "setTimeout":
                    function_behavior = self.handle_set_time_out(
                        current_node, parameters, file_context, program_behavior, pdg
                    )
                    if function_behavior:
                        merge_pbg(program_behavior, function_behavior)
                else:
                    sensitive_call = sensitive_call_finder.query(actual_value)
                    if sensitive_call:
                        if (
                            sensitive_call["full_name"] == "http.request.end"
                            or sensitive_call["full_name"] == "https.request.end"
                        ) and len(parameters) == 0:
                            pass
                        else:
                            logger.debug(f"Find sensitive Call, code: {code}, full name: {sensitive_call['full_name']}")
                            current_node.set_sensitive_node(True)
                            current_node.set_sensitive_dict(sensitive_call)
                        if first_ast_pdg_node and first_ast_pdg_node.is_sensitive_node():
                            first_ast_pdg_node.set_sensitive_node(False)

                        if sensitive_call["domain"] == "Process":
                            # like spawn and fork
                            self.handle_subprocess(
                                current_node, program_behavior, sensitive_call["full_name"], parameters, None
                            )
                        if sensitive_call["domain"] == "File":
                            # like readFile and writeFile
                            self.handle_file_op_in_static(current_node, sensitive_call["full_name"], parameters)

        if is_lambda:
            lambda_behavior = self.process_function_callee(
                current_node, function_pdg, file_context, pdg, program_behavior, is_lambda=True
            )
            if lambda_behavior:
                merge_pbg(program_behavior, lambda_behavior)
                current_node.set_behavior_of_call(lambda_behavior)

    @staticmethod
    def calculate_end_position(code_snippet: str, start_line: int, start_column: int):
        lines = code_snippet.splitlines()
        if not lines:
            return start_line, start_column
        if len(lines) == 1:
            end_line = start_line
            end_column = start_column + len(lines[0])
        else:
            end_line = start_line + len(lines) - 1
            end_column = len(lines[-1])
        return end_line, end_column

    def handle_set_time_out(
        self,
        current_node: PDGNode,
        parameters: list[CPGNode],
        file_context: FileContext,
        program_behavior: PBG,
        pdg: PDG,
    ):
        if parameters and len(parameters) > 1:
            first_parameter = parameters[0]
        else:
            return
        parameter_label = first_parameter.get_value("label")
        function_behavior = None
        if parameter_label == "METHOD_REF":
            method_full_name = first_parameter.get_value("METHOD_FULL_NAME")
            function_pdg = self.find_pdg_by_method_full_name(method_full_name.strip())
            if function_pdg:
                if file_context.function_in_stack(f"{function_pdg.get_full_name()}"):
                    logger.info(f"{function_pdg.get_name()} is in loop")
                    return
                file_context.add_stack(f"{function_pdg.get_full_name().strip()}")
                self.current_code_info.pdg_analyzed[function_pdg.get_first_node_id()] = True
                function_call_entrance_id = function_pdg.get_first_node_id()
                program_behavior.add_pdg_edge(current_node.get_id(), function_call_entrance_id, ["DDG", "CFG"])
                new_program_behavior = PBG(
                    self.current_code_info.cpg,
                    self.current_code_info.pdg_dict,
                    self.current_code_info.formatted_package_dir,
                    self.package_name,
                )
                # check if there exist parameters
                function_parameters = parameters[2:]
                if function_parameters:
                    parameter_send_list = self.get_parameter_send_list(
                        function_parameters, current_node, file_context, pdg
                    )
                    function_behavior = self.gen_behavior(
                        function_pdg.get_file_name(),
                        function_pdg,
                        "function",
                        new_program_behavior,
                        parameter_list=parameter_send_list,
                    )
                else:
                    function_behavior = self.gen_behavior(
                        function_pdg.get_file_name(),
                        function_pdg,
                        "function",
                        new_program_behavior,
                        parameter_list=None,
                    )
                file_context.delete_last_stack()

        return function_behavior

    def _handle_api_call(self, current_node, pdg, file_context, program_behavior, is_lambda, function_pdg) -> bool:
        """
        Handle API call information. Returns True to terminate subsequent processing if successful.
        """
        code = current_node.get_code().strip()
        end_line, end_column = self.calculate_end_position(
            code, current_node.get_line_number(), current_node.get_column_number()
        )

        api_call = self.current_code_info.api_call_info.find_api_call(
            "function",
            current_node.get_file_name(),
            current_node.get_line_number() - 1,
            current_node.get_column_number(),
            end_line - 1,
            end_column,
        )
        if api_call is None:
            return False

        self.current_code_info.api_call_to_pdg_node_mapping[api_call] = current_node.get_id()
        api_call_full_name = f"{api_call.module}.{api_call.function}"
        sensitive_call = sensitive_call_finder.query(api_call_full_name)
        if sensitive_call:
            current_node.set_sensitive_node(True)
            current_node.set_sensitive_dict(sensitive_call)
            logger.debug(f"Find sensitive Call, code: {code}, full_name: {sensitive_call['full_name']}")
            first_ast_node = self.current_code_info.cpg.get_first_ast_node_in_call(current_node.get_id())
            if first_ast_node and first_ast_node.get_id() in pdg.get_nodes():
                pdg.get_node(first_ast_node.get_id()).set_sensitive_node(False)
                program_behavior.add_pdg_edge(first_ast_node.get_id(), current_node.get_id(), ["DDG"])

            if sensitive_call["domain"] == "Process":
                # like spawn and fork
                self.handle_subprocess(
                    current_node, program_behavior, sensitive_call["full_name"], None, api_call.arguments
                )
            if sensitive_call["domain"] == "File":
                self.handle_file_op_in_dynamic(
                    current_node, sensitive_call["full_name"], api_call.arguments, api_call.result
                )

            # assign the full name
            self.assign_full_name(api_call_full_name, current_node, file_context)

        if is_lambda:
            lambda_behavior = self.process_function_callee(
                current_node, function_pdg, file_context, pdg, program_behavior, is_lambda=True
            )
            if lambda_behavior:
                merge_pbg(program_behavior, lambda_behavior)
                current_node.set_behavior_of_call(lambda_behavior)
        return True

    @staticmethod
    def assign_full_name(api_call_full_name: str, current_node: PDGNode, file_context: FileContext):
        split_res = api_call_full_name.split(".")
        module_name = split_res[0]
        if module_name == "global":
            global_object = file_context.find_global_object(split_res[1])
            if global_object:
                current_node.set_node_full_name((global_object, []))
        else:
            if module_name == "Buffer":
                ref_object = file_context.find_global_object("Buffer")
            else:
                ref_object = file_context.get_core_module_object(module_name)
            if ref_object:
                current_node.set_node_full_name((ref_object, split_res[1:]))

    def handle_subprocess(
        self,
        current_node: PDGNode,
        program_behavior: PBG,
        full_name: str,
        parameters: list[CPGNode] | None,
        str_parameters: str | None,
    ):
        """
        handle the subprocess for calling js file or other types
        """
        JS_EXTENSIONS = {".js", ".mjs", ".cjs"}

        def is_js_file(_file_path: str) -> bool:
            _, ext = os.path.splitext(_file_path)
            return ext.lower() in JS_EXTENSIONS

        is_file = False
        file_name = None

        if parameters:
            # static analysis
            parameter_str_list = self.get_str_from_parameter_list(parameters)
            if parameter_str_list and len(parameter_str_list) > 0 and None not in parameter_str_list:
                command_str = " ".join(parameter_str_list)
            else:
                command_str = None
        elif str_parameters:
            # dynamic analysis
            if full_name in ["child_process.spawn", "child_process.spawnSync"]:
                file, args = self.get_file_args_in_subprocess(str_parameters)
                if file and args:
                    command_str = file
                    if isinstance(args, dict):
                        for key, value in args.items():
                            if key.lower() in ("encoding", "shell"):
                                continue
                            command_str += " " + str(value)
                    elif isinstance(args, (list, tuple)):
                        for arg in args:
                            command_str += " " + str(arg)
                    else:
                        command_str += " " + str(args)
                else:
                    command_str = None
            else:
                command_str = str_parameters
        else:
            return

        if command_str is None:
            if "pipe" in full_name:
                return
            else:
                logger.debug("The Command String is None, Need Dynamic")
                self.need_dynamic = True
                return

        # these api can be used for run js scripts
        if full_name in [
            "child_process.exec",
            "child_process.execSync",
            "child_process.spawn",
            "child_process.spawnSync",
            "child_process.fork",
        ]:
            try:
                tokens = shlex.split(command_str.strip())
                if tokens:
                    if full_name == "child_process.fork":
                        is_file = is_js_file(tokens[0])
                        file_name = tokens[0]
                    else:
                        if tokens[0] == "/usr/lib/node_modules/@cs-au-dk/jelly/bin/node":
                            pattern = re.compile(r"(\S+\.js)(?!.*\.js)")
                            match = pattern.search(command_str)
                            if match:
                                file_name = match.group(1)
                                is_file = is_js_file(file_name)
                        else:
                            base = os.path.basename(tokens[0]).lower()
                            if base in {"node", "node.exe"}:
                                if len(tokens) >= 2:
                                    is_file = is_js_file(tokens[1])
                                    file_name = tokens[1]
            except Exception as e:
                logger.error(f"{e}")
                is_file = False

        if is_file:
            # find the pdg of the file
            file_path = os.path.join("package", file_name)
            if file_path in self.current_code_info.files and file_path != current_node.get_file_name():
                pdg_of_script = self.find_pdg_by_file(file_path)

                if pdg_of_script:
                    subprocess_behavior = PBG(
                        self.current_code_info.cpg,
                        self.current_code_info.pdg_dict,
                        self.current_code_info.formatted_package_dir,
                        self.package_name,
                    )
                    program_behavior_of_subprocess = self.gen_behavior(
                        pdg_of_script.get_file_name(), pdg_of_script, "implicit main", subprocess_behavior, None
                    )
                    if program_behavior_of_subprocess:
                        program_behavior.add_pdg_edge(
                            current_node.get_id(), program_behavior_of_subprocess.get_entrance_node().get_id(), ["CFG"]
                        )

                        # merge the behavior of the required module into the current behavior
                        merge_pbg(program_behavior, program_behavior_of_subprocess)
                else:
                    self.need_dynamic = True
                    logger.info("Can not find the pdg of target file in Process Execution")
                return
        else:
            if command_str:
                # analyze the parameter of the command
                if full_name in ["child_process.execFile", "child_process.execFileSync"]:
                    degree = llm.llm_execute_file_interpret(command_str)
                else:
                    degree = llm.llm_shell_command_interpret(command_str)
                current_node.set_sensitive_degree(degree)
        return

    @staticmethod
    def get_file_args_in_subprocess(json_string: str):
        try:
            data = json.loads(json_string)
            file = data.get("file")
            args = data.get("args")
            return file, args
        except json.JSONDecodeError as error:
            logger.error(f"JSON Decode Error: {error} of string: {json_string}")
            return None, None

    def handle_file_op_in_static(self, current_node: PDGNode, full_name: str, parameters: list[CPGNode] | None):
        """handle file operation based on the full name"""
        parameter_str_list = None
        if parameters:
            parameter_str_list = self.get_str_from_parameter_list(parameters)

        if not (parameter_str_list and len(parameter_str_list) > 0):
            return

        # File Stream, Search File, Open File, Remove File
        # Analyze the path
        if full_name in [
            "fs.createReadStream",
            "fs.createWriteStream",
            "fs.open",
            "fs/promises.open",
            "fs.openSync",
            "fs.readLink",
            "fs/promises.readlink",
            "fs.readlinkSync",
        ]:
            first_parameter = parameter_str_list[0]
            if first_parameter:
                first_parameter_str = str(first_parameter)
                if sensitive_degree_helper.is_sensitive_path(first_parameter_str):
                    current_node.set_sensitive_degree(1.0)
                else:
                    degree = llm.llm_path_sensitivity_interpret(first_parameter_str)
                    current_node.set_sensitive_degree(degree)
            else:
                self.need_dynamic = True
                logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")
        if full_name in ["fs.readdir", "fs.readdirSync", "fs/promises.readdir"]:
            first_parameter = parameter_str_list[0]
            if first_parameter:
                first_parameter_str = str(first_parameter)
                if sensitive_degree_helper.is_sensitive_path(first_parameter_str):
                    current_node.set_sensitive_degree(1.0)
                else:
                    degree = llm.llm_dir_sensitivity_interpret(first_parameter_str)
                    current_node.set_sensitive_degree(degree)
            else:
                self.need_dynamic = True
                logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")
        elif full_name in ["fs.glob", "fs.globSync", "fs/promises.glob"]:
            first_parameter = parameter_str_list[0]
            if first_parameter:
                first_parameter_str = str(first_parameter)
                degree = llm.llm_file_pattern_sensitivity_interpret(first_parameter_str)
                current_node.set_sensitive_degree(degree)
            else:
                self.need_dynamic = True
                logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")
        elif full_name in ["fs.rm", "fs/promises.rm", "fs.rmSync", "fs.unlink", "fs.unlinkSync", "fs/promises.unlink"]:
            first_parameter = parameter_str_list[0]
            if first_parameter:
                first_parameter_str = str(first_parameter)
                if sensitive_degree_helper.is_sensitive_path(first_parameter_str):
                    current_node.set_sensitive_degree(1.0)
                else:
                    degree = llm.llm_rm_files_sensitivity_interpret(first_parameter_str)
                    current_node.set_sensitive_degree(degree)
            else:
                self.need_dynamic = True
                logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")

        elif full_name in ["fs.readFile", "fs.readFileSync", "fs/promises.readFile"]:
            self.need_dynamic = True
            logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")

        elif full_name in [
            "fs.appendFile",
            "fs.appendFileSync",
            "fs/promises.appendFile",
            "fs.writeFile",
            "fs.writeFileSync",
            "fs/promises.writeFile",
        ]:
            if len(parameter_str_list) > 1 and parameter_str_list[0] and parameter_str_list[1]:
                degree = llm.llm_file_writing_sensitivity_interpret(parameter_str_list[0], parameter_str_list[1])
                current_node.set_sensitive_degree(degree)
            else:
                self.need_dynamic = True
                logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")
        elif full_name in ["fs.exists", "fs.existsSync"]:
            first_parameter = parameter_str_list[0]
            if first_parameter:
                first_parameter_str = str(first_parameter)
                if sensitive_degree_helper.is_sensitive_path(first_parameter_str):
                    current_node.set_sensitive_degree(1.0)
                else:
                    degree = llm.llm_path_sensitivity_interpret(first_parameter_str)
                    current_node.set_sensitive_degree(degree)
            else:
                self.need_dynamic = True
                logger.debug(f"Need Dynamic in File Operation of code: {current_node.get_code()}")

    @staticmethod
    def handle_file_op_in_dynamic(current_node: PDGNode, full_name: str, parameters: str | None, return_value):
        if not parameters:
            return
        result = str(return_value)

        current_node.set_sensitive_degree(
            sensitive_degree_helper.get_file_sensitivity_degree(full_name, parameters, result)
        )

    @staticmethod
    def handle_path_op_in_dynamic(current_node: PDGNode, full_name: str, return_value):
        if not return_value:
            return
        return_value = str(return_value)
        if full_name in ["path.format", "path.join", "path.normalize", "path.resolve"]:
            if sensitive_degree_helper.is_sensitive_path(return_value):
                current_node.set_sensitive_degree(1.0)
            else:
                degree = llm.llm_path_sensitivity_interpret(return_value)
                current_node.set_sensitive_degree(degree)

    def process_function_callee(
        self,
        current_node: PDGNode,
        function_pdg: PDG,
        file_context: FileContext,
        pdg: PDG,
        program_behavior: PBG,
        is_lambda=False,
    ):
        if file_context.function_in_stack(f"{function_pdg.get_full_name()}"):
            logger.info(f"{function_pdg.get_name()} is in loop")
            return None
        file_context.add_stack(f"{function_pdg.get_full_name().strip()}")
        self.current_code_info.pdg_analyzed[function_pdg.get_first_node_id()] = True

        # Get the first node of function call
        function_call_entrance_id = function_pdg.get_first_node_id()

        # Connection type is DDG
        program_behavior.add_pdg_edge(current_node.get_id(), function_call_entrance_id, ["DDG", "CFG"])

        new_program_behavior = PBG(
            self.current_code_info.cpg,
            self.current_code_info.pdg_dict,
            self.current_code_info.formatted_package_dir,
            self.package_name,
        )
        if not is_lambda:
            # get the argument list by Joern
            parameter_list = self.current_code_info.cpg.get_argument_from_joern(current_node.get_id())
            parameter_send_list = self.get_parameter_send_list(parameter_list, current_node, file_context, pdg)

            function_call_result = self.gen_behavior(
                function_pdg.get_file_name(),
                function_pdg,
                "function",
                new_program_behavior,
                parameter_list=parameter_send_list,
            )
        else:
            function_call_result = self.gen_behavior(
                function_pdg.get_file_name(), function_pdg, "function", new_program_behavior, parameter_list=None
            )
        file_context.delete_last_stack()
        return function_call_result

    @staticmethod
    def get_parameter_send_list(
        parameter_list: list[CPGNode], current_node: PDGNode, file_context: FileContext, pdg: PDG
    ):
        parameter_send_list = []
        if parameter_list:
            for parameter_node in parameter_list:
                label_of_parameter = parameter_node.get_value("label")
                if label_of_parameter == "IDENTIFIER":
                    found_identifier = file_context.find_identifier(
                        parameter_node.get_value("CODE"), current_node.get_line_number()
                    )
                    if found_identifier:
                        bind_object = found_identifier.get_ref_object()
                        if bind_object:
                            parameter_send_list.append(bind_object)
                        else:
                            parameter_send_list.append(None)
                    else:
                        parameter_send_list.append(None)
                elif label_of_parameter == "LITERAL":
                    if parameter_node.get_value("TYPE_FULL_NAME") == "__ecma.String":
                        array_object = file_context.find_global_object("Array")
                        parameter_send_list.append((array_object, []))
                    else:
                        parameter_send_list.append(None)
                else:
                    parameter_pdg_node = (
                        pdg.get_node(parameter_node.get_id()) if parameter_node.get_id() in pdg.get_nodes() else None
                    )
                    if parameter_pdg_node:
                        node_full_name = parameter_pdg_node.get_node_full_name()
                        parameter_send_list.append(node_full_name)
                    else:
                        parameter_send_list.append(None)
        return parameter_send_list

    def get_function_pdg_by_name_file(self, file_name: str, function_name: str):
        for key, function_pdg in self.current_code_info.pdg_dict.items():
            if function_pdg.get_name() == function_name and function_pdg.get_file_name() == file_name:
                return function_pdg
        return None

    def has_ddg_line_of_two_nodes(self, current_node_id: int, identifier_id: int, pdg: PDG):
        if (identifier_id, current_node_id) in pdg.get_edges() and self.get_type_of_edge(
            pdg.get_edges()[(identifier_id, current_node_id)]
        ) == "DDG":
            return True
        return False

    def get_callee(self, current_node):
        """
        find the callee of current function call
        """
        call_expression_code = current_node.get_code()
        file = current_node.get_file_name()
        start_line = current_node.get_line_number() - 1
        start_column = current_node.get_column_number()
        if (
            file in self.current_code_info.call_expression_dict
            and (start_line, start_column) in self.current_code_info.call_expression_dict[file]
        ):
            # locate the call expression
            end_line, end_column = self.current_code_info.call_expression_dict[file][(start_line, start_column)]
            callee = self.current_code_info.call_graph.get_callee(file, start_line, start_column, end_line, end_column)
            if callee is not None:
                logger.info(f"Find the callee of call expression: {call_expression_code}")
                file_of_callee = callee.file
                line_number_of_callee = callee.start_line + 1
                column_number_of_callee = callee.start_column
                end_line_number_of_callee = callee.end_line + 1
                enc_column_number_of_callee = callee.end_column
                pdg_of_callee = self.find_pdg_by_file_and_loc(
                    file_of_callee,
                    line_number_of_callee,
                    column_number_of_callee,
                    end_line_number_of_callee,
                    enc_column_number_of_callee,
                )
                return pdg_of_callee
        return None

    def lambda_function(self, current_node: PDGNode, depth_tree: FileContext, lambda_pdg: PDG, program_behavior: PBG):
        """
        Trigger the anonymous function
        """
        self.current_code_info.pdg_analyzed[lambda_pdg.get_first_node_id()] = True
        depth_tree.add_stack(lambda_pdg.get_full_name().strip())

        # using the ddg to connect the lambda function to the caller
        program_behavior.add_pdg_edge(current_node.get_id(), lambda_pdg.get_first_node_id(), ["DDG", "CFG"])
        new_program_behavior = PBG(
            self.current_code_info.cpg,
            self.current_code_info.pdg_dict,
            self.current_code_info.formatted_package_dir,
            self.package_name,
        )
        anonymous_call_result = self.gen_behavior(
            current_node.get_file_name(), lambda_pdg, "lambda", new_program_behavior, parameter_list=None
        )
        depth_tree.delete_last_stack()
        merge_pbg(program_behavior, anonymous_call_result)

    def connect_ddg_by_param(
        self,
        current_node: PDGNode,
        parameters: list[CPGNode],
        file_context: FileContext,
        program_behavior: PBG,
        pdg: PDG,
    ):
        # analyse the param to get extra data flow
        if len(parameters) != 0:
            for parameter in parameters:
                if parameter.get_id() in pdg.get_nodes():
                    if not self.has_ddg_line_of_two_nodes(current_node.get_id(), parameter.get_id(), pdg):
                        program_behavior.add_pdg_edge(
                            parameter.get_id(), current_node.get_id(), [f"DDG: {parameter.get_value('CODE')}"]
                        )
                if parameter.get_value("label") == "IDENTIFIER":
                    if parameter.get_value("CODE") != "this":
                        param_found = file_context.find_identifier(
                            parameter.get_value("CODE"), current_node.get_line_number()
                        )
                        if param_found:
                            if (
                                param_found.get_identifier_type() != GLOBAL_OBJECT
                                and param_found.get_identifier_type() != FILE_LEVEL_MODULE
                            ):
                                if not self.has_ddg_line_of_two_nodes(
                                    current_node.get_id(), param_found.get_node_id(), pdg
                                ):
                                    program_behavior.add_pdg_edge(
                                        param_found.get_node_id(),
                                        current_node.get_id(),
                                        [f"DDG: {param_found.get_name()}"],
                                    )
                                    logger.info(
                                        f"Find new data dependency by param: {parameter} to {param_found.get_name()} "
                                        f"of line: {param_found.get_line_number()}"
                                    )
                                else:
                                    attr = pdg.get_edges()[param_found.get_node_id(), current_node.get_id()].get_attr()
                                    program_behavior.add_pdg_edge(
                                        param_found.get_node_id(), current_node.get_id(), attr
                                    )
                            ref_object = param_found.get_ref_object()
                            program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())
                elif parameter.get_value("label") == "BLOCK":
                    self.find_pdg_edge_in_block(current_node, pdg, parameter, program_behavior, file_context)
                elif parameter.get_value("label") == "CALL":
                    if parameter.get_id() in pdg.get_nodes() and not self.has_ddg_line_of_two_nodes(
                        current_node.get_id(), parameter.get_id(), pdg
                    ):
                        program_behavior.add_pdg_edge(parameter.get_id(), current_node.get_id(), ["DDG"])

    def find_pdg_edge_in_block(
        self, current_node: PDGNode, pdg: PDG, parameter_node: CPGNode, program_behavior: PBG, file_context: FileContext
    ):
        """
        find the missing pdg edge in the block
        """
        ast_of_block = self.current_code_info.cpg.get_children_ast(parameter_node.get_id())
        for ast in ast_of_block:
            if ast.get_id() in pdg.get_nodes() and not self.has_ddg_line_of_two_nodes(
                current_node.get_id(), ast.get_id(), pdg
            ):
                program_behavior.add_pdg_edge(ast.get_id(), current_node.get_id(), [f"DDG: {ast.get_value('CODE')}"])
            if ast.get_value("label") == "CALL" and ast.get_value("NAME") == "<operator>.assignment":
                ast_children = self.current_code_info.cpg.get_children_ast(ast.get_id())
                if len(ast_children) > 1:
                    right_ast_node = ast_children[1]
                    if right_ast_node.get_value("label") == "IDENTIFIER":
                        found_identifier = file_context.find_identifier(
                            right_ast_node.get_value("CODE"), current_node.get_line_number()
                        )
                        if found_identifier:
                            program_behavior.add_object_to_pdg_edge(
                                found_identifier.get_ref_object(), current_node.get_id()
                            )

    @staticmethod
    def is_core_module(module_name):
        """
        check the module is core module
        """
        builtin_module_list = [
            "assert",
            "buffer",
            "child_process",
            "cluster",
            "crypto",
            "dgram",
            "dns",
            "domain",
            "events",
            "fs",
            "fs/promises",
            "http",
            "https",
            "net",
            "os",
            "path",
            "punycode",
            "querystring",
            "readline",
            "stream",
            "string_decoder",
            "timers",
            "tls",
            "tty",
            "url",
            "util",
            "v8",
            "vm",
            "zlib",
        ]
        if module_name in builtin_module_list:
            return True
        else:
            return False

    @staticmethod
    def is_sensitive_file_extension(filename: str):
        extensions = ["md", "sh", "exe"]
        for extension in extensions:
            if filename.endswith(extension):
                return True
        return False

    @staticmethod
    def get_str_from_parameter_list(parameter_list: list[CPGNode]):
        """
        extract the literal from the parameter node
        """
        parameter_str_list = []
        for parameter in parameter_list:
            if parameter.get_value("label") == "LITERAL":
                parameter_str_list.append(parameter.get_value("CODE").strip().strip("\"'"))
            elif parameter.get_value("label") == "METHOD_REF":
                pass
            else:
                parameter_str_list.append(None)
        return parameter_str_list
