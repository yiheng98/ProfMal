from __future__ import annotations

import os
import json
from npm_pipeline.classes.file import File
from base_classes.cpg import CPG
from loguru import logger
from npm_pipeline.classes.call_graph_info import CallGraph
from ast_parser import ASTParser
from base_classes.pdg import PDG
from npm_pipeline.classes.api_call import APICallCollection


class CodeInfo:
    def __init__(self, formatted_package_dir: str, pdg_dir: str, cpg_dir: str, pdg_graph_dict: dict, cpg_graph):
        self.formatted_package_dir = formatted_package_dir
        self.pdg_dir = pdg_dir
        self.cpg_dir = cpg_dir
        self.js_file_list = self.__iterate_file()  # get all .js files
        self.files: dict[str, File] = {}  # files
        for js_file, raw_code in self.js_file_list.items():
            self.files[js_file] = File(js_file, raw_code)
        self.js_file_list = list(self.js_file_list.keys())
        self.cpg = CPG(self.cpg_dir, cpg_graph)  # read the cpg dot
        self.__build_static_pdg_dict(pdg_graph_dict)  # read the pdg dot
        self.__build_call_expression_dict()  # build the call expression dict
        self.call_graph = None
        self.api_call_info = None  # the api call info is available in the dynamic analysis
        self.api_call_to_pdg_node_mapping = {}  # record the api call to pdg node mapping

    def __iterate_file(self) -> dict[str, list]:
        """
        iterate all the files in the package
        :return: list containing all the files in the call graph
        """
        js_files = {}
        for root, dirs, files in os.walk(self.formatted_package_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as code_file:
                        raw_code = code_file.readlines()
                except Exception as e:
                    logger.warning(f"UnicodeDecodeError reading file {file_path}: {e}")
                    raw_code = []
                js_files[os.path.relpath(file_path, self.formatted_package_dir)] = raw_code
        return js_files

    def __build_static_pdg_dict(self, pdg_graph_dict=None):
        """
        build the pdg from the pdg dot
        """
        dot_names = os.listdir(self.pdg_dir)

        # key: (first node id, name, full name, file)
        self.pdg_dict: dict[int, PDG] = {}

        # to record whether the pdg is analyzed
        self.pdg_analyzed: dict[int, bool] = {}
        for dot in dot_names:
            dot_path = os.path.join(self.pdg_dir, dot)
            try:
                if pdg_graph_dict is not None and dot in pdg_graph_dict:
                    pdg = PDG(pdg_path=dot_path, cpg=self.cpg, pdg_graph=pdg_graph_dict[dot])
                else:
                    pdg = PDG(pdg_path=dot_path, cpg=self.cpg)
            except Exception as e:
                logger.info(f"Failed to read PDG from {dot_path} of {e}. \nSkipping this PDG.")
                continue
            if pdg.is_empty():
                continue
            name = pdg.get_name()
            filename = pdg.get_file_name()
            if name is None or filename is None or filename == "<empty>" or filename.endswith(".ts"):
                continue

            self.pdg_dict[pdg.get_first_node_id()] = pdg
            self.pdg_analyzed[pdg.get_first_node_id()] = False

    def set_call_graph(self, call_graph: CallGraph):
        self.call_graph = call_graph

    def set_api_call_info(self, api_call_info: APICallCollection | None):
        self.api_call_info = api_call_info

    def build_static_call_graph(self, call_graph_path: str):
        """
        read the call graph in cg.json
        """
        self.call_graph = CallGraph()
        with open(call_graph_path, "r") as cg_file:
            json_data = json.load(cg_file)
        entries = json_data["entries"]
        if len(entries) != 0:
            for entry in entries:
                self.call_graph.add_entries(entry)

        files = json_data["files"]
        if len(files) != 0:
            for file in files:
                self.call_graph.add_file(file)

        functions = json_data["functions"]
        if len(functions) != 0:
            for key, value in functions.items():
                # the value is like 0:1:1:1:25
                split_value = value.split(":")
                self.call_graph.add_function(
                    int(key),
                    int(split_value[0]),
                    int(split_value[1]) - 1,
                    int(split_value[2]) - 1,
                    int(split_value[3]) - 1,
                    int(split_value[4]) - 1,
                )

        calls = json_data["calls"]
        if len(calls) != 0:
            for key, value in calls.items():
                split_value = value.split(":")
                self.call_graph.add_call(
                    int(key),
                    int(split_value[0]),
                    int(split_value[1]) - 1,
                    int(split_value[2]) - 1,
                    int(split_value[3]) - 1,
                    int(split_value[4]) - 1,
                )

        call2func_list = json_data["call2fun"]
        if len(call2func_list) != 0:
            for call2func in call2func_list:
                call_id = call2func[0]
                func_id = call2func[1]
                self.call_graph.add_call_to_function(call_id, func_id)

    def __build_call_expression_dict(self):
        """
        record the call expression start from line and column
        """
        self.call_expression_dict: dict[str, dict[tuple, tuple]] = {}
        for file in self.files:
            source_code = "".join(self.files[file].get_raw_code())
            parser = ASTParser(source_code)
            call_expression_list = parser.query("(call_expression)@call_expression")
            if len(call_expression_list) != 0:
                for call_expression in call_expression_list:
                    start_point = call_expression[0].start_point
                    end_point = call_expression[0].end_point
                    start_line = start_point[0]
                    start_column = start_point[1]
                    end_line = end_point[0]
                    end_column = end_point[1]
                    if file not in self.call_expression_dict:
                        self.call_expression_dict[file] = {}
                    self.call_expression_dict[file][(start_line, start_column)] = (end_line, end_column)
            new_expression_list = parser.query("(new_expression)@new_expression")
            if len(new_expression_list) != 0:
                for new_expression in new_expression_list:
                    start_point = new_expression[0].start_point
                    end_point = new_expression[0].end_point
                    start_line = start_point[0]
                    start_column = start_point[1]
                    end_line = end_point[0]
                    end_column = end_point[1]
                    if file not in self.call_expression_dict:
                        self.call_expression_dict[file] = {}
                    self.call_expression_dict[file][(start_line, start_column)] = (end_line, end_column)
