from base_classes.pdg_node import PDGNode
from base_classes.cpg_pdg_edge import Edge
import os
import re
import networkx as nx
from custom_exception import GraphReadingException
from custom_exception import JoernGenerationException


class PDG:
    def __init__(self, pdg_path, cpg, pdg_graph=None):
        self.pdg_path = pdg_path
        self.nodes: dict[int, PDGNode] = {}
        self.edges: dict[tuple[int, int], Edge] = {}
        self.out_edges: dict[int, list[int]] = {}
        self.in_edges: dict[int, list[int]] = {}

        if pdg_graph is None:
            if not os.path.exists(self.pdg_path):
                raise JoernGenerationException(f"dot file is not found in {self.pdg_path}")
            try:
                pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)
            except Exception:
                raise GraphReadingException(f"Dot Reading Exception of {pdg_path}")
        else:
            pdg = pdg_graph

        if len(pdg.nodes) == 0:
            return

        # the first node in the pdg
        first_node_id = list(pdg.nodes)[0]
        self.first_node_id = int(first_node_id)

        # the name of the pdg
        self.name = pdg.nodes[first_node_id]["NAME"] if "NAME" in pdg.nodes[first_node_id] else None

        # the start line number of the source code corresponding to the pdg
        self.line_number = (
            int(pdg.nodes[first_node_id]["LINE_NUMBER"]) if "LINE_NUMBER" in pdg.nodes[first_node_id] else None
        )

        # the end line number of the source code corresponding to the pdg
        self.line_number_end = (
            int(pdg.nodes[first_node_id]["LINE_NUMBER_END"]) if "LINE_NUMBER_END" in pdg.nodes[first_node_id] else None
        )

        # the start column number of the source code corresponding to the pdg
        self.column_number = (
            int(pdg.nodes[first_node_id]["COLUMN_NUMBER"]) if "COLUMN_NUMBER" in pdg.nodes[first_node_id] else None
        )

        # the end column number of the source code corresponding to the pdg
        self.column_number_end = (
            int(pdg.nodes[first_node_id]["COLUMN_NUMBER_END"])
            if "COLUMN_NUMBER_END" in pdg.nodes[first_node_id]
            else None
        )

        # the full name of the pdg
        if "FULL_NAME" in pdg.nodes[first_node_id]:
            self.full_name = pdg.nodes[first_node_id]["FULL_NAME"]
        else:
            self.full_name = None

        # the file name of the pdg
        if "FILENAME" in pdg.nodes[first_node_id]:
            self.file_name = pdg.nodes[first_node_id]["FILENAME"].strip()
        else:
            self.file_name = None

        # the code of the pdg. Attention this may not equal to the actual source code
        self.code = cpg.get_node(self.first_node_id).get_value("CODE")

        # the program corresponding to implicit main function
        if self.name == ":program":
            self.type = "program"

        # the function is anonymous function
        elif self.name is not None and re.search(r"<lambda>\d*", self.name):
            self.type = "lambda"
        else:
            # default type
            self.type = "function"

        # read all the nodes in the pdg
        for node in pdg.nodes:
            node_id = int(node)
            pdg_node = PDGNode(node_id)
            pdg_node.set_source_pdg(self.first_node_id)
            pdg_node.set_file_name(self.file_name)
            node_type = pdg.nodes[node]["NODE_TYPE"] if "NODE_TYPE" in pdg.nodes[node] else None
            pdg_node.set_node_type(node_type)
            if "LINE_NUMBER" in pdg.nodes[node]:
                line_number = int(pdg.nodes[node]["LINE_NUMBER"])
                pdg_node.set_line_number(line_number)
            else:
                pdg_node.set_line_number(None)

            if "COLUMN_NUMBER" in pdg.nodes[node]:
                column_number = int(pdg.nodes[node]["COLUMN_NUMBER"])
                pdg_node.set_column_number(column_number)
            else:
                pdg_node.set_column_number_end(None)

            if "NAME" in pdg.nodes[node]:
                name = pdg.nodes[node]["NAME"]
                pdg_node.set_name(name)

            if "CODE" in pdg.nodes[node]:
                code = cpg.get_node(int(node)).get_value("CODE")
                pdg_node.set_code(code)

            self.nodes[node_id] = pdg_node

        # the entrance of the pdg
        self.nodes[self.first_node_id].set_entrance(True)

        # read the line in the pdg
        for head, tail, key, edge_dict in pdg.edges(data=True, keys=True):
            src = int(head)
            dst = int(tail)
            if src not in self.nodes:
                # the start node is not in the pdg
                continue
            if (src, dst) not in self.edges:
                pdg_edge = Edge((src, dst))
            else:
                # the edge is already in the pdg
                # retrieve the edge
                pdg_edge = self.edges[(src, dst)]

            # add the (src, dst) to the out edges
            if src not in self.out_edges:
                self.out_edges[src] = []
                self.out_edges[src].append(dst)
            else:
                if dst not in self.out_edges[src]:
                    self.out_edges[src].append(dst)

            # add the (dst, src) to the in edges
            if dst not in self.in_edges:
                self.in_edges[dst] = []
                self.in_edges[dst].append(src)
            else:
                if src not in self.in_edges[dst]:
                    self.in_edges[dst].append(src)

            for _key, _value in edge_dict.items():
                pdg_edge.add_attr(_value)
            self.edges[(src, dst)] = pdg_edge

    def get_node(self, node_id) -> PDGNode:
        return self.nodes[node_id]

    def get_file_name(self) -> str:
        return self.file_name

    def get_line_number(self) -> int:
        return self.line_number

    def get_line_number_end(self) -> int:
        return self.line_number_end

    def get_column_number(self) -> int:
        return self.column_number

    def get_column_number_end(self) -> int:
        return self.column_number_end

    def get_name(self) -> str:
        return self.name

    def is_empty(self):
        return len(self.nodes) == 0

    def get_nodes(self) -> dict[int, PDGNode]:
        return self.nodes

    def get_edges(self) -> dict[tuple[int, int], Edge]:
        return self.edges

    def get_in_edges(self) -> dict[int, list[int]]:
        return self.in_edges

    def get_out_edges(self) -> dict[int, list[int]]:
        return self.out_edges

    def get_first_node_id(self) -> int:
        return self.first_node_id

    def get_full_name(self) -> str:
        return self.full_name
