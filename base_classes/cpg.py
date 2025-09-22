from __future__ import annotations
from custom_exception import GraphReadingException
from custom_exception import JoernGenerationException
from base_classes.cpg_node import CPGNode
from base_classes.cpg_pdg_edge import Edge
import os
import networkx as nx
from ast_parser import ASTParser


class CPG:
    def __init__(self, cpg_dir: str, cpg_graph=None):
        self.cpg_dir = cpg_dir
        self.nodes: dict[int, CPGNode] = {}
        self.edges: dict[tuple[int, int], Edge] = {}
        self.out_edges: dict[int, set[int]] = {}
        self.in_edges: dict[int, set[int]] = {}
        self.max_node_id = 0

        if cpg_graph is None:
            cpg_path = os.path.join(cpg_dir, "export.xml")
            if not os.path.exists(cpg_path):
                raise JoernGenerationException(f"export.xml is not found in {cpg_path}")

            try:
                cpg = nx.read_graphml(cpg_path)
            except Exception:
                raise GraphReadingException("GraphML Reading Exception")
        else:
            cpg = cpg_graph
        for node in cpg.nodes:
            # Read node information from CPG
            node_id = int(node)
            cpg_node = CPGNode(node_id)
            for key, value in cpg.nodes[node].items():
                format_key = self.transform_key(key)
                cpg_node.set_attr(format_key, value)
            self.nodes[node_id] = cpg_node
            self.max_node_id = node_id

        # Read all edges from CPG
        for head, tail, key, edge_dict in cpg.edges(data=True, keys=True):
            src = int(head)
            dst = int(tail)
            if (src, dst) not in self.edges:
                cpg_edge = Edge((src, dst))
            else:
                cpg_edge = self.edges[(src, dst)]

            # Add to outgoing edges
            if src not in self.out_edges:
                self.out_edges[src] = set()
                self.out_edges[src].add(dst)
            else:
                self.out_edges[src].add(dst)

            # Add to incoming edges
            if dst not in self.in_edges:
                self.in_edges[dst] = set()
                self.in_edges[dst].add(src)
            else:
                self.in_edges[dst].add(src)

            for _key, _value in edge_dict.items():
                cpg_edge.add_attr(_value)
            self.edges[(src, dst)] = cpg_edge

    def get_node(self, node_id: int) -> CPGNode:
        return self.nodes[node_id]

    def get_children_ast(self, node_id: int) -> list[CPGNode]:
        """
        Get AST child nodes
        """
        if node_id not in self.out_edges:
            return []
        nodes_id = self.out_edges[node_id]
        ast = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == "AST":
                    ast.append(self.nodes[tail_id])

        def sort_key(node):
            order = node.get_value("ORDER")
            # Check if ORDER is a valid non-negative integer
            if order is not None and int(order) >= 0:
                return 0, int(order)  # Valid ORDER: Primary sort
            else:
                return 1, 0  # Invalid ORDER: Secondary sort

        # Sort in ascending order
        return sorted(ast, key=sort_key)

    def get_first_ast_node_in_call(self, node_id: int) -> CPGNode | None:
        ast_list = self.get_children_ast(node_id)
        argument_list = self.get_argument_from_joern(node_id)
        ast_list = [node for node in ast_list if node not in argument_list]
        if ast_list and len(ast_list) > 0:
            return ast_list[0]
        else:
            return None

    def get_argument_from_joern(self, node_id: int) -> list[CPGNode]:
        """
        Search the CPG edge where edge property is argument
        """
        if node_id not in self.out_edges:
            return []
        nodes_id = self.out_edges[node_id]
        argument_list = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == "ARGUMENT":
                    argument_list.append(self.nodes[tail_id])
        valid_arguments = [
            node
            for node in argument_list
            if node.get_value("ARGUMENT_INDEX") is not None and int(node.get_value("ARGUMENT_INDEX")) >= 1
        ]
        sorted_arguments = sorted(valid_arguments, key=lambda x: int(x.get_value("ARGUMENT_INDEX")))
        return sorted_arguments

    def get_argument_from_joern_index_less_than_one(self, node_id: int) -> list[CPGNode]:
        if node_id not in self.out_edges:
            return []
        nodes_id = self.out_edges[node_id]
        argument_list = []
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == "ARGUMENT":
                    argument_list.append(self.nodes[tail_id])
        valid_arguments = [
            node
            for node in argument_list
            if node.get_value("ARGUMENT_INDEX") is not None and int(node.get_value("ARGUMENT_INDEX")) < 1
        ]
        sorted_arguments = sorted(valid_arguments, key=lambda x: int(x.get_value("ARGUMENT_INDEX")))
        return sorted_arguments

    def get_call(self, node_id: int) -> CPGNode | None:
        """
        Find edges in CPG where edge type is CALL
        """
        nodes_id = self.out_edges[node_id]
        call_node = None
        for tail_id in nodes_id:
            edge = self.edges[(node_id, tail_id)]
            attr = edge.get_attr()
            for item in attr:
                if item == "CALL":
                    call_node = self.nodes[tail_id]
        return call_node

    def get_max_node_id(self):
        """
        Get the maximum ID number for creating new nodes
        """
        self.max_node_id += 1
        return self.max_node_id

    @staticmethod
    def transform_key(key):
        if key == "labelV":
            return "label"
        elif key == "labelE":
            return "label"
        else:
            return key
