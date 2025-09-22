from detector.pyHGT.data import Graph
import pandas as pd
import os
import networkx as nx
from detector.config import allowed_relation_types, one_hot_encoding
from loguru import logger
import dill


def crete_csv_dict(csv_file):
    dataframe = pd.read_csv(csv_file)

    result_dict = {
        row["fullName"]: {"domain": row["domain"], "category": row["category"]} for _, row in dataframe.iterrows()
    }

    return result_dict


script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
csv_path = os.path.join(parent_dir, "sensitive_call.csv")
full_name_dict = crete_csv_dict(csv_path)


def process_dot_in_memory(dot_file_path):
    try:
        G = nx.nx_pydot.read_dot(dot_file_path)
    except Exception as e:
        logger.warning(f"Failed to read the dot file: {dot_file_path} of {e}")
        return None

    non_isolated_nodes = set(G.nodes()) - set(nx.isolates(G))
    if not non_isolated_nodes:
        return None

    # build the graph dict
    node_info = {}
    for node, attr in G.nodes(data=True):
        degree = attr.get("degree")
        full_name = attr.get("full_name")
        if full_name is not None:
            full_name = full_name.strip('"')
        else:
            continue  # 如果没有 full_name，则跳过该节点

        if full_name not in full_name_dict:
            continue

        domain = full_name_dict[full_name]["domain"]
        category = full_name_dict[full_name]["category"]
        try:
            deg = float(degree) if degree is not None else 0.5
        except ValueError:
            deg = 0.5

        emb = one_hot_encoding(category)
        node_info[node] = {
            "id": node,
            "type": category,
            "degree": deg,
            "domain": domain,
            "emb": emb,
        }

    graph = Graph()

    for u, v, key, attr in G.edges(data=True, keys=True):
        label = attr.get("label", "")
        color = attr.get("color", "")
        if isinstance(label, str):
            label = label.strip('"')
        if isinstance(color, str):
            color = color.strip('"')

        # 获取边的两个端点
        source_node = node_info.get(u)
        target_node = node_info.get(v)
        if source_node is None or target_node is None:
            continue

        relation_type = label
        if relation_type in allowed_relation_types:
            graph.add_edge(source_node, target_node, time=10086, relation_type=relation_type)
        else:
            logger.warning(f"Add invalid relation_type: {relation_type}, Skipp")

    for type_ in graph.node_backward:
        df = pd.DataFrame(graph.node_backward[type_])
        graph.node_feature[type_] = df

    clean_edge_list = {}
    for k1 in graph.edge_list:
        if k1 not in clean_edge_list:
            clean_edge_list[k1] = {}
        for k2 in graph.edge_list[k1]:
            if k2 not in clean_edge_list[k1]:
                clean_edge_list[k1][k2] = {}
            for k3 in graph.edge_list[k1][k2]:
                if k3 not in clean_edge_list[k1][k2]:
                    clean_edge_list[k1][k2][k3] = {}
                triple_count = 0
                for e1 in graph.edge_list[k1][k2][k3]:
                    edge_count = len(graph.edge_list[k1][k2][k3][e1])
                    triple_count += edge_count
                    if edge_count == 0:
                        continue
                    clean_edge_list[k1][k2][k3][e1] = {}
                    for e2 in graph.edge_list[k1][k2][k3][e1]:
                        clean_edge_list[k1][k2][k3][e1][e2] = graph.edge_list[k1][k2][k3][e1][e2]
    graph.edge_list = clean_edge_list

    return graph
