from collections import defaultdict
import torch
import numpy as np
import dill


class Graph:
    def __init__(self):
        super(Graph, self).__init__()
        """
            node_forward and bacward are only used when building the data. 
            Afterwards will be transformed into node_feature by DataFrame
            
            node_forward: name -> node_id
            node_backward: node_id -> feature_dict
            node_feature: a DataFrame containing all features
        """
        self.node_forward = defaultdict(lambda: {})
        self.node_backward = defaultdict(lambda: [])
        self.node_feature = defaultdict(lambda: [])
        self.depended_nodes = defaultdict(lambda: [])
        self.node_sensitivity = defaultdict(lambda: [])

        """
            edge_list: index the adjacancy matrix (time) by 
            <target_type, source_type, relation_type, target_id, source_id>
        """
        self.edge_list = defaultdict(  # target_type
            lambda: defaultdict(  # source_type
                lambda: defaultdict(  # relation_type
                    lambda: defaultdict(  # target_id
                        lambda: defaultdict(  # source_id(
                            lambda: int  # time
                        )
                    )
                )
            )
        )
        self.times = {}

    def add_node(self, node):
        nfl = self.node_forward[node["type"]]
        if node["id"] not in nfl:
            self.node_backward[node["type"]] += [node]
            self.node_sensitivity[node["type"]].append(node)
            ser = len(nfl)
            nfl[node["id"]] = ser
            return ser
        return nfl[node["id"]]

    def add_edge(self, source_node, target_node, time=None, relation_type=None, directed=True):
        edge = [self.add_node(source_node), self.add_node(target_node)]
        """
            Add bi-directional edges with different relation type
        """
        self.edge_list[target_node["type"]][source_node["type"]][relation_type][edge[1]][edge[0]] = time
        if directed:
            self.edge_list[source_node["type"]][target_node["type"]]["rev_" + relation_type][edge[0]][edge[1]] = time
        else:
            self.edge_list[source_node["type"]][target_node["type"]][relation_type][edge[0]][edge[1]] = time
        self.times[time] = True

    def update_node(self, node):
        nbl = self.node_backward[node["type"]]
        ser = self.add_node(node)
        for k in node:
            if k not in nbl[ser]:
                nbl[ser][k] = node[k]

    def get_meta_graph(self):
        metas = []
        for target_type in self.edge_list:
            for source_type in self.edge_list[target_type]:
                for r_type in self.edge_list[target_type][source_type]:
                    metas += [(target_type, source_type, r_type)]
        return metas

    def get_types(self):
        return list(self.node_feature.keys())


def to_torch(feature, degree, edge_list, graph, node_type2id, meta2id):
    """
    Transform a sampled sub-graph into pytorch Tensor
    node_dict: {node_type: <node_number, node_type_ID>} node_number is used to trace back the nodes in original graph.
    edge_dict: {edge_type: edge_type_ID}
    """
    node_feature_list = []
    node_degree_list = []
    node_type_list = []
    node_dict = {}

    # 1) Build the concatenated node feature tensors, degree, and node_type
    current_offset = 0
    for t_str in graph.get_types():
        t_id = node_type2id[t_str]
        node_dict[t_str] = [current_offset, t_id]

        node_feature_list += list(feature[t_str])
        node_degree_list += list(degree[t_str])

        node_type_list.extend([t_id] * len(feature[t_str]))

        current_offset += len(feature[t_str])

    # 2) Build edge_index and edge_type
    edge_index_list = []
    edge_type_list = []

    for t_str in edge_list:  # target node type (string)
        t_id = node_type2id[t_str]
        for s_str in edge_list[t_str]:  # source node type (string)
            s_id = node_type2id[s_str]
            for r_str in edge_list[t_str][s_str]:
                # If (t_id, s_id, r_str) is not in meta2id, skip
                if (t_id, s_id, r_str) not in meta2id:
                    continue
                rel_id = meta2id[(t_id, s_id, r_str)]

                for t_idx in edge_list[t_str][s_str][r_str]:
                    for s_idx in edge_list[t_str][s_str][r_str][t_idx]:
                        # Global index in the final node_feature array
                        global_t_idx = t_idx + node_dict[t_str][0]
                        global_s_idx = s_idx + node_dict[s_str][0]

                        edge_index_list.append([global_s_idx, global_t_idx])
                        edge_type_list.append(rel_id)

    # node features: shape [N, feat_dim]
    node_feature_array = np.stack(node_feature_list, axis=0).astype(np.float32)
    node_feature_tensor = torch.from_numpy(node_feature_array)

    # node degrees: shape [N]
    node_degree_array = np.array(node_degree_list, dtype=np.float32)
    node_degree_tensor = torch.from_numpy(node_degree_array)

    # node types: shape [N]
    node_type_array = np.array(node_type_list, dtype=np.int64)
    node_type_tensor = torch.from_numpy(node_type_array)

    # edges: shape [2, E]
    edge_index_array = np.array(edge_index_list, dtype=np.int64).T
    edge_index_tensor = torch.from_numpy(edge_index_array)

    # edge types: shape [E]
    edge_type_array = np.array(edge_type_list, dtype=np.int64)
    edge_type_tensor = torch.from_numpy(edge_type_array)

    return (
        node_feature_tensor,
        node_degree_tensor,
        node_type_tensor,
        edge_index_tensor,
        edge_type_tensor,
        node_dict,
    )


class RenameUnpickler(dill.Unpickler):
    def find_class(self, module, name):
        renamed_module = module
        if module == "GPT_GNN.data" or module == "data":
            renamed_module = "pyHGT.data"
        return super(RenameUnpickler, self).find_class(renamed_module, name)


def renamed_load(file_obj):
    return RenameUnpickler(file_obj).load()
