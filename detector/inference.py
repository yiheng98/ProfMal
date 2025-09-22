from detector.pyHGT.data import to_torch
from detector.pyHGT.model import GNN, Classifier
from detector.config import (
    node_type2id,
    meta2id,
    node_types,
    allowed_relation_types,
    id2meta,
)
import torch
import numpy as np

conv_name = "hgt"
in_dim = 39
n_hid = 256
n_heads = 8
n_layers = 3
dropout = 0.2


device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")


def feature_extract(_graph):
    _feat, _deg = {}, {}
    for _type, df in _graph.node_feature.items():
        _feat[_type] = np.array(df["emb"].tolist())
        _deg[_type] = np.array(df["degree"].tolist())
    return _feat, _deg


def weighted_pooling(_node_rep, sensitivity):
    weighted = _node_rep * sensitivity.unsqueeze(1)  # [N, d]
    global_rep = weighted.sum(dim=0) / (sensitivity.sum() + 1e-9)
    return global_rep


def load_graph(graph):
    feature, degree = feature_extract(graph)
    edge_list = graph.edge_list

    node_feature, node_degree_feature, node_type, edge_index, edge_type, node_dict = to_torch(
        feature, degree, edge_list, graph, node_type2id, meta2id
    )

    _sample = {
        "node_feature": node_feature,  # shape [N, in_dim]
        "node_degree_feature": node_degree_feature,  # shape [N]
        "node_type": node_type,  # shape [N]
        "edge_index": edge_index,  # shape [2, E]
        "edge_type": edge_type,  # shape [E]
    }
    return _sample


def predict_graph(graph, model_path):
    gnn_p = GNN(
        conv_name=conv_name,
        in_dim=in_dim,
        n_hid=n_hid,
        n_heads=n_heads,
        n_layers=n_layers,
        dropout=dropout,
        num_types=len(node_types),
        num_relations=len(node_types) * len(node_types) * len(allowed_relation_types) * 2 + 1,
        id2meta=id2meta,
    ).to(device)
    cls_p = Classifier(in_dim=n_hid, hidden_dim=n_hid // 2).to(device)
    model_p = torch.nn.Sequential(gnn_p, cls_p)
    model_p.load_state_dict(torch.load(model_path, map_location=device))
    model_p.eval()

    sample = load_graph(graph)
    nf = sample["node_feature"].to(device)
    nd_raw = sample["node_degree_feature"].to(device)  # [N]
    nd = nd_raw.unsqueeze(1)  # [N, 1]
    nf = torch.cat([nf, nd], dim=1)  # [N, in_dim + 1]

    nt = sample["node_type"].to(device)
    ei = sample["edge_index"].to(device)
    et = sample["edge_type"].to(device)

    with torch.no_grad():
        node_rep = gnn_p(nf, nt, ei, et)  # [N, n_hid]
        graph_feat = weighted_pooling(node_rep, nd_raw)  # [n_hid]
        graph_feat = graph_feat.unsqueeze(0)  # [1, n_hid]
        logit = cls_p(graph_feat).view(-1)  # [1]
        prob = torch.sigmoid(logit)[0].item()

    return prob
