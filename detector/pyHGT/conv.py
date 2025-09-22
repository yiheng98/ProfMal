import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn.conv import MessagePassing
from torch_geometric.nn.inits import glorot
from torch_geometric.utils import softmax
import math


class HGTConv(MessagePassing):
    """
    Implementation of Heterogeneous Graph Transformer (HGT) convolution layer.
    This layer performs message passing and node feature updates based on heterogeneous information
    (including node types, edge types, and temporal information), while utilizing multi-head attention
    mechanisms and relation-specific parameters to capture interaction information in heterogeneous graphs.

    Parameters:
      - in_dim: Input node feature dimension
      - out_dim: Output node feature dimension
      - num_types: Number of node types (different node types in heterogeneous graph)
      - num_relations: Number of edge (relation) types
      - n_heads: Number of multi-head attention heads
      - dropout: Dropout probability for preventing overfitting
      - use_norm: Whether to use LayerNorm for normalization
    """

    def __init__(
        self,
        in_dim,
        out_dim,
        num_types,
        num_relations,
        n_heads,
        dropout=0.2,
        id2meta=None,
        use_norm=True,
        **kwargs,
    ):
        super(HGTConv, self).__init__(node_dim=0, aggr="add", **kwargs)

        self.in_dim = in_dim
        self.out_dim = out_dim
        self.num_types = num_types
        self.num_relations = num_relations
        self.total_rel = num_types * num_relations * num_types
        self.n_heads = n_heads
        # Dimension of each attention head
        self.d_k = out_dim // n_heads
        self.sqrt_dk = math.sqrt(self.d_k)
        self.use_norm = use_norm
        self.att = None
        self.id2meta = id2meta

        # Create independent linear mappings for each node type, used for Key, Query, Value and final transformation (a_linear)
        self.k_linears = nn.ModuleList()
        self.q_linears = nn.ModuleList()
        self.v_linears = nn.ModuleList()
        self.a_linears = nn.ModuleList()
        self.norms = nn.ModuleList()

        for t in range(num_types):
            self.k_linears.append(nn.Linear(in_dim, out_dim))
            self.q_linears.append(nn.Linear(in_dim, out_dim))
            self.v_linears.append(nn.Linear(in_dim, out_dim))
            self.a_linears.append(nn.Linear(out_dim, out_dim))
            if use_norm:
                self.norms.append(nn.LayerNorm(out_dim))
        """
            TODO: make relation_pri smaller, as not all <st, rt, tt> pair exist in meta relation list.
        """
        self.relation_pri = nn.Parameter(torch.ones(num_relations, self.n_heads))
        self.relation_att = nn.Parameter(torch.Tensor(num_relations, n_heads, self.d_k, self.d_k))
        self.relation_msg = nn.Parameter(torch.Tensor(num_relations, n_heads, self.d_k, self.d_k))
        self.skip = nn.Parameter(torch.ones(num_types))
        self.drop = nn.Dropout(dropout)

        # Use Glorot initialization for relation attention and message weights
        glorot(self.relation_att)
        glorot(self.relation_msg)

    def forward(self, node_inp, node_type, edge_index, edge_type):
        return self.propagate(edge_index, node_inp=node_inp, node_type=node_type, edge_type=edge_type)

    def message(self, edge_index_i, node_inp_i, node_inp_j, node_type_i, node_type_j, edge_type):
        """
        j: source, i: target; <j, i>
        """
        data_size = edge_index_i.size(0)
        """
            Create Attention and Message tensor beforehand.
        """
        res_att = torch.zeros(data_size, self.n_heads).to(node_inp_i.device)
        res_msg = torch.zeros(data_size, self.n_heads, self.d_k).to(node_inp_i.device)

        # Iterate through each possible source node type
        for rid in range(self.num_relations):
            if rid not in self.id2meta:
                continue
            t_tid, s_tid, rel_str = self.id2meta[rid]
            idx = (edge_type == rid) & (node_type_j == s_tid) & (node_type_i == t_tid)
            if idx.sum() == 0:
                continue

            target_node_vec = node_inp_i[idx]
            source_node_vec = node_inp_j[idx]

            k_linear = self.k_linears[s_tid]
            v_linear = self.v_linears[s_tid]
            q_linear = self.q_linears[t_tid]

            """
                Step 1: Heterogeneous Mutual Attention
            """
            q_mat = q_linear(target_node_vec).view(-1, self.n_heads, self.d_k)
            k_mat = k_linear(source_node_vec).view(-1, self.n_heads, self.d_k)
            k_mat = torch.bmm(k_mat.transpose(1, 0), self.relation_att[rid]).transpose(1, 0)
            res_att[idx] = (q_mat * k_mat).sum(dim=-1) * self.relation_pri[rid] / self.sqrt_dk
            """
                Step 2: Heterogeneous Message Passing
            """
            v_mat = v_linear(source_node_vec).view(-1, self.n_heads, self.d_k)
            res_msg[idx] = torch.bmm(v_mat.transpose(1, 0), self.relation_msg[rid]).transpose(1, 0)

        self.att = softmax(res_att, edge_index_i)
        res = res_msg * self.att.view(-1, self.n_heads, 1)
        del res_att, res_msg
        return res.view(-1, self.out_dim)

    def update(self, aggr_out, node_inp, node_type):
        """
        Update function that performs two-step processing after message passing aggregation:
        1. For each node type, first process the aggregated results using linear transformation and skip connection (fusing original input).
        2. Then obtain final output through intermediate fully connected layer (mid_linear) and output layer (out_linear), combined with GELU activation, Dropout and LayerNorm.

        Output:
        - Updated node feature tensor with shape [num_nodes, out_dim]

        Step 3: Target-specific Aggregation
        x = W[node_type] * gelu(Agg(x)) + x
        """
        aggr_out = F.gelu(aggr_out)
        res = torch.zeros(aggr_out.size(0), self.out_dim).to(node_inp.device)
        for target_type in range(self.num_types):
            idx = node_type == int(target_type)
            if idx.sum() == 0:
                continue
            trans_out = self.drop(self.a_linears[target_type](aggr_out[idx]))
            """
                Add skip connection with learnable weight self.skip[t_id]
            """
            alpha = torch.sigmoid(self.skip[target_type])
            if self.use_norm:
                res[idx] = self.norms[target_type](trans_out * alpha + node_inp[idx] * (1 - alpha))
            else:
                res[idx] = trans_out * alpha + node_inp[idx] * (1 - alpha)
        return res

    def __repr__(self):
        return f"{self.__class__.__name__}(in_dim={self.in_dim}, out_dim={self.out_dim}, num_types={self.num_types}, num_types={self.num_relations})"


class GeneralConv(nn.Module):
    def __init__(
        self,
        conv_name,
        in_hid,
        out_hid,
        num_types,
        num_relations,
        n_heads,
        dropout,
        id2meta=None,
        use_norm=True,
    ):
        super(GeneralConv, self).__init__()
        self.conv_name = conv_name
        if self.conv_name == "hgt":
            self.base_conv = HGTConv(
                in_hid,
                out_hid,
                num_types,
                num_relations,
                n_heads,
                dropout,
                id2meta,
                use_norm,
            )

    def forward(self, meta_xs, node_type, edge_index, edge_type):
        if self.conv_name == "hgt":
            return self.base_conv(meta_xs, node_type, edge_index, edge_type)
