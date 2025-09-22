import torch
import torch.nn as nn
from detector.pyHGT.conv import GeneralConv


class Classifier(nn.Module):
    """
    Classifier uses an MLP to perform binary classification on global graph features.
    Input: global_feature, shape [d] (d = n_hid)
    Output: a scalar (without activation), can be used with BCEWithLogitsLoss.
    """

    def __init__(self, in_dim, hidden_dim, num_layers=2):
        super(Classifier, self).__init__()
        layers = []
        layers.append(nn.Linear(in_dim, hidden_dim))
        layers.append(nn.ReLU())
        # Hidden layers: determine number of hidden layers based on num_layers (num_layers represents number of hidden layers)
        for _ in range(num_layers - 1):
            layers.append(nn.Linear(hidden_dim, hidden_dim))
            layers.append(nn.ReLU())
        # Last layer: map hidden_dim to 1 (output one logit)
        layers.append(nn.Linear(hidden_dim, 1))
        self.mlp = nn.Sequential(*layers)

    def forward(self, global_feature):
        # global_feature: [d] or [batch_size, d] (here for single graph global features)
        out = self.mlp(global_feature)
        return out


class GNN(nn.Module):
    def __init__(
        self,
        in_dim,
        n_hid,
        num_types,
        num_relations,
        n_heads,
        n_layers,
        dropout=0.2,
        conv_name="hgt",
        id2meta=None,
        prev_norm=False,
        last_norm=False,
    ):
        """
        Constructor:
          in_dim      -- Dimension of input node features
          n_hid       -- Feature dimension of hidden (output) layer
          num_types   -- Number of node types (used for heterogeneous graphs)
          num_relations -- Number of edge types (used for heterogeneous graphs)
          n_heads     -- Number of heads in multi-head attention (when using HGT structure)
          n_layers    -- Number of graph convolution layers
          dropout     -- Dropout probability for preventing overfitting
          conv_name   -- Type name of graph convolution layer, e.g., 'hgt'
          prev_norm   -- Whether to use normalization in previous layers
          last_norm   -- Whether to use normalization in the last layer
          use_RTE     -- Whether to use RTE (Relation Type Encoding) module
        """
        super(GNN, self).__init__()

        # Store module list of graph convolution layers (GeneralConv)
        self.gcs = nn.ModuleList()
        self.num_types = num_types
        self.in_dim = in_dim
        self.n_hid = n_hid

        # Define adaptation layers for each node type to linearly transform input features to hidden feature dimension
        # Use independent linear layers for different types of nodes to adapt to different feature distributions
        self.adapt_ws = nn.ModuleList()
        self.drop = nn.Dropout(dropout)
        for t in range(num_types):
            # Create linear transformations for different node types
            self.adapt_ws.append(nn.Linear(in_dim, n_hid))
        for l in range(n_layers - 1):
            self.gcs.append(
                GeneralConv(
                    conv_name,
                    n_hid,
                    n_hid,
                    num_types,
                    num_relations,
                    n_heads,
                    dropout,
                    id2meta,
                    use_norm=prev_norm,
                )
            )
        self.gcs.append(
            GeneralConv(
                conv_name,
                n_hid,
                n_hid,
                num_types,
                num_relations,
                n_heads,
                dropout,
                id2meta,
                use_norm=last_norm,
            )
        )

    def forward(self, node_feature, node_type, edge_index, edge_type):
        """
        Input:
          - node_feature: Node feature matrix, shape [num_nodes, in_dim]. Each row is the initial feature of a node.
          - node_type: Node type
          - edge_time: Edge temporal information (e.g., for dynamic graphs or temporal characteristics), specific meaning depends on implementation. Used for information in original paper, needs modification here
          - edge_index: Edge index
          - edge_type: Edge type labels

        Output:
          - meta_xs: Updated node embeddings, shape [num_nodes, n_hid]. Each node's representation has integrated neighbor information, serving as the foundation for subsequent tasks (such as classification, regression, etc.).
        """
        res = torch.zeros(node_feature.size(0), self.n_hid).to(node_feature.device)
        for t_id in range(self.num_types):
            # Filter out node indices of current node type t_id
            idx = node_type == int(t_id)
            if idx.sum() == 0:
                continue
            # Use corresponding adaptation layer to transform input features of current type nodes to hidden space, then apply tanh activation function
            res[idx] = torch.tanh(self.adapt_ws[t_id](node_feature[idx]))
        meta_xs = self.drop(res)
        del res
        for gc in self.gcs:
            meta_xs = gc(meta_xs, node_type, edge_index, edge_type)
        return meta_xs
