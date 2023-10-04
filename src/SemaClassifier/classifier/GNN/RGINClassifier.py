import torch
import torch.nn.functional as F
from torch_geometric.nn import GINConv, global_mean_pool


class RanGIN_node(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4):
        super(RanGIN_node, self).__init__()
        self.num_layers = num_layers
        self.emb_dim = hidden
        self.num_tasks = num_classes
        self.num_features = num_features

        if self.num_layers < 2:
            raise ValueError("Number of GNN layers must be greater than 1.")
        
        self.convs = torch.nn.ModuleList()
        for layer in range(num_layers):
            if layer == 0:
                nn = torch.nn.Sequential(
                    torch.nn.Linear(num_features, hidden),
                    torch.nn.ReLU(),
                    torch.nn.Linear(hidden, hidden),
                )
            else:
                nn = torch.nn.Sequential(
                    torch.nn.Linear(hidden, hidden),
                    torch.nn.ReLU(),
                    torch.nn.Linear(hidden, hidden),
                )
            self.convs.append(GINConv(nn))

        # self.graph_pred_linear = torch.nn.Linear(hidden, num_classes)


    def forward(self, x, edge_index, batch):
        # x = F.relu(self.conv1(x, edge_index))
        for conv in self.convs:
            x = F.relu(conv(x, edge_index))
        return x

class RanGIN(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4):
        super(RanGIN, self).__init__()
        self.num_layers = num_layers
        self.emb_dim = hidden
        self.num_tasks = num_classes
        self.num_features = num_features

        if self.num_layers < 2:
            raise ValueError("Number of GNN layers must be greater than 1.")
        
        self.gnn_node = RanGIN_node(num_features, hidden, num_classes, num_layers)

        self.pool = global_mean_pool

        self.graph_pred_linear = torch.nn.Linear(hidden, num_classes)


    def forward(self, x, edge_index, batch):
        
        node_rep = self.gnn_node(x, edge_index, batch)
        pooled_rep = self.pool(node_rep, batch)
        graph_rep = self.graph_pred_linear(pooled_rep)

        return F.log_softmax(graph_rep, dim=-1)