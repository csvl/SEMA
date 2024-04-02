import torch
import torch.nn.functional as F
from torch_geometric.nn import GINConv, global_mean_pool


'''
GIN model, with Jumping Knowledge

    h_v^{k} = MLP^{(k)}((1+\epsilon^{(k)}).h_v^{(k-1)} + \Sigma_{u \in \mathcal{N}(v)} h_u^{(k-1)})
    
    h_G = concat(readout(\{h_v^{(K)} | v \in G\}) | k = 0, 1, ..., K)

'''
class GINJK(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4):
        super(GINJK, self).__init__()
        self.num_layers = num_layers
        self.convs = torch.nn.ModuleList()
        for i in range(num_layers):
            if i == 0:
                self.convs.append(
                    GINConv(
                        torch.nn.Sequential(
                            torch.nn.Linear(num_features, 2*hidden),
                            torch.nn.BatchNorm1d(2*hidden),
                            torch.nn.ReLU(),
                            torch.nn.Linear(2*hidden, hidden),
                        ), train_eps=False, aggr="mean"
                    )
                )
            else:
                self.convs.append(
                    GINConv(
                        torch.nn.Sequential(
                            torch.nn.Linear(hidden, 2*hidden),
                            torch.nn.BatchNorm1d(2*hidden),
                            torch.nn.ReLU(),
                            torch.nn.Linear(2*hidden, hidden),
                        ), aggr="mean"
                    )
                )
        self.fc = torch.nn.Linear(hidden * num_layers, num_classes)  # Adjust the output dimension

    def forward(self, x, edge_index, edge_attr, batch, pertrub=None):
        xs = []
        for i in range(self.num_layers):
            x = F.relu(self.convs[i](x, edge_index))
            xs.append(x)
        x = torch.cat(xs, dim=1)  # Concatenate representations from all layers
        x = global_mean_pool(x, batch)
        x = self.fc(x)
        return F.log_softmax(x, dim=-1)

# class GINJK(torch.nn.Module):
#     def __init__(self, num_features, hidden, num_classes, num_layers=4):
#         super(GINJK, self).__init__()
#         self.num_layers = num_layers
#         self.convs = torch.nn.ModuleList()
#         self.edge_encoder = torch.nn.Linear(1, hidden)
#         for i in range(num_layers):
#             if i == 0:
#                 self.convs.append(
#                     GINEConv(
#                         torch.nn.Sequential(
#                             torch.nn.Linear(num_features, hidden),
#                             torch.nn.ReLU(),
#                             torch.nn.Linear(hidden, hidden),
#                         ), train_eps=False, edge_dim=hidden, aggr="mean"
#                     )
#                 )
#             else:
#                 self.convs.append(
#                     GINEConv(
#                         torch.nn.Sequential(
#                             torch.nn.Linear(hidden, hidden),
#                             torch.nn.ReLU(),
#                             torch.nn.Linear(hidden, hidden),
#                         ), edge_dim=hidden, aggr="mean"
#                     )
#                 )
#         self.fc = torch.nn.Linear(hidden * num_layers, num_classes)  # Adjust the output dimension

#     def forward(self, x, edge_index, edge_attr, batch, pertrub=None):
#         xs = []
#         for i in range(self.num_layers):
#             edge_embedding = self.edge_encoder(edge_attr)
#             x = F.relu(self.convs[i](x, edge_index, edge_attr=edge_embedding))
#             xs.append(x)
#         x = torch.cat(xs, dim=1)  # Concatenate representations from all layers
#         x = global_mean_pool(x, batch)
#         x = self.fc(x)
#         return F.log_softmax(x, dim=-1)
    

# class RanGINJK_node(torch.nn.Module):
#     def __init__(self, num_features, hidden, num_classes, num_layers=4):
#         super(RanGINJK_node, self).__init__()
#         self.num_layers = num_layers
#         self.emb_dim = hidden
#         self.num_tasks = num_classes
#         self.num_features = num_features

#         if self.num_layers < 2:
#             raise ValueError("Number of GNN layers must be greater than 1.")
        
#         self.convs = torch.nn.ModuleList()
#         for layer in range(num_layers):
#             if layer == 0:
#                 nn = torch.nn.Sequential(
#                     torch.nn.Linear(num_features, hidden),
#                     torch.nn.ReLU(),
#                     torch.nn.Linear(hidden, hidden),
#                 )
#             else:
#                 nn = torch.nn.Sequential(
#                     torch.nn.Linear(hidden, hidden),
#                     torch.nn.ReLU(),
#                     torch.nn.Linear(hidden, hidden),
#                 )
#             self.convs.append(GINConv(nn))

#         # self.graph_pred_linear = torch.nn.Linear(hidden, num_classes)


#     def forward(self, x, edge_index, batch):
#         xs = []
#         for i in range(self.num_layers):
#             x = F.relu(self.convs[i](x, edge_index))
#             xs.append(x)
#         x = torch.cat(xs, dim=1)  # Concatenate representations from all layers
#         return x

# class RanGINJK(torch.nn.Module):
#     def __init__(self, num_features, hidden, num_classes, num_layers=4):
#         super(RanGINJK, self).__init__()
#         self.num_layers = num_layers
#         self.emb_dim = hidden
#         self.num_tasks = num_classes
#         self.num_features = num_features

#         if self.num_layers < 2:
#             raise ValueError("Number of GNN layers must be greater than 1.")
        
#         self.gnn_node = RanGINJK_node(num_features, hidden, num_classes, num_layers)

#         self.pool = global_mean_pool

#         self.graph_pred_linear = torch.nn.Linear(hidden * num_layers, num_classes)  # Adjust the output dimension


#     def forward(self, x, edge_index, batch):
        
#         node_rep = self.gnn_node(x, edge_index, batch)
#         pooled_rep = self.pool(node_rep, batch)
#         graph_rep = self.graph_pred_linear(pooled_rep)

#         return F.log_softmax(graph_rep, dim=-1)