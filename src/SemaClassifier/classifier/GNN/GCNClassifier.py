import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool
    
class GCN(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels, num_layers):
        super(GCN, self).__init__()
        self.conv1 = GCNConv(in_channels, hidden_channels)
        self.convs = torch.nn.ModuleList([
            GCNConv(hidden_channels, hidden_channels) for _ in range(num_layers - 2)
        ])
        self.conv2 = GCNConv(hidden_channels, out_channels)

    def forward(self, data):
        x, edge_index = data.x, data.edge_index

        x = F.relu(self.conv1(x, edge_index))
        for conv in self.convs:
            x = F.relu(conv(x, edge_index))
        x = self.conv2(x, edge_index)

        return F.log_softmax(x, dim=1)
    

### GCN convolution along the graph structure
# class GCNConv(MessagePassing):
#     def __init__(self, emb_dim):
#         super(GCNConv, self).__init__(aggr='add')

#         self.linear = torch.nn.Linear(emb_dim, emb_dim)
#         self.root_emb = torch.nn.Embedding(1, emb_dim)
#         self.bond_encoder = BondEncoder(emb_dim = emb_dim)

#     def forward(self, x, edge_index, edge_attr):
#         x = self.linear(x)
#         edge_embedding = self.bond_encoder(edge_attr)

#         row, col = edge_index

#         #edge_weight = torch.ones((edge_index.size(1), ), device=edge_index.device)
#         deg = degree(row, x.size(0), dtype = x.dtype) + 1
#         deg_inv_sqrt = deg.pow(-0.5)
#         deg_inv_sqrt[deg_inv_sqrt == float('inf')] = 0

#         norm = deg_inv_sqrt[row] * deg_inv_sqrt[col]

#         return self.propagate(edge_index, x=x, edge_attr = edge_embedding, norm=norm) + F.relu(x + self.root_emb.weight) * 1./deg.view(-1,1)

#     def message(self, x_j, edge_attr, norm):
#         return norm.view(-1, 1) * F.relu(x_j + edge_attr)

#     def update(self, aggr_out):
#         return aggr_out

