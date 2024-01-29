import torch
import torch.nn.functional as F
from torch_geometric.nn import global_mean_pool, global_add_pool, MessagePassing
from utils import get_graph_info, build_graph

### GIN convolution along the graph structure
class GINConv(MessagePassing):
    def __init__(self, emb_dim):
        '''
            emb_dim (int): node embedding dimensionality
        '''
        super(GINConv, self).__init__(aggr = "mean") # can change to add
        self.emb_dim = emb_dim
        self.mlp = torch.nn.Sequential(
            torch.nn.Linear(emb_dim, 2*emb_dim), 
            # torch.nn.BatchNorm1d(2*emb_dim), 
            torch.nn.ReLU(),
            torch.nn.Linear(2*emb_dim, emb_dim))
        self.eps = torch.nn.Parameter(torch.Tensor([0]))
        # self.eps = torch.nn.Parameter(torch.randn(1) * 0.01)
        
        # edge_attr is 1 dimensional after augment_edge transformation
        self.edge_encoder = torch.nn.Linear(6, emb_dim)

    def forward(self, x, edge_index, edge_attr):
        # import pdb; pdb.set_trace()
        edge_embedding = self.edge_encoder(edge_attr)
        out = self.mlp((1 + self.eps) *x + self.propagate(edge_index, x=x, edge_embedding=edge_embedding))
        return out
        # return self.propagate(edge_index, x=x, edge_embedding=edge_embedding)

    def message(self, x_j, edge_embedding):
        # import pdb; pdb.set_trace()
        return F.relu(x_j + edge_embedding)
        
    def update(self, aggr_out):
        return aggr_out

    # def message(self, x_j, edge_embedding):
    #     return F.relu(x_j + edge_embedding)
    #     # return torch.cat([x_j, edge_embedding], dim = 1)

    # def update(self, aggr_out):
    #     return self.mlp(aggr_out)

class GINJKFlag_node(torch.nn.Module):
    def __init__(self, hidden, num_classes, num_layers=4):
        super(GINJKFlag_node, self).__init__()
        self.num_layers = num_layers
        self.emb_dim = hidden
        self.hidden = hidden
        self.num_tasks = num_classes

        if self.num_layers < 2:
            raise ValueError("Number of GNN layers must be greater than 1.")
        
        self.convs = torch.nn.ModuleList()
        self.batch_norms = torch.nn.ModuleList()
        for layer in range(num_layers):
            self.convs.append(GINConv(hidden))

    def forward(self, x, edge_index, edge_attr, batch, perturb=None, edge_types=None):
        tmp = x + perturb if perturb is not None else x
        h_list = []
        h = tmp
        xs = []
        for i in range(self.num_layers):
            # Update to use R_GINConv with the correct edge_type for each layer
            # import pdb; pdb.set_trace()
            # edge_types = edge_attr.view(-1).long() - 1
            h = F.relu(self.convs[i](h, edge_index, edge_attr))
            h_list.append(h)
        node_representation = torch.cat(h_list, dim=1)  # Concatenate representations from all layers

        return node_representation

class GINJKFlag(torch.nn.Module):
    def __init__(self, hidden, num_classes, num_layers=4):
        super(GINJKFlag, self).__init__()
        self.num_layers = num_layers
        self.emb_dim = hidden
        self.hidden = hidden
        self.num_tasks = num_classes

        if self.num_layers < 2:
            raise ValueError("Number of GNN layers must be greater than 1.")
        
        self.gnn_node = GINJKFlag_node(hidden, num_classes, num_layers)

        self.pool = global_mean_pool
        # self.pool = global_add_pool

        self.graph_pred_linear = torch.nn.Linear(hidden * num_layers, num_classes)  # Adjust the output dimension
        # self.graph_pred_linear = torch.nn.Linear(hidden, num_classes)



    def forward(self, x, edge_index, edge_attr, batch, perturb=None):
        
        node_rep = self.gnn_node(x, edge_index, edge_attr, batch, perturb)
        # import pdb; pdb.set_trace()
        pooled_rep = self.pool(node_rep, batch)
        graph_rep = self.graph_pred_linear(pooled_rep)

        return F.log_softmax(graph_rep, dim=-1)