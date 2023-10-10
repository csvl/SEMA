import torch
import torch.nn.functional as F
from torch_geometric.nn import GINConv, global_mean_pool
from .utils import get_graph_info, build_graph


class GIN_Triplet_unit(torch.nn.Module):
    def __init__(self, hidden, drop_ratio):
        super(GIN_Triplet_unit, self).__init__()
        self.relu = torch.nn.ReLU()
        self.conv = GINConv(
            torch.nn.Sequential(
                torch.nn.Linear(hidden, hidden),
                torch.nn.ReLU(),
                torch.nn.Linear(hidden, hidden),
            )
        )
        self.drop_ratio = drop_ratio
        self.norm = torch.nn.BatchNorm1d(hidden)
    
    def forward(self, hidden, edge_index, add_activation=False):
        out = self.relu(hidden)
        out = self.conv(hidden, edge_index)
        out = self.norm(out)
        if add_activation:
            out = self.relu(out)
        out = F.dropout(out, p=self.drop_ratio, training=self.training)
        return out
    
class Node_OP(torch.nn.Module):
    def __init__(self, Node, hidden, drop_ratio, drop_path_p):
        super(Node_OP, self).__init__()
        self.is_input_node = Node.type == 'input'
        self.input_nums = len(Node.inputs)
        self.drop_path_p = drop_path_p
        if self.input_nums > 1:
            self.mean_weight = torch.nn.Parameter(torch.ones(self.input_nums))
            self.sigmoid = torch.nn.Sigmoid()
        
        self.conv = GIN_Triplet_unit(hidden, drop_ratio)
        self.drop_ratio = drop_ratio
    
    def forward(self, *input):
        if self.input_nums > 1:
            if torch.rand(1) < self.drop_path_p:
                out = 0.0*input[0][0]
            else:
                out = self.sigmoid(self.mean_weight[0])*input[0][0]
                # out = self.mean_weight[1]*input[0][1]
            for i in range(1, self.input_nums):
                if torch.rand(1) > self.drop_path_p:
                    # aa = self.sigmoid(self.mean_weight[i])*input[i][0]

                    out += self.sigmoid(self.mean_weight[i])*input[i][0]
                    # out += self.mean_weight[i]*input[i][1]
        else:
            out = input[0][0]
        
        out = self.conv(out, input[0][1])
        return out
    
class StageBlock(torch.nn.Module):
    def __init__(self, net_graph, hidden, net_linear, drop_ratio, drop_path_p=0.0):
        super(StageBlock, self).__init__()
        self.nodes, self.input_nodes, self.output_nodes = get_graph_info(net_graph, net_linear)
        self.nodeop = torch.nn.ModuleList()
        for node in self.nodes:
            self.nodeop.append(Node_OP(node, hidden, drop_ratio, drop_path_p))
    
    def forward(self, hidden, edge_index, batch:None):
        results = {}
        for id in self.input_nodes:
            results[id] = self.nodeop[id](*[[hidden, edge_index]])

        for id, node in enumerate(self.nodes):
            if id not in self.input_nodes:
                if id not in self.output_nodes:
                    results[id] = self.nodeop[id](*[[hidden, edge_index]])
                else:
                    results[id] = self.nodeop[id](*[[results[_id], edge_index] for _id in node.inputs])
        result = results[self.output_nodes[0]]
        for idx, id in enumerate(self.output_nodes):
            if idx > 0:
                result += results[id]
        result = result / len(self.output_nodes)
        return result
                        
class RanGINJK_node(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4, net_linear=False, drop_ratio=0.5, drop_path_p=0.01, edge_p=0.6, net_seed=47):
        super(RanGINJK_node, self).__init__()
        self.num_layers = num_layers
        self.emb_dim = hidden
        self.num_tasks = num_classes
        self.num_features = num_features

        if self.num_layers < 2:
            raise ValueError("Number of GNN layers must be greater than 1.")
        
        self.convs = torch.nn.ModuleList()
        self.net_linear = net_linear
        self.drop_path_p = drop_path_p
        self.net_args = {'graph_model': "ER",
                         'P': edge_p,
                         'seed': net_seed,
                         'net_linear': net_linear}
        net_graph = build_graph(self.num_layers-1, self.net_args)
        self.stage = StageBlock(net_graph, hidden, net_linear, drop_ratio, drop_path_p)


    def forward(self, x, edge_index, batch):
        
        h_list = [x]
        h_stage = self.stage(x, edge_index, batch)

        for layer in h_stage:
            # hh = self.convs[layer](h_list[layer], edge_index)
            hh = h_stage[layer]
            h_list.append(hh)
            

        node_representation = h_list[-1]
        return node_representation

class RanGINJK(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4):
        super(RanGINJK, self).__init__()
        self.num_layers = num_layers
        self.emb_dim = hidden
        self.num_tasks = num_classes
        self.num_features = num_features

        if self.num_layers < 2:
            raise ValueError("Number of GNN layers must be greater than 1.")
        
        self.gnn_node = RanGINJK_node(num_features, hidden, num_classes, num_layers)

        self.pool = global_mean_pool

        self.graph_pred_linear = torch.nn.Linear(hidden * num_layers, num_classes)  # Adjust the output dimension


    def forward(self, x, edge_index, batch):
        
        node_rep = self.gnn_node(x, edge_index, batch)
        pooled_rep = self.pool(node_rep, batch)
        graph_rep = self.graph_pred_linear(pooled_rep)

        return F.log_softmax(graph_rep, dim=-1)
    

class RanGINJK_virtualnode(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4, drop_ratio=0.5, residual=False):
        super(RanGINJK_virtualnode, self).__init__()
        self.num_layers = num_layers
        self.emb_dim = hidden
        self.num_tasks = num_classes
        self.num_features = num_features
        self.drop_ratio = drop_ratio
        self.residual = residual

        if self.num_layers < 2:
            raise ValueError("Number of GNN layers must be greater than 1.")
        
        ### set the initial virtual node embedding to 0.
        self.virtualnode_embedding = torch.nn.Embedding(1, hidden)
        torch.nn.init.constant_(self.virtualnode_embedding.weight.data, 0)


        self.convs = torch.nn.ModuleList()

        self.mlp_virtualnode_list = torch.nn.ModuleList()

        for layer in range(num_layers):
            self.convs.append(GINConv(hidden))
        
        for layer in range(num_layers - 1):
            self.mlp_virtualnode_list.append(
                torch.nn.Sequential(
                    torch.nn.Linear(hidden, hidden), 
                    torch.nn.ReLU(),
                    torch.nn.Linear(hidden, hidden), 
                    torch.nn.ReLU()
                    ))
    
    def forward(self, x, edge_index, edge_attr, batch, perturb=None):

        virtualnode_embedding = self.virtualnode_embedding(torch.zeros(batch[-1].item() + 1).to(edge_index.dtype).to(edge_index.device))
        tmp = x + perturb if perturb is not None else x
        h_list = []
        h = tmp

        for i in range(self.num_layers):
            h = h + virtualnode_embedding[batch]
            h = self.convs[i](h, edge_index, edge_attr)
            h_list.append(h)


            if i < self.num_layers - 1:
                    ### add message from graph nodes to virtual nodes
                    virtualnode_embedding_temp = global_add_pool(h_list[i], batch) + virtualnode_embedding
                    ### transform virtual nodes using MLP

                    if self.residual:
                        virtualnode_embedding = virtualnode_embedding + F.dropout(self.mlp_virtualnode_list[i](virtualnode_embedding_temp), self.drop_ratio, training = self.training)
                    else:
                        virtualnode_embedding = F.dropout(self.mlp_virtualnode_list[i](virtualnode_embedding_temp), self.drop_ratio, training = self.training)
        node_representation = torch.cat(h_list, dim=1)  # Concatenate representations from all layers
        return node_representation
    