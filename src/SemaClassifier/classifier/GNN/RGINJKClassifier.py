import torch
import torch.nn.functional as F
from torch_geometric.nn import global_mean_pool, global_add_pool, MessagePassing
from .utils import get_graph_info, build_graph

### GIN convolution along the graph structure
class GINConv(MessagePassing):
    def __init__(self, emb_dim):
        '''
            emb_dim (int): node embedding dimensionality
        '''

        super(GINConv, self).__init__(aggr = "mean") # can change to add
        self.emb_dim = emb_dim
        self.mlp = torch.nn.Sequential(
            torch.nn.Linear(emb_dim, emb_dim), 
            # torch.nn.BatchNorm1d(2*emb_dim), 
            torch.nn.ReLU(),
            torch.nn.Linear(emb_dim, emb_dim))
        self.eps = torch.nn.Parameter(torch.Tensor([0]))
        
        # edge_attr is two dimensional after augment_edge transformation
        self.edge_encoder = torch.nn.Linear(1, emb_dim)

    def forward(self, x, edge_index, edge_attr):
        # import pdb; pdb.set_trace()
        edge_embedding = self.edge_encoder(edge_attr)
        out = self.mlp((1 + self.eps) *x + self.propagate(edge_index, x=x, edge_attr=edge_embedding))
    
        return out

    def message(self, x_j, edge_attr):
        return F.relu(x_j + edge_attr)
        
    def update(self, aggr_out):
        return aggr_out
    
class GIN_Triplet_unit(torch.nn.Module):
    def __init__(self, hidden, drop_ratio):
        super(GIN_Triplet_unit, self).__init__()
        self.relu = torch.nn.ReLU()
        self.conv = GINConv(hidden)
        self.drop_ratio = drop_ratio
        self.norm = torch.nn.BatchNorm1d(hidden)
    
    def forward(self, hidden, edge_index, edge_attr, add_activation=False):
        out = self.relu(hidden)
        out = self.conv(hidden, edge_index, edge_attr)
        # out = self.norm(out)
        if add_activation:
            out = self.relu(out)
        # out = F.dropout(out, p=self.drop_ratio, training=self.training)
        return out
    
class Node_OP(torch.nn.Module):
    def __init__(self, Node, hidden, drop_ratio, drop_path_p):
        super(Node_OP, self).__init__()
        self.is_input_node = Node.type == 0
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
        out = self.conv(out, input[0][1], input[0][2], input[0][3])
        return out

class StageBlock(torch.nn.Module):
    def __init__(self, net_graph, hidden, net_linear, drop_ratio, drop_path_p=0.0):
        super(StageBlock, self).__init__()
        self.nodes, self.input_nodes, self.output_nodes = get_graph_info(net_graph, net_linear)
        self.nodeop = torch.nn.ModuleList()
        for node in self.nodes:
            self.nodeop.append(Node_OP(node, hidden, drop_ratio, drop_path_p))
    
    def forward(self, hidden, edge_index, edge_attr, batch=None):
        results = {}
        for id in self.input_nodes:
            results[id] = self.nodeop[id](*[[hidden, edge_index, edge_attr, True]])

        # import pdb; pdb.set_trace()
        for id, node in enumerate(self.nodes):
            if id not in self.input_nodes:
                if id not in self.output_nodes:
                    # results[id] = self.nodeop[id](*[[hidden, edge_index, edge_attr]])
                    results[id] = self.nodeop[id](*[[results[_id], edge_index, edge_attr, True] for _id in node.inputs])
                else:
                    results[id] = self.nodeop[id](*[[results[_id], edge_index, edge_attr, False] for _id in node.inputs])
        result = results[self.output_nodes[0]]
        for idx, id in enumerate(self.output_nodes):
            if idx > 0:
                result += results[id]
        result = result / len(self.output_nodes)
        return results

class GINJK_flag_node(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4, drop_ratio=0.5, residual=False):
        super(GINJK_flag_node, self).__init__()
        self.num_layers = num_layers
        self.emb_dim = hidden
        self.num_tasks = num_classes
        self.num_features = num_features
        self.drop_ratio = drop_ratio
        self.residual = residual

        if self.num_layers < 2:
            raise ValueError("Number of GNN layers must be greater than 1.")
        
        self.convs = torch.nn.ModuleList()
        self.batch_norms = torch.nn.ModuleList()
        for layer in range(num_layers):
            # if layer == 0:
            #     nn = torch.nn.Sequential(
            #         torch.nn.Linear(hidden, hidden),
            #         torch.nn.ReLU(),
            #         torch.nn.Linear(hidden, hidden),
            #     )
            # else:
            #     nn = torch.nn.Sequential(
            #         torch.nn.Linear(hidden, hidden),
            #         torch.nn.ReLU(),
            #         torch.nn.Linear(hidden, hidden),
            #     )
            # self.convs.append(GINConv(nn))
            self.convs.append(GINConv(hidden))

        # self.graph_pred_linear = torch.nn.Linear(hidden, num_classes)


    def forward(self, x, edge_index, edge_attr, batch, perturb=None):
        tmp = x + perturb if perturb is not None else x
        h_list = []
        h = tmp
        xs = []
        for i in range(self.num_layers):
            # h = F.relu(self.convs[i](h_list[i], edge_index, edge_attr))
            # try:
            #     # h = self.convs[i](h, edge_index, edge_attr)
            #     h = F.relu(self.convs[i](h, edge_index, edge_attr))
            # except:
            #     import pdb; pdb.set_trace()
            h = F.relu(self.convs[i](h, edge_index, edge_attr))
            h_list.append(h)

            # x = F.relu(self.convs[i](x, edge_index))
            # xs.append(x)
        # x = torch.cat(xs, dim=1)  # Concatenate representations from all layers
        # node_representation = h_list[-1]
        # import pdb; pdb.set_trace()
        node_representation = torch.cat(h_list, dim=1)  # Concatenate representations from all layers

        return node_representation
    
class RanGINJK_node(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4, net_linear=False, drop_ratio=0.5, drop_path_p=0.01, edge_p=0.6, net_seed=47, residual=False):
        super(RanGINJK_node, self).__init__()
        self.num_layers = num_layers
        self.emb_dim = hidden
        self.num_tasks = num_classes
        self.num_features = num_features
        self.drop_ratio = drop_ratio
        self.residual = residual

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



    def forward(self, x, edge_index, edge_attr, batch, perturb=None):
        tmp = x + perturb if perturb is not None else x
        h_list = []
        h = tmp
        h_stage = self.stage(h, edge_index, edge_attr, batch)
        xs = []
        for layer in h_stage:
            # h = F.relu(self.convs[i](h, edge_index, edge_attr))
            # h_list.append(h)
            # hh = h_stage[i]
            hh = h_stage[layer]
            h_list.append(hh)

        node_representation = h_list[-1]
        # import pdb; pdb.set_trace()
        # node_representation = 0
        # for layer in range(self.num_layers):
        #         try:
        #             node_representation += h_list[layer]
        #         except:
        #             import pdb; pdb.set_trace()
        # node_representation = torch.cat(h_list, dim=1)  # Concatenate representations from all layers

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
        # self.gnn_node = RanGINJK_virtualnode(num_features, hidden, num_classes, num_layers)

        self.pool = global_mean_pool
        # self.pool = global_add_pool

        # self.graph_pred_linear = torch.nn.Linear(hidden * num_layers, num_classes)  # Adjust the output dimension
        self.graph_pred_linear = torch.nn.Linear(hidden, num_classes)



    def forward(self, x, edge_index, edge_attr, batch, perturb=None):
        
        node_rep = self.gnn_node(x, edge_index, edge_attr, batch, perturb)
        # import pdb; pdb.set_trace()
        pooled_rep = self.pool(node_rep, batch)
        graph_rep = self.graph_pred_linear(pooled_rep)

        return F.log_softmax(graph_rep, dim=-1)