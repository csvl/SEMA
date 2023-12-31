import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool

class GCN(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4):
        super(GCN, self).__init__()
        self.num_layers = num_layers
        self.convs = torch.nn.ModuleList()
        for i in range(num_layers):
            if i == 0:
                self.convs.append(
                    GCNConv(
                        torch.nn.Sequential(
                            torch.nn.Linear(num_features, hidden),
                            torch.nn.ReLU(),
                            torch.nn.Linear(hidden, hidden),
                        ), train_eps=False
                    )
                )
            else:
                self.convs.append(
                    GCNConv(
                        torch.nn.Sequential(
                            torch.nn.Linear(hidden, hidden),
                            torch.nn.ReLU(),
                            torch.nn.Linear(hidden, hidden),
                        )
                    )
                )
        self.fc = torch.nn.Linear(hidden * num_layers, num_classes)  # Adjust the output dimension

    def forward(self, x, edge_index, batch):
        xs = []
        for i in range(self.num_layers):
            x = F.relu(self.convs[i](x, edge_index))
            xs.append(x)
        x = torch.cat(xs, dim=1)  # Concatenate representations from all layers
        x = global_mean_pool(x, batch)
        x = self.fc(x)
        return F.log_softmax(x, dim=-1)