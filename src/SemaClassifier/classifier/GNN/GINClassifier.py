import torch
import torch.nn.functional as F
from torch_geometric.nn import GINConv, global_mean_pool


class GIN(torch.nn.Module):
    def __init__(self, num_features, hidden, num_classes, num_layers=4):
        super(GIN, self).__init__()
        self.conv1 = GINConv(
            torch.nn.Sequential(
                torch.nn.Linear(num_features, hidden),
                torch.nn.ReLU(),
                torch.nn.Linear(hidden, hidden),
            ), train_eps=False)
        self.convs = torch.nn.ModuleList()
        for i in range(num_layers - 1):
            self.convs.append(
                GINConv(
                    torch.nn.Sequential(
                        torch.nn.Linear(hidden, hidden),
                        torch.nn.ReLU(),
                        torch.nn.Linear(hidden, hidden),
                    )))
        self.fc = torch.nn.Linear(hidden, num_classes) 

    def forward(self, x, edge_index, batch):
        x = F.relu(self.conv1(x, edge_index))
        for conv in self.convs:
            x = F.relu(conv(x, edge_index))
        x = global_mean_pool(x, batch)
        x = self.fc(x)
        return F.log_softmax(x, dim=-1)