from flwr.common import NDArrays, Scalar
from GINJKFlagClassifier import GINJKFlag
import flwr as fl
import numpy as np
import torch

import GNN_script
from utils import read_mapping, read_mapping_inverse

from collections import OrderedDict
from typing import Dict, List, Tuple

DEVICE: str = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")

class GNNClient(fl.client.NumPyClient):
    """Flower client implementing Graph Neural Networks using PyTorch."""

    def __init__(self, model, trainset, testset) -> None:
        super().__init__()
        self.model = model
        self.trainset = trainset
        self.testset = testset

    def get_parameters(self, config: Dict[str, str]) -> List[np.ndarray]:
        return [val.cpu().numpy() for _, val in self.model.state_dict().items()]
    
    def set_parameters(self, parameters: List[np.ndarray]) -> None:
        self.model.train()
        params_dict = zip(self.model.state_dict().keys(), parameters)
        state_dict = OrderedDict({k: torch.tensor(v) for k, v in params_dict})
        self.model.load_state_dict(state_dict, strict=True)

    def fit(self, parameters: List[np.ndarray], config:Dict[str,str]) -> Tuple[List[np.ndarray], int, Dict]:
        self.set_parameters(parameters)
        m, loss = GNN_script.train(self.model, self.trainset, 16, 5, DEVICE)
        return self.get_parameters(config={}), len(self.trainset), loss

    def evaluate(self, parameters: List[np.ndarray], config: Dict[str, str]
    ) -> Tuple[float, int, Dict]:
        self.set_parameters(parameters)
        accuracy, loss, y_pred = GNN_script.test(self.model, self.testset, 32, DEVICE)
        print("Client: Evaluation accuracy & loss", accuracy, loss)
        return float(loss), len(self.testset), {"accuracy": float(accuracy)}
    
def main() -> None:
    families = ["berbew","sillyp2p","benjamin","small","mira","upatre","wabot"]
    batch_size = 32
    hidden = 64
    num_classes = len(families)
    num_layers = 5
    drop_ratio = 0.5
    residual = False

    mapping = read_mapping("./mapping.txt")
    reversed_mapping = read_mapping_inverse("./mapping.txt")
    dataset, label, fam_idx, fam_dict, dataset_wl = GNN_script.init_dataset("./databases/examples_samy/BODMAS/01", families, reversed_mapping, [], {}, False)

    print(f"GNN Dataset length: {len(dataset)}")

    full_train_dataset, y_full_train, test_dataset, y_test = [], [], [], []
    train_idx, test_idx = GNN_script.split_dataset_indexes(dataset, label)
    for i in train_idx:
        full_train_dataset.append(dataset[i])
        y_full_train.append(dataset[i].y)
    for i in test_idx:
        test_dataset.append(dataset[i])
        y_test.append(dataset[i].y)

    model = GINJKFlag(full_train_dataset[0].num_node_features, hidden, num_classes, num_layers, drop_ratio=drop_ratio, residual=residual).to(DEVICE)

    client = GNNClient(model, full_train_dataset, test_dataset)
    fl.client.start_numpy_client(server_address="127.0.0.1:8080", client=client)

if __name__ == "__main__":
    main()