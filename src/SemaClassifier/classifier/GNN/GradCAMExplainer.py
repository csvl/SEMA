from dig.xgraph.dataset import SynGraphDataset
from dig.xgraph.models import *
import torch
from torch_geometric.data import DataLoader
from torch_geometric.data import Data, InMemoryDataset, download_url, extract_zip
import os.path as osp
import os

import torch.nn.functional as F
import torch_geometric.transforms as T
from torch_geometric.datasets import Planetoid
from dig.xgraph.models import GCN_2l

from torch_geometric.explain import Explainer, GNNExplainer
from torch_geometric.utils import add_self_loops
import matplotlib.pyplot as plt
from math import sqrt
from typing import Any, Optional

import torch
from torch import Tensor

from dig.xgraph.method import GradCAM
from dig.xgraph.evaluation import XCollector, ExplanationProcessor


device = torch.device('cuda:0' if torch.cuda.is_available() else 'cpu')


class GradCAMExplainer():
    def __init__(self,dataset, loader, model, mapping, fam_idx, output_path=None):
        self.dataset = dataset
        self.loader = loader
        self.model = model
        self.output_path= output_path
        self.mapping = mapping
        self.fam_idx = fam_idx

    def explain(self):
        explainer = GradCAM(self.model, explain_graph=True)
        
        sparsity = 0.5
        x_collector = XCollector(sparsity)
        # x_processor = ExplanationProcessor(model=model, device=device)


        for i in range(len(self.dataset)):
            data = self.dataset[i]
            print(data)
            
            _, explanation, related_preds = explainer(data.x, data.edge_index, edge_attr=data.edge_attr, batch=data.batch, num_classes=len(self.fam_idx))
            print("EXPLANATION : ", explanation)
            import pdb; pdb.set_trace()
            pred = explainer.get_prediction(data.x, data.edge_index, data.edge_attr, data.batch).argmax(dim=1).item()
            true_label = data.y.item()
            # unfaithfulness_score = unfaithfulness(explainer, explanation)
            # print(unfaithfulness_score)
            # fid_pm = fidelity(explainer, explanation)
            # print(fid_pm)
            if self.output_path is not None:
                visualize_graph(explanation.x, 
                                self.mapping,
                                explanation.edge_index, 
                                explanation.edge_mask,
                                self.output_path+f"subgraph_{i}_{self.fam_idx[true_label]}_{self.fam_idx[pred]}.png", 
                                backend="networkx")
                # explanation.visualize_graph(self.output_path+f'subgraph_{i}_{true_label}_{pred}.png', backend="graphviz")
                # explanation.visualize_feature_importance(self.output_path+f'feature_importance_{i}_{true_label}_{pred}.png', top_k=10)
            else:
                explanation.visualize_graph(f'subgraph_{i}_{self.fam_idx[true_label]}_{self.fam_idx[pred]}.png', backend="networkx")
                # explanation.visualize_feature_importance(f'feature_importance_{i}_{true_label}_{pred}.png', top_k=10)


BACKENDS = {'graphviz', 'networkx'}


def has_graphviz() -> bool:
    try:
        import graphviz
    except ImportError:
        return False

    try:
        graphviz.Digraph().pipe()
    except graphviz.backend.ExecutableNotFound:
        return False

    return True

def _visualize_graph_via_graphviz(
    x: Tensor,
    mapping: dict,
    edge_index: Tensor,
    edge_weight: Tensor,
    path: Optional[str] = None,
) -> Any:
    import graphviz

    suffix = path.split('.')[-1] if path is not None else None
    g = graphviz.Digraph('graph', format=suffix)
    g.attr('node', shape='circle', fontsize='11pt')

    for node in edge_index.view(-1).unique().tolist():
        # import pdb; pdb.set_trace()
        node_feat = x[node].item()
        g.node(str(node), label=f"idx {str(node)}; "+str(mapping[node_feat]))

    for (src, dst), w in zip(edge_index.t().tolist(), edge_weight.tolist()):
        hex_color = hex(255 - round(255 * w))[2:]
        hex_color = f'{hex_color}0' if len(hex_color) == 1 else hex_color
        g.edge(str(src), str(dst), label="aaaaa", attrs="bbbb", color=f'#{hex_color}{hex_color}{hex_color}')

    if path is not None:
        path = '.'.join(path.split('.')[:-1])
        g.render(path, cleanup=True)
    else:
        g.view()

    return g

def _visualize_graph_via_networkx(
    x: Tensor,
    mapping: dict,
    edge_index: Tensor,
    edge_weight: Tensor,
    path: Optional[str] = None,
) -> Any:
    import matplotlib.pyplot as plt
    import networkx as nx

    g = nx.DiGraph()
    node_size = 800
    labels = {}

    for node in edge_index.view(-1).unique().tolist():
        node_feat = x[node].item()
        g.add_node(node, label=str(mapping[node_feat]))
        labels.update({node: str(mapping[node_feat])})
        # g.add_node(node)

    for (src, dst), w in zip(edge_index.t().tolist(), edge_weight.tolist()):
        g.add_edge(src, dst, label="boooo", alpha=w)

    ax = plt.gca()
    pos = nx.spring_layout(g)
    for src, dst, data in g.edges(data=True):
        ax.annotate(
            '',
            xy=pos[src],
            xytext=pos[dst],
            arrowprops=dict(
                arrowstyle="->",
                alpha=data['alpha'],
                shrinkA=sqrt(node_size) / 2.0,
                shrinkB=sqrt(node_size) / 2.0,
                connectionstyle="arc3,rad=0.1",
            ),
        )

    nodes = nx.draw_networkx_nodes(g, pos, node_size=node_size,
                                   node_color='white', margins=0.1)
    nodes.set_edgecolor('black')
    nx.draw_networkx_labels(g, pos, labels=labels, font_size=10)

    if path is not None:
        plt.savefig(path)
    else:
        plt.show()

    plt.close()

def visualize_graph(
    x: Tensor,
    mapping: dict,
    edge_index: Tensor,
    edge_weight: Optional[Tensor] = None,
    path: Optional[str] = None,
    backend: Optional[str] = None,
) -> Any:
    r"""Visualizes the graph given via :obj:`edge_index` and (optional)
    :obj:`edge_weight`.

    Args:
        edge_index (torch.Tensor): The edge indices.
        edge_weight (torch.Tensor, optional): The edge weights.
        path (str, optional): The path to where the plot is saved.
            If set to :obj:`None`, will visualize the plot on-the-fly.
            (default: :obj:`None`)
        backend (str, optional): The graph drawing backend to use for
            visualization (:obj:`"graphviz"`, :obj:`"networkx"`).
            If set to :obj:`None`, will use the most appropriate
            visualization backend based on available system packages.
            (default: :obj:`None`)
    """
    if edge_weight is not None:  # Normalize edge weights.
        edge_weight = edge_weight - edge_weight.min()
        edge_weight = edge_weight / edge_weight.max()

    if edge_weight is not None:  # Discard any edges with zero edge weight:
        mask = edge_weight > 1e-7
        edge_index = edge_index[:, mask]
        edge_weight = edge_weight[mask]

    if edge_weight is None:
        edge_weight = torch.ones(edge_index.size(1))

    if backend is None:
        backend = 'graphviz' if has_graphviz() else 'networkx'

    if backend.lower() == 'networkx':
        return _visualize_graph_via_networkx(x, mapping, edge_index, edge_weight, path)
    elif backend.lower() == 'graphviz':
        return _visualize_graph_via_graphviz(x, mapping, edge_index, edge_weight, path)

    raise ValueError(f"Expected graph drawing backend to be in "
                     f"{BACKENDS} (got '{backend}')")