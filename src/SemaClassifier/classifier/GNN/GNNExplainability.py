from torch_geometric.data import Data
from torch_geometric.explain import Explainer, PGExplainer, GNNExplainer, CaptumExplainer
from torch_geometric.loader import DataLoader
from torch_geometric.explain.metric import fidelity
from torch_geometric.explain import unfaithfulness

import matplotlib.pyplot as plt
from math import sqrt
from typing import Any, Optional

import torch
from torch import Tensor

from captum.attr import DeepLift

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

# dataset = ...
# loader = DataLoader(dataset, batch_size=1, shuffle=True)

class GNNExplainability():
    def __init__(self,dataset, loader, model, mapping, fam_idx, output_path=None):
        self.dataset = dataset
        self.loader = loader
        self.model = model
        self.output_path= output_path
        self.mapping = mapping
        self.fam_idx = fam_idx

    def explain(self):
        explainer = Explainer(
            model=self.model,
            algorithm=GNNExplainer(epochs=200),
            explanation_type='phenomenon', #'model',
            node_mask_type='attributes',
            edge_mask_type='object',
            model_config=dict(
                mode='multiclass_classification',
                task_level='graph',
                return_type='log_probs',
            ),
            threshold_config=dict(threshold_type='topk', value=20),
        )

        for i in range(len(self.dataset)):
            data = self.dataset[i]
            print(data)
            explanation = explainer(data.x, data.edge_index, edge_attr=data.edge_attr, target=data.y)
            # print(explanation)
            # import pdb; pdb.set_trace()
            unfaithfulness_score = unfaithfulness(explainer, explanation)
            print(unfaithfulness_score)
            fid_pm = fidelity(explainer, explanation)
            print(fid_pm)
            pred = explainer.get_prediction(data.x, data.edge_index, data.edge_attr).argmax(dim=1).item()
            true_label = data.y.item()
            if self.output_path is not None:
                visualize_graph(explanation.x, 
                                self.mapping,
                                explanation.edge_index, 
                                explanation.edge_attr,
                                explanation.edge_mask,
                                self.output_path+f"subgraph_{i}_{self.fam_idx[true_label]}_{self.fam_idx[pred]}.png", 
                                backend="graphviz")
                # explanation.visualize_graph(self.output_path+f'subgraph_{i}_{true_label}_{pred}.png', backend="graphviz")
                # explanation.visualize_feature_importance(self.output_path+f'feature_importance_{i}_{true_label}_{pred}.png', top_k=10)
            else:
                explanation.visualize_graph(f'subgraph_{i}_{self.fam_idx[true_label]}_{self.fam_idx[pred]}.png', backend="graphviz")
                # explanation.visualize_feature_importance(f'feature_importance_{i}_{true_label}_{pred}.png', top_k=10)

    # def explain(self):
    #     explainer = Explainer(
    #         model=self.model,
    #         algorithm=PGExplainer(epochs=30, lr=0.003),
    #         explanation_type='phenomenon',
    #         edge_mask_type='object',
    #         model_config=dict(
    #             mode='multiclass_classification',
    #             task_level='graph',
    #             return_type='raw',
    #         ),
    #         # Include only the top 10 most important edges:
    #         threshold_config=dict(threshold_type='topk', value=10),
    #     )

    #     # PGExplainer needs to be trained separately since it is a parametric
    #     # explainer i.e it uses a neural network to generate explanations:
    #     for epoch in range(30):
    #         for data in self.loader:
    #             # import pdb; pdb.set_trace()
    #             loss = explainer.algorithm.train(
    #                 epoch, self.model, data.x, data.edge_index, target=data.y, batch=data.batch)

    #     # Generate the explanation for a particular graph:
        # for i in range(len(self.dataset)):
        #     explanation = explainer(self.dataset[i].x, self.dataset[i].edge_index, target=self.dataset[i].y, batch=self.dataset[i].batch)
        #     print(explanation.edge_mask)
        #     import pdb; pdb.set_trace()
        #     # fid_pm = fidelity(explainer, explanation)
        #     # print(fid_pm)
            
        #     if self.output_path is not None:
        #         explanation.visualize_graph(self.output_path+f'subgraph_{i}.png', backend="networkx")
        #         # explanation.visualize_feature_importance(self.output_path+f'features_subgraph_{i}.png', top_k=10)
        #     else:
        #         explanation.visualize_graph(f'subgraph_{i}.png', backend="networkx")
        #         # explanation.visualize_feature_importance(f'features_subgraph_{i}.png', top_k=10)

def _visualize_graph_via_graphviz(
    x: Tensor,
    mapping: dict,
    edge_index: Tensor,
    edge_attr: Tensor,
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
        g.edge(str(src), str(dst), color=f'#{hex_color}{hex_color}{hex_color}')

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
        g.add_edge(src, dst, alpha=w)

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
    edge_attr: Tensor,
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
        return _visualize_graph_via_graphviz(x, mapping, edge_index, edge_attr, edge_weight, path)

    raise ValueError(f"Expected graph drawing backend to be in "
                     f"{BACKENDS} (got '{backend}')")