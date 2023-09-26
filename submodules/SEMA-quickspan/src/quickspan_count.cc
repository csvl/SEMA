#include <quickspan.h>
#include <history.h>
#include <algorithm>

namespace quickspan {

void quickSpan::build_right_most_path(const DfsCodes &dfs_codes, vector<size_t> &right_most_path) {
  int prev_id = -1;

  for (size_t i = dfs_codes.size(); i > 0; --i) {
    if (dfs_codes[i - 1].from < dfs_codes[i - 1].to &&
        (right_most_path.empty() || prev_id == static_cast<int>(dfs_codes[i - 1].to))) {
      prev_id = dfs_codes[i - 1].from;
      right_most_path.push_back(i - 1);
    }
  }
}

size_t quickSpan::count_support(const Projection &projection) {
  int prev_id = -1;
  size_t size = 0;

  for (size_t i = 0; i < projection.size(); ++i) {
    if (prev_id != static_cast<int>(projection[i].id)) {
      prev_id = projection[i].id;
      ++size;
    }
  }
  return size;
}

void quickSpan::build_graph(const DfsCodes &dfs_codes, Graph &graph) {
  size_t edge_id = 0;
  Vertice *vertice = graph.get_p_vertice();

  for (size_t i = 0; i < dfs_codes.size(); ++i) {
    // Push vertice
    vertice->resize(std::max(dfs_codes[i].from + 1, vertice->size()));
    vertice->resize(std::max(dfs_codes[i].to + 1, vertice->size()));
    (*vertice)[dfs_codes[i].from].label = dfs_codes[i].from_label;
    (*vertice)[dfs_codes[i].from].id = dfs_codes[i].from;
    (*vertice)[dfs_codes[i].to].label = dfs_codes[i].to_label;
    (*vertice)[dfs_codes[i].to].id = dfs_codes[i].to;
    // Push an edge
    struct edge_t edge(dfs_codes[i].from, dfs_codes[i].edge_label, dfs_codes[i].to, edge_id, dfs_codes[i].direction);
    (*vertice)[edge.from].edges.emplace_back(
      dfs_codes[i].from, dfs_codes[i].edge_label, dfs_codes[i].to, edge_id, dfs_codes[i].direction);
    (*vertice)[edge.to].edges.emplace_back(
      dfs_codes[i].to, dfs_codes[i].edge_label, dfs_codes[i].from, edge_id, flip_direction(dfs_codes[i].direction));
    ++edge_id;
  }
  graph.set_nedges(edge_id);
}

bool quickSpan::is_min(const DfsCodes &dfs_codes) {
  if (dfs_codes.size() == 1)
    return true;

  ProjectionMap projection_map;
  // Reuse memory, TODO: necessary or not? just set an index?
  quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
  Graph *min_graph = instance->min_graph;
  DfsCodes *min_dfs_codes = instance->min_dfs_codes;
  min_graph->clear();
  min_dfs_codes->clear();
  // Build min graph
  build_graph(dfs_codes, *min_graph);

  for (size_t i = 0; i < min_graph->size(); ++i) {
    const struct vertex_t *vertex = min_graph->get_p_vertex(i);
    Edges edges;

    if (get_forward_init(*vertex, *min_graph, edges)) {
      for (size_t j = 0; j < edges.size(); ++j) {
        // Push dfs code according to the same edge label
        const struct vertex_t *vertex_from = min_graph->get_p_vertex(edges[j]->from);
        const struct vertex_t *vertex_to = min_graph->get_p_vertex(edges[j]->to);
        struct dfs_code_t dfs_code(0, 1, vertex_from->label, edges[j]->label, vertex_to->label, edges[j]->direction);
        // Push back all the graphs
        projection_map[dfs_code].emplace_back(0, edges[j], (const prev_dfs_t *)NULL);
      }
    }
  }
  auto it = projection_map.begin();
  min_dfs_codes->emplace_back(0, 1,
    (it->first).from_label, (it->first).edge_label, (it->first).to_label, (it->first).direction);
  if (dfs_codes[min_dfs_codes->size() - 1] != (*min_dfs_codes)[min_dfs_codes->size() - 1]) {
    return false;
  }
  return is_projection_min(dfs_codes, it->second);
}

bool quickSpan::judge_backward(
  const vector<size_t> &right_most_path,
  const Projection &projection,
  size_t min_label,
  ProjectionMapBackward &projection_map_backward) {
  quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
  Graph *min_graph = instance->min_graph;
  DfsCodes *min_dfs_codes = instance->min_dfs_codes;
  History *history = instance->history;

  // i > 1, because it cannot reach the path itself
  for (size_t i = right_most_path.size(); i > 1; --i) {
    for (size_t j = 0; j < projection.size(); ++j) {
      history->build_edges(projection[j], *min_graph);

      const struct edge_t *edge = history->get_p_edge(right_most_path[i - 1]);
      const struct edge_t *last_edge = history->get_p_edge(right_most_path[0]);
      const struct vertex_t *from_node = min_graph->get_p_vertex(edge->from);
      const struct vertex_t *last_node = min_graph->get_p_vertex(last_edge->to);
      const struct vertex_t *to_node = min_graph->get_p_vertex(edge->to);

      for (size_t k = 0; k < last_node->edges.size(); ++k) {
        if (history->has_edges(last_node->edges[k].id))
          continue;
        if (last_node->edges[k].to == edge->from &&
            (last_node->edges[k].label > edge->label ||
             (last_node->edges[k].label == edge->label &&
              last_node->label >= to_node->label))) {
          size_t from_id = (*min_dfs_codes)[right_most_path[0]].to;
          size_t to_id = (*min_dfs_codes)[right_most_path[i - 1]].from;
          struct dfs_code_t dfs_code(from_id, to_id,
            last_node->label, (last_node->edges[k]).label, from_node->label, (last_node->edges[k]).direction);
          if ((!remove_duplicates_) || duplication_check(&(last_node->edges[k]), (projection[j]),projection_map_backward[dfs_code])) {
            projection_map_backward[dfs_code].emplace_back(0, &(last_node->edges[k]), &(projection[j]));
          }
        }
      }
    }
    if (projection_map_backward.size() != 0)
      return true;
  }
  return false;
}


bool quickSpan::judge_forward(
  const vector<size_t> &right_most_path,
  const Projection &projection,
  size_t min_label,
  ProjectionMapForward &projection_map_forward) {
  quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
  Graph *min_graph = instance->min_graph;
  History *history = instance->history;
  DfsCodes *min_dfs_codes = instance->min_dfs_codes;

  for (size_t i = 0; i < projection.size(); ++i) {
    history->build_vertice(projection[i], *min_graph);

    const struct edge_t *last_edge = history->get_p_edge(right_most_path[0]);
    const struct vertex_t *last_node = min_graph->get_p_vertex(last_edge->to);

    for (size_t j = 0; j < (last_node->edges).size(); ++j) {
      const struct edge_t *edge = &(last_node->edges[j]);
      const struct vertex_t *to_node = min_graph->get_p_vertex(edge->to);
      if (history->has_vertice(edge->to) || to_node->label < min_label)
        continue;
      size_t to_id = (*min_dfs_codes)[right_most_path[0]].to;
      struct dfs_code_t dfs_code(to_id, to_id + 1, last_node->label, edge->label, to_node->label, edge->direction);
      if ((!remove_duplicates_) || duplication_check(edge, projection[i], projection_map_forward[dfs_code])) {
        projection_map_forward[dfs_code].emplace_back(0, edge, &(projection[i]));
      }
    }
  }

  if (projection_map_forward.size() == 0) {
    for (size_t i = 0; i < right_most_path.size(); ++i) {
      for (size_t j = 0; j < projection.size(); ++j) {
        history->build_vertice(projection[j], *min_graph);

        const struct edge_t *cur_edge = history->get_p_edge(right_most_path[i]);
        const struct vertex_t *cur_node = min_graph->get_p_vertex(cur_edge->from);
        const struct vertex_t *cur_to = min_graph->get_p_vertex(cur_edge->to);

        for (size_t k = 0; k < cur_node->edges.size(); ++k) {
          const struct vertex_t *to_node = min_graph->get_p_vertex(cur_node->edges[k].to);
          if (history->has_vertice(to_node->id) || cur_edge->to == to_node->id || to_node->label < min_label)
            continue;
          if (cur_edge->label < cur_node->edges[k].label ||
              (cur_edge->label == cur_node->edges[k].label &&
               cur_to->label <= to_node->label)) {
            size_t from_id = (*min_dfs_codes)[right_most_path[i]].from;
            size_t to_id = (*min_dfs_codes)[right_most_path[0]].to;
            struct dfs_code_t dfs_code(from_id, to_id + 1,
              cur_node->label, cur_node->edges[k].label, to_node->label, cur_node->edges[k].direction);
            if ((!remove_duplicates_) || duplication_check(&(cur_node->edges[k]), (projection[j]), projection_map_forward[dfs_code])) {
              projection_map_forward[dfs_code].emplace_back(0, &(cur_node->edges[k]), &(projection[j]));
            }
          }
        }
      }
      if (projection_map_forward.size() != 0) {
        break;
      }
    }
  }
  if (projection_map_forward.size() != 0)
    return true;
  else 
    return false;
}

bool quickSpan::is_projection_min(const DfsCodes &dfs_codes, const Projection &projection) {
  quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
  DfsCodes *min_dfs_codes = instance->min_dfs_codes;
  vector<size_t> right_most_path;
  ProjectionMapBackward projection_map_backward;

  build_right_most_path((*min_dfs_codes), right_most_path);
  size_t min_label = (*min_dfs_codes)[0].from_label;

  if (judge_backward(right_most_path, projection, min_label, projection_map_backward)) {
    auto it = projection_map_backward.begin();
    min_dfs_codes->emplace_back((it->first).from, (it->first).to,
      (it->first).from_label, (it->first).edge_label, (it->first).to_label, (it->first).direction);
    // Dfs code not equals to min dfs code
    if (dfs_codes[min_dfs_codes->size() - 1] != (*min_dfs_codes)[min_dfs_codes->size() - 1]) {
      return false;
    }
    return is_projection_min(dfs_codes, it->second);
  }

  ProjectionMapForward projection_map_forward;

  if (judge_forward(right_most_path, projection, min_label, projection_map_forward)) {
    auto it = projection_map_forward.begin();
    min_dfs_codes->emplace_back((it->first).from, (it->first).to,
      (it->first).from_label, (it->first).edge_label, (it->first).to_label, (it->first).direction);
    // Dfs code not equals to min dfs code
    if (dfs_codes[min_dfs_codes->size() - 1] != (*min_dfs_codes)[min_dfs_codes->size() - 1]) {
      return false;
    }
    return is_projection_min(dfs_codes, it->second);
  }
  return true;
}

}  // namespace quickspan
