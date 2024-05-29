#include <quickspan.h>
#include <history.h>
#include <common.h>

namespace quickspan {

void quickSpan::enumerate(
  const vector<Graph> &graphs,
  const DfsCodes &dfs_codes,
  const Projection &projection,
  const vector<size_t> &right_most_path,
  size_t min_label,
  ProjectionMapBackward &projection_map_backward,
  ProjectionMapForward &projection_map_forward) {
  quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
  History *history = instance->history;
  for (size_t i = 0; i < projection.size(); ++i) {
    const Graph &graph = graphs[projection[i].id];
    history->build(projection[i], graph);

    get_backward(projection[i], graph, dfs_codes, right_most_path, projection_map_backward);
    get_first_forward(projection[i], graph, dfs_codes, right_most_path, min_label, projection_map_forward);
    get_other_forward(projection[i], graph, dfs_codes, right_most_path, min_label, projection_map_forward);
  }
}

bool quickSpan::duplication_check(
    const struct edge_t *init_edge,
    const struct prev_dfs_t &init_dfs,
    const Projection &projection) {
  // Set of edges currently known?
  set<const struct edge_t *> cur_edges_set;
  // The current edge we're working with
  cur_edges_set.insert(init_edge);
  const struct prev_dfs_t *cur_dfs = &init_dfs;
  // VR: We add to the set cur_edges the previous edges of the cur_dfs
  while (cur_dfs != nullptr) {
    cur_edges_set.insert(cur_dfs->edge);
    cur_dfs = cur_dfs->prev;
  }
  // VR: For every prev_dfs inside the projection,
  // we compare its previous edges with the previous of the new one
  for (size_t k = 0; k < projection.size(); ++k) {
    if (stop) return false;
    // VR: Only prev_dfs in the same graph can have the same edges
    if (projection[k].id == init_dfs.id) {
      cur_dfs = &projection[k];
      // VR: While we haven't reach the first edge
      while (cur_dfs != nullptr) {
        auto it = cur_edges_set.find(cur_dfs->edge);
        // VR: If an edge is not found, we break and go to the next prev_dfs
        if (it == cur_edges_set.end()) { break; }
        cur_dfs = cur_dfs->prev;
      }
      // VR: If cur_dfs is null then the edges of this prev_dfs are equals to the
      // edges in the prev_dfs we're about to add
      if (cur_dfs == nullptr) { return false; }
    }
  }
  return true;
}


bool quickSpan::get_forward_init(const struct vertex_t &vertex, const Graph &graph, Edges &edges) {
  for (size_t i = 0; i < vertex.edges.size(); ++i) {
    size_t to = vertex.edges[i].to;
    const struct vertex_t *next_vertex = graph.get_p_vertex(to);
    // Partial pruning: if the first label is greater than the second label, then there must be
    // another graph whose second label is greater than the first label.
    if (vertex.label <= next_vertex->label) {
      edges.emplace_back(&(vertex.edges[i]));
    }
  }
  return !edges.empty();
}

void quickSpan::get_backward(
  const struct prev_dfs_t &prev_dfs,
  const Graph &graph,
  const DfsCodes &dfs_codes,
  const vector<size_t> &right_most_path,
  ProjectionMapBackward &projection_map_backward) {
  quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
  History *history = instance->history;
  const struct edge_t *last_edge = history->get_p_edge(right_most_path[0]);
  const struct vertex_t *last_node = graph.get_p_vertex(last_edge->to);

  for (size_t i = right_most_path.size(); i > 1; --i) {
    const struct edge_t *edge = history->get_p_edge(right_most_path[i - 1]);
    for (size_t j = 0; j < (last_node->edges).size(); ++j) {
      if (stop) { return; }
      if (history->has_edges((last_node->edges[j]).id))
        continue;
      const struct vertex_t *from_node = graph.get_p_vertex(edge->from);
      const struct vertex_t *to_node = graph.get_p_vertex(edge->to);
      if (last_node->edges[j].to == edge->from &&
          (last_node->edges[j].label > edge->label ||
           (last_node->edges[j].label == edge->label &&
             (last_node->label > to_node->label ||
               (last_node->label == to_node->label &&
                last_node->edges[j].direction >= edge->direction))))) {
        size_t from_id = dfs_codes[right_most_path[0]].to;
        size_t to_id = dfs_codes[right_most_path[i - 1]].from;
        struct dfs_code_t dfs_code(from_id, to_id,
          last_node->label, (last_node->edges[j]).label, from_node->label, (last_node->edges[j]).direction);
        if ((!remove_duplicates_) || duplication_check(&(last_node->edges[j]),prev_dfs,projection_map_backward[dfs_code])) {
          projection_map_backward[dfs_code].
            emplace_back(graph.get_id(), &(last_node->edges[j]), &(prev_dfs));
        }
      }
    }
  }
}

void quickSpan::get_first_forward(
  const struct prev_dfs_t &prev_dfs,
  const Graph &graph,
  const DfsCodes &dfs_codes,
  const vector<size_t> &right_most_path,
  size_t min_label,
  ProjectionMapForward &projection_map_forward) {
  quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
  History *history = instance->history;
  const struct edge_t *last_edge = history->get_p_edge(right_most_path[0]);
  const struct vertex_t *last_node = graph.get_p_vertex(last_edge->to);

  for (size_t i = 0; i < (last_node->edges).size(); ++i) {
    if (stop) { return; }
    const struct edge_t *edge = &(last_node->edges[i]);
    const struct vertex_t *to_node = graph.get_p_vertex(edge->to);
    // Partial pruning: if this label is less than the minimum label, then there
    // should exist another lexicographical order which renders the same letters, but
    // in the asecending order.
    // Could we perform the same partial pruning as other extending methods?
    // No, we cannot, for this time, the extending id is greater the the last node
    if (history->has_vertice(edge->to) || to_node->label < min_label)
      continue;
    size_t to_id = dfs_codes[right_most_path[0]].to;
    struct dfs_code_t dfs_code(to_id, to_id + 1,
      last_node->label, edge->label, to_node->label, edge->direction);
    if ((!remove_duplicates_) || duplication_check(edge,prev_dfs,projection_map_forward[dfs_code])) {
      projection_map_forward[dfs_code].
        emplace_back(graph.get_id(), edge, &(prev_dfs));
    }
  }
}

void quickSpan::get_other_forward(
  const struct prev_dfs_t &prev_dfs,
  const Graph &graph,
  const DfsCodes &dfs_codes,
  const vector<size_t> &right_most_path,
  size_t min_label,
  ProjectionMapForward &projection_map_forward) {
  quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
  History *history = instance->history;
  for (size_t i = 0; i < right_most_path.size(); ++i) {
    const struct edge_t *cur_edge = history->get_p_edge(right_most_path[i]);
    const struct vertex_t *cur_node = graph.get_p_vertex(cur_edge->from);
    const struct vertex_t *cur_to = graph.get_p_vertex(cur_edge->to);

    for (size_t j = 0; j < cur_node->edges.size(); ++j) {
      if (stop) { return; }
      const struct vertex_t *to_node = graph.get_p_vertex(cur_node->edges[j].to);
      // Partial pruning: guarantees that extending label is greater
      // than the minimum one
      if (history->has_vertice(to_node->id) ||
        to_node->id == cur_to->id || to_node->label < min_label)
        continue;
      if (cur_edge->label < cur_node->edges[j].label ||
          (cur_edge->label == cur_node->edges[j].label &&
            (cur_to->label < to_node->label ||
              (cur_to->label == to_node->label &&
                cur_edge->direction <= cur_node->edges[j].direction)))) {
        size_t from_id = dfs_codes[right_most_path[i]].from;
        size_t to_id = dfs_codes[right_most_path[0]].to;
        struct dfs_code_t dfs_code(from_id, to_id + 1, cur_node->label,
          cur_node->edges[j].label, to_node->label, cur_node->edges[j].direction);
        if ((!remove_duplicates_) || duplication_check(&(cur_node->edges[j]),prev_dfs,projection_map_forward[dfs_code])) {
          projection_map_forward[dfs_code].
            emplace_back(graph.get_id(), &(cur_node->edges[j]), &(prev_dfs));
        }
      }
    }
  }
}

}  // namespace quickspan
