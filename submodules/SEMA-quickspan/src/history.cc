#include <history.h>
#include <graph.h>
#include <algorithm>

namespace quickspan {

// Reduce push back memory costs
// while (cur_dfs != NULL) {
//   edges_.push_back(cur_dfs->edge);
//   has_edges_[cur_dfs->edge->id] = true;
//   has_vertice_[cur_dfs->edge->from] = true;
//   has_vertice_[cur_dfs->edge->to] = true;
//   cur_dfs = cur_dfs->prev;
// }
void History::build(const struct prev_dfs_t &start, const Graph &graph) {
  const struct prev_dfs_t *cur_dfs = &start;
  memset(has_edges_, false, sizeof(bool) * graph.get_nedges() + 1);
  memset(has_vertice_, false, sizeof(bool) * graph.size() + 1);
  edge_size_ = 0;

  // Reduce push back memory costs
  while (cur_dfs != NULL) {
    edges_[edge_size_++] = cur_dfs->edge;
    has_edges_[cur_dfs->edge->id] = true;
    has_vertice_[cur_dfs->edge->from] = true;
    has_vertice_[cur_dfs->edge->to] = true;
    cur_dfs = cur_dfs->prev;
  }
}

void History::build_edges(const struct prev_dfs_t &start, const Graph &graph) {
  const struct prev_dfs_t *cur_dfs = &start;
  memset(has_edges_, false, sizeof(bool) * graph.get_nedges() + 1);
  edge_size_ = 0;

  // Reduce push back memory costs
  while (cur_dfs != NULL) {
    edges_[edge_size_++] = cur_dfs->edge;
    has_edges_[cur_dfs->edge->id] = true;
    cur_dfs = cur_dfs->prev;
  }
}

void History::build_vertice(const struct prev_dfs_t &start, const Graph &graph) {
  const struct prev_dfs_t *cur_dfs = &start;
  memset(has_vertice_, false, sizeof(bool) * graph.size() + 1);
  edge_size_ = 0;

  // Reduce push back memory costs
  while (cur_dfs != NULL) {
    edges_[edge_size_++] = cur_dfs->edge;
    has_vertice_[cur_dfs->edge->from] = true;
    has_vertice_[cur_dfs->edge->to] = true;
    cur_dfs = cur_dfs->prev;
  }
}

}  // namespace quickspan
