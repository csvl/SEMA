#ifndef INCLUDE_HISTORY_H_
#define INCLUDE_HISTORY_H_

#include <common.h>
#include <graph.h>

namespace quickspan {

class History {
 public:
  History(size_t max_edges, size_t max_vertice) : edge_size_(0) {
    edges_ = new ConstEdgePointer[max_edges + 1];
    has_edges_ = new bool[max_edges + 1]();
    has_vertice_ = new bool[max_vertice + 1]();
  }

  void build(const struct prev_dfs_t &start, const Graph &graph);

  void build_edges(const struct prev_dfs_t &start, const Graph &graph);

  void build_vertice(const struct prev_dfs_t &start, const Graph &graph);

  bool has_edges(size_t index) const {
    return has_edges_[index];
  }

  bool has_vertice(size_t index) const {
    return has_vertice_[index];
  }

  const struct edge_t *get_p_edge(size_t index) const {
    return edges_[edge_size_ - index - 1];
  }

  ~History() {
    delete[] edges_;
    delete[] has_edges_;
    delete[] has_vertice_;
  }

 private:
  typedef const struct edge_t * ConstEdgePointer;
  ConstEdgePointer *edges_;
  bool *has_edges_;
  bool *has_vertice_;
  size_t edge_size_;
};

}  // namespace quickspan

#endif  // INCLUDE_HISTORY_H_
