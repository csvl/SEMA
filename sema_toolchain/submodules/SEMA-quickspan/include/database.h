#ifndef INCLUDE_DATABASE_H_
#define INCLUDE_DATABASE_H_

#include <common.h>
#include <vector>
#include <string>

namespace quickspan {

class Graph;

class Database {
 public:
  static Database *get_instance() {
    return instance_;
  }

  // Return graph count
  void read_input(const string &input_file, const string &separator);

  // Construct graph
  void construct_graphs(vector<Graph> &graphs, bool directed);

  // Construct graph by frequent labels
  void construct_graphs(
    const unordered_map<size_t, std::vector<size_t> > &frequent_vertex_labels,
    const unordered_map<size_t, size_t> &frequent_edge_labels,
    vector<Graph> &graphs,
    bool directed);

  ~Database() {
    delete instance_;
  }

 private:
  Database() {}

 private:
  static Database *instance_;
  vector<vector<string> > input_;
  size_t num_graph_;
};

}  // namespace quickspan

#endif  // INCLUDE_DATABASE_H_
