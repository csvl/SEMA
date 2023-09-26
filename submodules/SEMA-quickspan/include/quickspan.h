#ifndef INCLUDE_QUICKSPAN_H_
#define INCLUDE_QUICKSPAN_H_

#include <common.h>
#include <graph.h>
#include <history.h>
#include <output.h>
#include <map>
#include <vector>
#include <string>
#include <signal.h>

namespace quickspan {

struct Version{
  static const std::string version;
};

struct quickspan_instance_t {
  Graph *min_graph = 0;
  DfsCodes *min_dfs_codes = 0;
  History *history = 0;
  Output *output = 0;

  ~quickspan_instance_t() {
    delete this->min_graph;
    delete this->min_dfs_codes;
    delete this->history;
    delete this->output;
  }
};

class quickSpan {
 public:
  quickSpan(
    int biggest_subgraphs,
    bool directed_graphs,
    int max_graph_size,
    int min_graph_size,
    const string &output_file,
    int output_increment,
    bool parent,
    bool pattern,
    bool remove_duplicates,
    bool remove_parent,
    double support,
    bool stop_at_max
    ) :
    biggest_subgraphs_(biggest_subgraphs),
    directed_graphs_(directed_graphs),
    max_graph_size_(max_graph_size),
    min_graph_size_(min_graph_size),
    output_file_(output_file),
    output_increment_(output_increment),
    parent_(parent),
    output_pattern_(pattern),
    remove_duplicates_(remove_duplicates),
    remove_parent_(remove_parent),
    support_(support),
    stop_at_max_(stop_at_max),
    output_frequent_nodes_(0),
    quickspan_instances_(0)
    {}

  void execute();

  void save(bool output_nodes);

  void stopExec(int signum) {
    LOG(INFO) << "Signal received, halting mining and producing output...";
    if(signum == SIGINT || signum == SIGTERM || signum == SIGALRM) {
      stop = true;
    }
  }

  ~quickSpan() {
    if (quickspan_instances_ != 0) {
      delete[] quickspan_instances_;
    }
    if (output_frequent_nodes_ != 0) {
      delete output_frequent_nodes_;
    }
  }

 private:
  
  typedef map<struct dfs_code_t, Projection, struct dfs_code_project_compare_t> ProjectionMap;
  typedef map<struct dfs_code_t, Projection, struct dfs_code_backward_compare_t> ProjectionMapBackward;
  typedef map<struct dfs_code_t, Projection, struct dfs_code_forward_compare_t> ProjectionMapForward;

 private:
  // Mine
  void init_instances(const vector<Graph> &graphs);

  void project(const vector<Graph> &graphs);

  void find_frequent_nodes_and_edges(const vector<Graph> &graphs);

  void mine_subgraph(
    const vector<Graph> &graphs,
    const DfsCodes &dfs_codes,
    const Projection &projection,
    size_t prev_nsupport,
    size_t prev_thread_id,
    int prev_graph_id);

  // Extend
  void build_right_most_path(const DfsCodes &dfs_codes, vector<size_t> &right_most_path);

  void enumerate(
    const vector<Graph> &graphs,
    const DfsCodes &dfs_codes,
    const Projection &projection,
    const vector<size_t> &right_most_path,
    size_t min_label,
    ProjectionMapBackward &projection_map_backward,
    ProjectionMapForward &projection_map_forward);

  bool duplication_check(
    const struct edge_t *init_edge,
    const struct prev_dfs_t &init_dfs,
    const Projection &projection);

  bool get_forward_init(
    const struct vertex_t &vertex,
    const Graph &graph,
    Edges &edges);

  void get_first_forward(
    const struct prev_dfs_t &prev_dfs,
    const Graph &graph,
    const DfsCodes &dfs_codes,
    const vector<size_t> &right_most_path,
    size_t min_label,
    ProjectionMapForward& projection_map_forward);

  void get_other_forward(
    const struct prev_dfs_t &prev_dfs,
    const Graph &graph,
    const DfsCodes &dfs_codes,
    const vector<size_t> &right_most_path,
    size_t min_label,
    ProjectionMapForward& projection_map_forward);

  void get_backward(
    const struct prev_dfs_t &prev_dfs,
    const Graph &graph,
    const DfsCodes &dfs_codes,
    const vector<size_t> &right_most_path,
    ProjectionMapBackward& projection_map_backward);

  // Count
  size_t count_support(const Projection &projection);

  void build_graph(const DfsCodes &dfs_codes, Graph &graph);

  bool is_min(const DfsCodes &dfs_codes);

  bool is_projection_min(const DfsCodes &dfs_codes, const Projection &projection);

  bool judge_backward(
    const vector<size_t> &right_most_path,
    const Projection &projection,
    size_t min_label,
    ProjectionMapBackward &projection_map_backward);

  bool judge_forward(
    const vector<size_t> &right_most_path,
    const Projection &projection,
    size_t min_label,
    ProjectionMapForward &projection_map_forward);

  // Report
  size_t report(const DfsCodes &dfs_codes, const Projection &projection,
    size_t nsupport, size_t prev_thread_id, int prev_graph_id);

 private:
  // Graphs after reconstructing
  vector<Graph> graphs_;
  // Single instance of minigraph
  unordered_map<size_t, vector<size_t> > frequent_vertex_labels_;
  unordered_map<size_t, size_t> frequent_edge_labels_;
  // Parameters from instantiation
  size_t biggest_subgraphs_; /*!< How many subgraphs to keep per instance*/
  bool directed_graphs_; /*<! Whether or not to consider edges directed*/
  size_t max_graph_size_; /*!< Maximum graph size to mine for*/
  size_t min_graph_size_; /*!< Minimum graph size to mine for*/
  string output_file_;
  size_t output_increment_; /*!< How many graphs to output per increment*/
  bool parent_; /*!< Whether to output parent IDs */
  bool output_pattern_; /*!< Whether to build patterns for output*/
  bool remove_duplicates_; /*<! Remove duplicate graphs flag*/
  bool remove_parent_; /*<! Remove parent graphs with the same support*/
  // Algorithmic parameters
  double support_;
  bool stop_at_max_; /*<! Stop mining if max_graph_size is found */
  size_t nsupport_;
  // Stop parameter, used to halt when interrupted or timed out
  bool stop = false;
  // ??
  Output *output_frequent_nodes_;
  quickspan_instance_t *quickspan_instances_;
};

}  // namespace quickspan

#endif  // INCLUDE_QUICKSPAN_H_
