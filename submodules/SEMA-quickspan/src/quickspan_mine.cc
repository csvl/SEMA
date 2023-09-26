#include <quickspan.h>
#include <graph.h>
#include <common.h>
#include <sstream>
#include <fstream>

namespace quickspan {

void quickSpan::find_frequent_nodes_and_edges(const vector<Graph> &graphs) {
  unordered_map<size_t, vector<size_t> > vertex_labels;
  unordered_map<size_t, size_t> edge_labels;

  for (size_t i = 0; i < graphs.size(); ++i) {
    unordered_set<size_t> vertex_set;
    unordered_set<size_t> edge_set;
    for (size_t j = 0; j < graphs[i].size(); ++j) {
      const struct vertex_t *vertex = graphs[i].get_p_vertex(j);
      vertex_set.insert(vertex->label);
      for (size_t k = 0; k < (vertex->edges).size(); ++k) {
        edge_set.insert(vertex->edges[k].label);
      }
    }
    for (auto it = vertex_set.begin(); it != vertex_set.end(); ++it) {
      vertex_labels[*it].emplace_back(i);
    }
    for (auto it = edge_set.begin(); it != edge_set.end(); ++it) {
      ++edge_labels[*it];
    }
  }
  for (auto it = vertex_labels.begin(); it != vertex_labels.end(); ++it) {
    if (it->second.size() >= nsupport_) {
      frequent_vertex_labels_.insert(std::make_pair(it->first, it->second));
    }
  }
  for (auto it = edge_labels.begin();
    it != edge_labels.end(); ++it) {
    if (it->second >= nsupport_) {
      frequent_edge_labels_.insert(std::make_pair(it->first, it->second));
    }
  }
}

size_t quickSpan::report(const DfsCodes &dfs_codes, const Projection &projection,
  size_t nsupport, size_t prev_thread_id, int prev_graph_id) {
  quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
  Output *output = instance->output;
  size_t size = dfs_codes.size();
  // If the graph is too small to report, return now.
  if (size < min_graph_size_) {
    return output->get_new_id();
  }
  std::stringstream ss;
  // Only build the string if we're going to print it later
  if (output_pattern_) {
    Graph graph;
    build_graph(dfs_codes, graph);
    for (size_t i = 0; i < graph.size(); ++i) {
      const struct vertex_t *vertex = graph.get_p_vertex(i);
      ss << "v " << vertex->id << " " << vertex->label << std::endl;
    }
    for (size_t i = 0; i < size; ++i) {
      if (dfs_codes[i].direction != DIR_BACK) {
        ss << "e " << dfs_codes[i].from << " " << dfs_codes[i].to
          << " " << dfs_codes[i].edge_label << std::endl;
      } else {
        ss << "e " << dfs_codes[i].to << " " << dfs_codes[i].from
          << " " << dfs_codes[i].edge_label << std::endl;
      }
    }
    ss << "x: ";
    size_t prev = 0;
    for (size_t i = 0; i < projection.size(); ++i) {
      if (i == 0 || projection[i].id != prev) {
        prev = projection[i].id;
        ss << prev << " ";
      }
    }
  }
  size_t graph_id = output->push_back(ss.str(), nsupport, prev_thread_id, prev_graph_id, size);
  if (remove_parent_) {
    (quickspan_instances_ + prev_thread_id)->output->erase_graph(prev_graph_id, nsupport);
  }
  return graph_id;
}

void quickSpan::save(bool output_nodes) {
  #pragma omp parallel
  {
    quickspan_instance_t *instance = quickspan_instances_ + omp_get_thread_num();
    Output *output = instance->output;
    output->save();
  }
  // Save output for frequent nodes
  if (output_nodes) {
    string output_file_nodes = output_file_ + ".nodes";
    std::ofstream out(output_file_nodes.c_str(), std::ios_base::app);
    size_t graph_id = 0;
    for (auto it = frequent_vertex_labels_.begin(); it != frequent_vertex_labels_.end(); ++it) {
      out << "t # " << graph_id << " * " << it->second.size() << std::endl;
      out << "v 0 " + std::to_string(it->first) << std::endl;
      out << "x: ";
      for (size_t i = 0; i < it->second.size(); ++i) {
        out << it->second[i] << " ";
      }
      out << std::endl << std::endl;
      graph_id++;
    }
    out.close();
  }
}

void quickSpan::mine_subgraph(
  const vector<Graph> &graphs,
  const DfsCodes &dfs_codes,
  const Projection &projection,
  size_t prev_nsupport,
  size_t prev_thread_id,
  int prev_graph_id) {
  // Exit if we should stop, or not min DFS code
  if (stop || !is_min(dfs_codes)) { return; }
  prev_graph_id = report(dfs_codes, projection, prev_nsupport, prev_thread_id, prev_graph_id);
  // If we have reached maximum size then stop mining
  if (dfs_codes.size() == max_graph_size_) {
    // If we should stop at maximum size then tell all mining to stop.
    if (stop_at_max_) { stop = true; }
    return;
  }
  prev_thread_id = omp_get_thread_num();
  // Find right most path
  vector<size_t> right_most_path;
  build_right_most_path(dfs_codes, right_most_path);
  size_t min_label = dfs_codes[0].from_label;
  // Enumerate backward paths and forward paths by different rules
  ProjectionMapBackward projection_map_backward;
  ProjectionMapForward projection_map_forward;
  enumerate(graphs, dfs_codes, projection, right_most_path, min_label,
    projection_map_backward, projection_map_forward);
  // Recursive mining: first backward, last backward, and then last forward to the first forward
  for (auto it = projection_map_backward.begin(); it != projection_map_backward.end(); ++it) {
    Projection &projection = it->second;
    size_t nsupport = count_support(projection);
    if (nsupport < nsupport_) { continue; }
    size_t from = (it->first).from;
    size_t to = (it->first).to;
    size_t from_label = (it->first).from_label;
    size_t edge_label = (it->first).edge_label;
    size_t to_label = (it->first).to_label;
    #pragma omp task shared(graphs, dfs_codes, projection, prev_thread_id, prev_graph_id) firstprivate(nsupport)
    {
      DfsCodes dfs_codes_copy(dfs_codes);
      dfs_codes_copy.emplace_back(from, to, from_label, edge_label, to_label, (it->first).direction);
      mine_subgraph(graphs, dfs_codes_copy, projection, nsupport, prev_thread_id, prev_graph_id);
    }
  }
  for (auto it = projection_map_forward.rbegin(); it != projection_map_forward.rend(); ++it) {
    Projection &projection = it->second;
    size_t nsupport = count_support(projection);
    if (nsupport < nsupport_) { continue; }
    size_t from = (it->first).from;
    size_t to = (it->first).to;
    size_t from_label = (it->first).from_label;
    size_t edge_label = (it->first).edge_label;
    size_t to_label = (it->first).to_label;
    #pragma omp task shared(graphs, dfs_codes, projection, prev_thread_id, prev_graph_id) firstprivate(nsupport)
    {
      DfsCodes dfs_codes_copy(dfs_codes);
      dfs_codes_copy.emplace_back(from, to, from_label, edge_label, to_label, (it->first).direction);
      mine_subgraph(graphs, dfs_codes_copy, projection, nsupport, prev_thread_id, prev_graph_id);
    }
  }
  #pragma omp taskwait
}

}  // namespace quickspan
