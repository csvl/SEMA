#ifndef INCLUDE_OUTPUT_H_
#define INCLUDE_OUTPUT_H_

#include <common.h>
#include <list>
#include <string>

namespace quickspan {

class Output {
  struct data_t {
    data_t(const string &buffer, size_t support, size_t graph_id, size_t parent_tid, int parent, size_t size):
      buffer(buffer), support(support), graph_id(graph_id), parent_tid(parent_tid), parent_id(parent), size(size){}
    const string buffer;
    size_t support;
    size_t graph_id;
    size_t parent_tid;
    int parent_id;
    size_t size;
  };

 public:
  explicit Output(
    size_t increment,
    size_t max_results,
    const string &output_file, 
    bool output_parent,
    bool output_pattern
    ):
      increment_(increment),
      max_results_(max_results),
      output_file_(output_file),
      output_parent_(output_parent),
      output_pattern_(output_pattern)
    {
    omp_init_lock(&ctr_lock_);
    omp_init_lock(&write_lock_);
  }

  size_t get_new_id();

  size_t push_back(const string &str, size_t nsupport, size_t parent_tid, int parent_id, size_t size);

  void erase_graph(size_t id, size_t support);

  void save();

  void write_out();

 private:
  std::list<struct data_t> data_list_;
  size_t increment_;
  size_t max_results_;
  const string output_file_;
  bool output_parent_;
  bool output_pattern_;
  omp_lock_t ctr_lock_;
  omp_lock_t write_lock_;
  size_t id_ctr_ = 0;
  size_t list_size_ = 0;
};

}  // namespace quickspan

#endif  // INCLUDE_OUTPUT_H_
