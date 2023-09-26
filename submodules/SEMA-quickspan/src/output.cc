#include <output.h>
#include <fstream>

namespace quickspan {

size_t Output::get_new_id() {
  omp_set_lock(&ctr_lock_);
  size_t res = id_ctr_;
  id_ctr_++;
  omp_unset_lock(&ctr_lock_);
  return res;
}

size_t Output::push_back(const string &str, size_t nsupport, size_t parent_tid, int parent_id, size_t size) {
  omp_set_lock(&ctr_lock_);
  size_t res = id_ctr_;
  id_ctr_++;
  omp_unset_lock(&ctr_lock_);
  omp_set_lock(&write_lock_);
  if (max_results_ > 0 && list_size_ == max_results_) {
    std::list<struct data_t>::iterator it = data_list_.begin();
    std::list<struct data_t>::iterator del = data_list_.begin();
    while (it != data_list_.end()) {
      if (del->size > it->size) {
        del = it;
      }
      it++;
    }
    if (del->size >= size) {
      omp_unset_lock(&write_lock_);
      return res;
    }
    data_list_.erase(del);
    list_size_--;
  }
  data_t data(str, nsupport, res, parent_tid, parent_id, size);
  data_list_.emplace_back(data);
  list_size_++;
  if (list_size_ == increment_) {
    write_out();
    data_list_.clear();
    list_size_ = 0;
  }
  omp_unset_lock(&write_lock_);
  return res;
}

void Output::erase_graph(size_t id, size_t support) {
  omp_set_lock(&write_lock_);
  std::list<struct data_t>::iterator it = data_list_.begin();
  while (it != data_list_.end() && it->graph_id < id) { it++; }
  if (it != data_list_.end() && it->graph_id == id && it->support == support) {
    data_list_.erase(it);
    list_size_--;
  }
  omp_unset_lock(&write_lock_);
}

void Output::write_out() {
  std::ofstream out(output_file_.c_str(), std::ios_base::app);
  for (auto x: data_list_) {
    out << "t # " << x.graph_id << " * " << x.support << std::endl;
    if (output_parent_) {
      out << "parent : " << x.parent_id << " thread : " << x.parent_tid << std::endl;
    }
    if (output_pattern_) {
      out << x.buffer << std::endl;
    }
  }
  out.close();
}

void Output::save() {
  // Should only be called by one thread/execution anyway
  omp_set_lock(&write_lock_);
  write_out();
  omp_unset_lock(&write_lock_);
}

}  // namespace quickspan
