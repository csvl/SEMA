#ifndef INCLUDE_COMMON_H_
#define INCLUDE_COMMON_H_

#include <sys/time.h>
#include <omp.h>
#include <glog/logging.h>
#include <config.h>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <set>
#include <vector>

#define FILE_MAX_LINE 1024

#define CPU_TIMER_START(elapsed_time, t1) \
  do { \
    elapsed_time = 0.0; \
    gettimeofday(&t1, NULL); \
  } while (0)

#define CPU_TIMER_END(elapsed_time, t1, t2) \
  do { \
    gettimeofday(&t2, NULL); \
    elapsed_time = (t2.tv_sec - t1.tv_sec) * 1000.0; \
    elapsed_time += (t2.tv_usec - t1.tv_usec) / 1000.0; \
    elapsed_time /= 1000.0; \
  } while (0)

namespace quickspan {

using std::map;
using std::unordered_map;
using std::string;
using std::set;
using std::unordered_set;
using std::vector;

}  // namespace quickspan

#endif  // INCLUDE_COMMON_H_
