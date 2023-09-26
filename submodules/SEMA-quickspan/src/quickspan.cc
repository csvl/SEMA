#include <quickspan.h>
#include <database.h>
#include <common.h>
#include <gflags/gflags.h>

DEFINE_string(input_file, "", "Input path of graph data");
DEFINE_string(output_file, "", "Output quickspan mining results");
DEFINE_double(support, 1.0, "Minimum subgraph frequency: (0.0, 1.0)");
DEFINE_string(separator, " ", "Graph data separator");
DEFINE_bool(parent, false, "Output subgraph parent ids");
DEFINE_bool(pattern, false, "Output subgraph patterns");
DEFINE_bool(nodes, false, "Output frequent nodes");
// New quickSpan arguments below
DEFINE_int32(biggest_subgraphs, 0, "Output only the N biggest subgraphs");
DEFINE_bool(directed_graphs, false, "Consider graph edges to be directed");
DEFINE_int32(min_graph_size, 0 , "Maximum graph size to mine for");
DEFINE_int32(max_graph_size, 0 , "Maximum graph size to mine for");
DEFINE_int32(output_increment, 0, "Output every N graphs");
DEFINE_bool(remove_duplicates, false, "Remove graph duplication in projections [Warning, computationally expensive]");
DEFINE_bool(remove_parent, false, "Remove parent graphs");
DEFINE_bool(stop_at_max, false, "Stop if max_graph_size subgraph is found");
DEFINE_int32(threads, 0, "Number of threads");
DEFINE_int32(timeout, 0, "Timemout after N seconds");

// Below not currently implemented
//DEFINE_bool(remove_same_edges, false, "Merge the edges sharing the same properties (Pathological case)");

// Initialize instance
using quickspan::Database;
Database *Database::instance_ = new Database();

// Static link for signal handling
static quickspan::quickSpan* quickspan_inst;

// Signal handling, for safer output and timing out
extern "C" void sig_handler(int signum){ quickspan_inst->stopExec(signum); }

int main(int argc, char *argv[]) {
  std::string version_string = QUICKSPAN_VERSION_MAJOR + "." + QUICKSPAN_VERSION_MINOR;
  gflags::SetVersionString(quickspan::Version::version);
  gflags::VersionString();
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_logtostderr = true;
  google::InitGoogleLogging(argv[0]);
  // Check input flags, start with the fatal ones, and exit if they fail
  if (FLAGS_biggest_subgraphs > 0 && FLAGS_output_increment > 0) {
    LOG(INFO) << "Cannot enable both -biggest_subgraphs and -output_increment";
    exit(18);
  }
  if (FLAGS_input_file == "") {
    LOG(INFO) << "Input file should not be empty";
    exit(1);
  }
  // Check input flags that are non-fatal
  if (FLAGS_max_graph_size != 0) {
    if (FLAGS_max_graph_size < 0) {
      LOG(INFO) << "Cannot mine for negative sized graphs";
      exit(12);
    }
  }
  if (FLAGS_min_graph_size != 0) {
    if (FLAGS_min_graph_size < 0) {
      LOG(INFO) << "Cannot mine for negative sized graphs";
      exit(12);
    }
    if (FLAGS_min_graph_size > FLAGS_max_graph_size && FLAGS_max_graph_size != 0) {
      LOG(INFO) << "min_graph_size must be <= max_graph_size";
      exit(12);
    }
  }
  if (FLAGS_stop_at_max && FLAGS_max_graph_size == 0) {
    LOG(INFO) << "Must have max_graph_size set to use stop_at_max";
    exit(14);
  }
  if (FLAGS_support > 1.0 || FLAGS_support <= 0.0) {
    LOG(INFO) << "Support value should be less than 1.0 and greater than 0.0";
    exit(2);
  }
  if (FLAGS_threads != 0) {
    if (FLAGS_threads < 0) {
      LOG(INFO) << "Thread count cannot be negative";
      exit(11);
    }
    omp_set_dynamic(0);
    omp_set_num_threads(FLAGS_threads);
  }
  if(FLAGS_timeout != 0){
    if (FLAGS_timeout < 0) {
      LOG(INFO) << "Timeout cannot be negative";
      exit(13);
    }
    LOG(INFO) << "quickspan timeout: " << FLAGS_timeout;
    // VR Set timer
    struct itimerval timer;
    timer.it_value.tv_sec = FLAGS_timeout;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer (ITIMER_REAL, &timer, nullptr);
    signal(SIGALRM,sig_handler);
  }
  // Warnings, these do not prevent execution.
  if (FLAGS_output_increment > 0 && FLAGS_remove_parent) {
    LOG(INFO) << "Warning: -output_increment and -remove_parent together will not remove parent graphs already output";
  }
  if (FLAGS_parent && FLAGS_remove_parent) {
    LOG(INFO) << "Warning: -parent and -remove_parent together will reference deleted graphs";
  }
  // Read input
  #ifdef QUICKSPAN_PERFORMANCE
  struct timeval time_start, time_end;
  double elapsed = 0.0;
  CPU_TIMER_START(elapsed, time_start);
  #endif
  Database::get_instance()->read_input(FLAGS_input_file, FLAGS_separator);
  #ifdef QUICKSPAN_PERFORMANCE
  CPU_TIMER_END(elapsed, time_start, time_end);
  LOG(INFO) << "quickspan read input time: " << elapsed;
  CPU_TIMER_START(elapsed, time_start);
  #endif
  // Construct algorithm
  quickspan::quickSpan quickspan(
    FLAGS_biggest_subgraphs,
    FLAGS_directed_graphs,
    FLAGS_max_graph_size,
    FLAGS_min_graph_size,
    FLAGS_output_file,
    FLAGS_output_increment,
    FLAGS_parent,
    FLAGS_pattern,
    FLAGS_remove_duplicates,
    FLAGS_remove_parent,
    FLAGS_support,
    FLAGS_stop_at_max
    );
  // Set signal handlers
  quickspan_inst = &quickspan;
  signal(SIGINT,sig_handler);
  signal(SIGTERM,sig_handler);
  signal(SIGUSR1,sig_handler);
  // Start execution
  quickspan.execute();
  #ifdef QUICKSPAN_PERFORMANCE
  CPU_TIMER_END(elapsed, time_start, time_end);
  LOG(INFO) << "quickspan execute time: " << elapsed;
  #endif
  // Save results
  if (FLAGS_output_file.size() != 0) {
    #ifdef QUICKSPAN_PERFORMANCE
    CPU_TIMER_START(elapsed, time_start);
    #endif
    quickspan.save(FLAGS_nodes);
    #ifdef QUICKSPAN_PERFORMANCE
    CPU_TIMER_END(elapsed, time_start, time_end);
    LOG(INFO) << "quickspan save output time: " << elapsed;
    #endif
  }
  return 0;
}
