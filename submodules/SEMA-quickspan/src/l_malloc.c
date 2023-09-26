/**
 * Licensed to Institut National de Recherche en Informatique et Automatique
 * - INRIA - one one or more license agreement.
 *
 * (C) 2016, 2017, 2018, All right reserved.
 *
 * @copyright Inria
 * @author Laurent Morin 
 */

#define OVERLOAD_MALLOC_LIB		/*!< Flag: enables the memory monitoring system to initialize. */
#define OVERLOAD_MALLOC			/*!< Flag: enables the overloading of regular C memory operations. */

#ifdef OVERLOAD_MALLOC_LIB

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include <malloc.h>
#include <string.h>

/** \defgroup Memory monitoring system
 *  @{
 */

/** @file l_malloc.c
 * Memory monitoring system
 *
 * This memory monitoring system records the memory allocated and send
 * a signal when a limit is reached. The system fit on one single file
 * and opereates at linking time: it does not need any header or declaration.
 * 
 * The system is activated using environment variables:
 *  ::OCLENI_MALLOC_MODE (integer): must be set to 1 to activate the
 *  memory limitation.
 *  ::OCLENI_MAX_MEMORY  (integer) maximum memory allocated at a time
 *  before sending a signal.
 *
 * Dependencies: The systems requires pthread (posix threads) and
 * dl (dynamic library) libraries.
 *
 */

/** The maximum memory that can allocated during the initialization phase */
#define MAX_TEMP_MEMORY 1000000

/** Environment variable name for the memory monitoring mode. See ::m_state */
static const char * const OCLENI_MALLOC_MODE_ENV =		"OCLENI_MALLOC_MODE";

/** Environment variable name for the maximum memory size in kb. See ::m_maxSize */
static const char * const OCLENI_MAX_MEMORY_ENV =		"OCLENI_MAX_MEMORY";

/**
 * Monitoring global structure
 *
 * Global and static structure for the memory monitor.
 * Access shall be protetected with the inner semaphore for thread safe operations.
 */
static struct {
  void *		(*m_malloc_h)(size_t);		/*!< Overloading pointer for malloc. */
  void *		(*m_realloc_h)(void*, size_t);	/*!< Overloading pointer for realloc. */
  void *		(*m_calloc_h)(size_t, size_t);	/*!< Overloading pointer for calloc. */
  void *		(*m_free_h)(void*);		/*!< Overloading pointer for free. */
  enum  {
    MALLOC_OFF=0,			/*!< Monitoring disabled. */
    MALLOC_ON=1,			/*!< Monitoring enabled. */
  }			m_mode;	/*!< Monitoring mode (active or not). */
  enum  {
    MALLOC_S_RUN = 0,				/*!< Normal operation.*/
    MALLOC_S_LIMIT_REACHED = 1,			/*!< Maximum memory limit reached, signal sent.*/
    MALLOC_S_INIT = 2				/*!< Initialization phase, local stack used.*/
  }			m_state;	/*!< Monitor state: run, initialization, limit reached.*/
  pthread_mutex_t	m_lock;		/*!< Global structure semaphore. */
  size_t		m_totalSize;	/*!< Total size of memory allocated. */
  size_t		m_maxSize;	/*!< Limit size. */
} __mmon_g_mem_desc;

/**
 * Error and assert function.
 * @param errorCode	error code
 * @param message	error message
 *
 * This function prints an error and always abort
 * the execution if the error code is not zero.
 */
static inline void __mmon_assert(int errorCode, char *message)
{
  if (!errorCode) {
    fputs("[ocleni] fatal error: ", stderr);
    fputs(message, stderr);
    abort();
  }
}

/**
 * Locks the global data structure semaphore.
 */
static inline void __mmon_lock(void) {
  pthread_mutex_lock( &__mmon_g_mem_desc.m_lock );
}

/**
 * Unlocks the global data structure semaphore.
 */
static inline void __mmon_unlock(void) {
  pthread_mutex_unlock( &__mmon_g_mem_desc.m_lock );
}

/**
 * Allocate a memory block in the local stack.
 * @param size	size of the memory to allocate.
 *
 * This function allocate in the data segment a small
 * portion of memory for allocations operated before
 * and during the initialization phase.
 */
static inline void *__mmon_getblobalstack(size_t size) {
  static char g_global_stack[MAX_TEMP_MEMORY];
  static size_t g_global_stack_size = 0;
  g_global_stack_size += size;
  __mmon_assert(g_global_stack_size < MAX_TEMP_MEMORY, "ocleni: out of memory in local stack\n");
  return &g_global_stack[g_global_stack_size];
}

/**
 * Main initialization function
 *
 * This function initialize the overloading of regular
 * C memory operations and the local data stucture.
 * During the execution of this function, parallel and
 * underlying memory allocation use the local data segment
 * (See ::__mmon_getblobalstack).
 */
static inline void __mmon_startmalloc(void)
{
  static int g_done = 0;
  if (!g_done) {
    g_done = 1;
    __mmon_g_mem_desc.m_state = MALLOC_S_INIT;
    __mmon_g_mem_desc.m_mode = MALLOC_OFF;
    __mmon_g_mem_desc.m_maxSize = 0;

    const char *modestr = getenv(OCLENI_MALLOC_MODE_ENV);
    if (modestr) {
      __mmon_g_mem_desc.m_mode = atoi(modestr);
    }
    const char *maxmemstr = getenv(OCLENI_MAX_MEMORY_ENV);
    if (maxmemstr) {
      __mmon_g_mem_desc.m_maxSize = strtol(maxmemstr, NULL, 10) * 1000;
    }

    void * handle = (void*) -1;
    __mmon_g_mem_desc.m_malloc_h = (void *) dlsym(handle, "malloc");
    __mmon_assert(__mmon_g_mem_desc.m_malloc_h != NULL, "'ocleni'' not found");

    __mmon_g_mem_desc.m_realloc_h = (void *) dlsym(handle, "realloc");
    __mmon_assert(__mmon_g_mem_desc.m_realloc_h != NULL, "'realloc' not found");

    __mmon_g_mem_desc.m_calloc_h = (void *) dlsym(handle, "calloc");
    __mmon_assert(__mmon_g_mem_desc.m_calloc_h != NULL, "'calloc' not found");

    __mmon_g_mem_desc.m_free_h = (void *) dlsym(handle, "free");
    __mmon_assert(__mmon_g_mem_desc.m_free_h != NULL, "'free' not found");

    __mmon_g_mem_desc.m_totalSize = 0;
    pthread_mutex_t init = PTHREAD_MUTEX_INITIALIZER;
    __mmon_g_mem_desc.m_lock = init;

    __mmon_g_mem_desc.m_state = MALLOC_S_RUN;

    if (__mmon_g_mem_desc.m_mode > MALLOC_ON) {
      fprintf(stderr, "ocleni:start malloc overloading\n"
              "ocleni: memory limit before SIGINT=%lu (env:%s)\n",
              __mmon_g_mem_desc.m_maxSize, OCLENI_MAX_MEMORY_ENV);
    }
  }
}

/**
 * Launches a unique instance of the initialization function.
 */
__attribute__((constructor))
static void __mmon_startmalloc_unique(void)
{
  static pthread_once_t g_initialized = PTHREAD_ONCE_INIT;	/*!< Pthread initialization flag. */
  pthread_once(&g_initialized, (void(*)()) __mmon_startmalloc);
}

/**
 * Clean-up the global data structure.
 */
__attribute__((destructor))
static inline void __mmon_stopmalloc(void)
{
  pthread_mutex_destroy(&__mmon_g_mem_desc.m_lock);
}

/**
 * Main monitoring function
 *
 * Monitor the size and the data allocated, update the statistics,
 * and send a signal when the limit is reached.
 */
static inline void __mmon_limit_malloc(void *alloc, size_t size) {
  if (__mmon_g_mem_desc.m_mode >= MALLOC_ON) {
    __mmon_lock();
    if (alloc) size = malloc_usable_size (alloc);
    __mmon_g_mem_desc.m_totalSize += size;
    if ((__mmon_g_mem_desc.m_state == MALLOC_S_RUN) &
        (__mmon_g_mem_desc.m_maxSize != 0) &
        (__mmon_g_mem_desc.m_totalSize > __mmon_g_mem_desc.m_maxSize)) {
      __mmon_g_mem_desc.m_state = MALLOC_S_LIMIT_REACHED;
      __mmon_unlock();
      kill(getpid(), SIGINT);
    }
    else __mmon_unlock();
  }
}

#ifdef OVERLOAD_MALLOC

/**
 * Overloads standard C malloc
 *
 */
void *malloc(size_t size) {
  __mmon_startmalloc_unique();
  void *alloc = (*__mmon_g_mem_desc.m_malloc_h)(size);
  __mmon_limit_malloc(alloc, size);
  return alloc;
}

/**
 * Overloads standard C calloc
 *
 */
void *calloc(size_t nmemb, size_t size) {
  __mmon_lock();
  int init_state = (__mmon_g_mem_desc.m_state == MALLOC_S_INIT);
  void *alloc;
  if (init_state) {
    alloc = __mmon_getblobalstack(size);
    __mmon_unlock();
    memset(alloc, 0, nmemb);
  }
  else {
    __mmon_unlock();
    __mmon_startmalloc_unique();
    alloc = (*__mmon_g_mem_desc.m_calloc_h)(nmemb, size);
    __mmon_limit_malloc(alloc, size);
  }
  return alloc;
}

/**
 * Overloads standard C realloc
 *
 */
void *realloc(void *alloc, size_t size) {
  __mmon_startmalloc_unique();
  alloc = (*__mmon_g_mem_desc.m_realloc_h)(alloc, size);
  __mmon_limit_malloc(alloc, size);
  return alloc;
}

/**
 * Overloads standard C free
 *
 */
void free(void *alloc) {
  size_t size = 0;
  __mmon_startmalloc_unique();
  if (alloc == NULL)
    return;
  if (__mmon_g_mem_desc.m_mode >= MALLOC_ON) {
    size = malloc_usable_size (alloc);
  }
  (*__mmon_g_mem_desc.m_free_h)(alloc);
  __mmon_limit_malloc(NULL, -size);
}

/** @} */

#endif

#endif
