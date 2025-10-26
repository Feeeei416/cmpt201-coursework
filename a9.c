#define _POSIX_C_SOURCE 200809L
#define _ISOC99_SOURCE
#define _DEFAULT_SOURCE

#include "alloc.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#define HEADER_SIZE (sizeof(struct header))

static bool first_initialized = true;
static int free_space = 0;
static int total_space = 0;
static int space_limit = 0;
static void *base;
static struct header *free_head = NULL;
static enum algs alg = FIRST_FIT;

struct header *find_first_fit(struct header *free_ptr, uint64_t size) {
  while (free_ptr != NULL) {
    if (free_ptr->size >= size)
      return free_ptr;
    free_ptr = free_ptr->next;
  }
  return NULL;
}

struct header *find_best_fit(struct header *free_ptr, uint64_t size) {
  struct header *best_ptr = NULL;
  uint64_t best_fit_size = UINT64_MAX;
  while (free_ptr != NULL) {
    if (free_ptr->size >= size && free_ptr->size < best_fit_size) {
      best_fit_size = free_ptr->size;
      best_ptr = free_ptr;
    }
    free_ptr = free_ptr->next;
  }
  return best_ptr;
}

struct header *find_worst_fit(struct header *free_ptr, uint64_t size) {
  struct header *worst_ptr = NULL;
  uint64_t worst_fit_size = 0;
  while (free_ptr != NULL) {
    if (free_ptr->size >= size && free_ptr->size > worst_fit_size) {
      worst_fit_size = free_ptr->size;
      worst_ptr = free_ptr;
    }
    free_ptr = free_ptr->next;
  }
  return worst_ptr;
}

/*
 * alloc() allocates memory from the heap. The first argument indicates the
 * size. It returns the pointer to the newly-allocated memory. It returns NULL
 * if there is not enough space.
 */
void *alloc(int size) {
  if (size <= 0)
    return NULL;

  if (first_initialized) {
    first_initialized = false;
    if (sbrk(INCREMENT) == (void *)-1)
      return NULL;
    total_space = INCREMENT;
    free_space = INCREMENT;
    free_head = base;
    free_head->next = NULL;
  }

  const int need_space = HEADER_SIZE + size;
  if (free_space < need_space && total_space + INCREMENT <= space_limit) {
    if (sbrk(INCREMENT) == (void *)-1)
      return NULL;
    total_space += INCREMENT;
    free_space += INCREMENT;
  } else if (free_space < need_space && total_space + INCREMENT > space_limit)
    return NULL;

  struct header *h = free_head;
  struct header *res = NULL;
  if (alg == FIRST_FIT)
    // first fit algorithm
    res = find_first_fit(h, need_space);
  else if (alg == BEST_FIT)
    // BEST_FIT
    res = find_best_fit(h, need_space);
  else
    // WORST_FIT
    res = find_worst_fit(h, need_space);

  if (!res)
    return NULL;

  res->size = need_space;
  free_space -= need_space;
  free_head = res + need_space;
  free_head->size = free_space;
  free_head->next = NULL;

  return (char *)res + HEADER_SIZE;
}

// dealloc() frees the memory pointer to by the first argument.
void dealloc(void *node) {
  if (!node)
    return;

  struct header *h = (struct header *)((char *)node - HEADER_SIZE);

  if (h->size < HEADER_SIZE)
    return;

  free_space += h->size;
  h->next = free_head;
  free_head = h;

  // coalesce
  struct header *cur = free_head;
  while (cur && cur->next) {
    struct header *end_cur = cur + cur->size;
    if (end_cur == cur->next) {
      cur->size += end_cur->size;
      cur->next = end_cur->next;
    } else {
      cur = cur->next;
    }
  }
}

/*
 * allocopt() sets the options for the memory allocator.
 *
 * The first argument sets the algorithm.
 * The second argument sets the size limit.
 */
void allocopt(enum algs option, int set_lim) {
  if (!base)
    base = sbrk(0);
  if (set_lim < 0)
    set_lim = 0;
  space_limit = set_lim;
  free_head = NULL;
  total_space = 0;
  free_space = 0;
  alg = option;
}

// allocinfo() returns the current statistics.
struct allocinfo allocinfo(void) {
  struct allocinfo res;
  res.free_size = (uint64_t)(free_space - HEADER_SIZE);

  uint64_t largest = 0;
  uint64_t smallest = 0;
  uint64_t chunks = 0;
  struct header *cur = free_head;
  while (cur) {
    uint64_t s = cur->size;
    if (s >= HEADER_SIZE) {
      chunks++;
      if (largest < s)
        largest = s;
      if (smallest == 0 || s < smallest)
        smallest = s;
    }
    cur = cur->next;
  }
  res.free_chunks = chunks;
  res.largest_free_chunk_size = largest;
  res.smallest_free_chunk_size = smallest;
  return res;
}
