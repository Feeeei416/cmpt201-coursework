#define _POSIX_C_SOURCE 200809L
#define _ISOC99_SOURCE
#define _DEFAULT_SOURCE

#include "alloc.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#define HEADER_SIZE (sizeof(struct header))

static int free_space = 0;
static int total_space = 0;
static int space_limit = 0;
static void *base;
static struct header *free_head = NULL;
static enum algs alg = FIRST_FIT;

void insert_free_sorted(struct header *h);
void coalesce(void);

int find_first_fit(struct header *free_ptr, uint64_t size,
                   struct header **res_out, struct header **prev_out) {
  struct header *prev = NULL;
  while (free_ptr != NULL) {
    if (free_ptr->size >= size) {
      *res_out = free_ptr;
      *prev_out = prev;
      return 0;
    }
    prev = free_ptr;
    free_ptr = free_ptr->next;
  }
  return -1;
}

int find_best_fit(struct header *free_ptr, uint64_t size,
                  struct header **res_out, struct header **prev_out) {
  struct header *best_ptr = NULL;
  struct header *best_prev = NULL;
  struct header *prev = NULL;
  uint64_t best_fit_size = UINT64_MAX;
  while (free_ptr != NULL) {
    if (free_ptr->size >= size && free_ptr->size < best_fit_size) {
      best_fit_size = free_ptr->size;
      best_ptr = free_ptr;
      best_prev = prev;
    }
    prev = free_ptr;
    free_ptr = free_ptr->next;
  }
  if (best_ptr != NULL) {
    *res_out = best_ptr;
    *prev_out = best_prev;
    return 0;
  } else
    return -1;
}

int find_worst_fit(struct header *free_ptr, uint64_t size,
                   struct header **res_out, struct header **prev_out) {
  struct header *worst_ptr = NULL;
  struct header *worst_prev = NULL;
  struct header *prev = NULL;
  uint64_t worst_fit_size = 0;
  while (free_ptr != NULL) {
    if (free_ptr->size >= size && free_ptr->size > worst_fit_size) {
      worst_fit_size = free_ptr->size;
      worst_ptr = free_ptr;
      worst_prev = prev;
    }
    prev = free_ptr;
    free_ptr = free_ptr->next;
  }
  if (worst_ptr != NULL) {
    *res_out = worst_ptr;
    *prev_out = worst_prev;
    return 0;
  } else
    return -1;
}

int grow_heap(struct header **h) {
  void *old_ptr = sbrk(0);
  if (sbrk(INCREMENT) == (void *)-1)
    return -1;
  total_space += INCREMENT;
  free_space += INCREMENT;

  struct header *ptr = (struct header *)old_ptr;
  ptr->size = INCREMENT;
  ptr->next = NULL;
  *h = ptr;
  return 0;
}

int select_space(struct header *h, int space, struct header **res,
                 struct header **prev) {
  int ans = -1;
  if (alg == FIRST_FIT)
    ans = find_first_fit(h, space, res, prev);
  else if (alg == BEST_FIT)
    ans = find_best_fit(h, space, res, prev);
  else
    ans = find_worst_fit(h, space, res, prev);
  return ans;
}
/*
 * alloc() allocates memory from the heap. The first argument indicates the
 * size. It returns the pointer to the newly-allocated memory. It returns NULL
 * if there is not enough space.
 */
void *alloc(int size) {
  if (size <= 0)
    return NULL;

  int need_space = HEADER_SIZE + size;
  if (free_space < need_space) {
    if (total_space + INCREMENT > space_limit)
      return NULL;

    // Increase the end_header's space
    struct header *h = NULL;
    int output = grow_heap(&h);
    if (output == -1)
      return NULL;

    h->next = free_head;
    free_head = h;
    coalesce();
  }

  struct header *h = free_head;
  struct header *res = NULL;
  struct header *prev = NULL;
  int output = select_space(h, need_space, &res, &prev);
  if (output == -1)
    return NULL;

  uint64_t rem = res->size - need_space;
  if (rem < HEADER_SIZE) {
    if (prev)
      prev->next = res->next;
    else
      free_head = res->next;
    need_space += rem;
    res->size = need_space;
    free_space -= res->size;
  } else {
    struct header *remh = (struct header *)((char *)res + need_space);
    remh->size = rem;
    remh->next = res->next;
    if (prev)
      prev->next = remh;
    else
      free_head = remh;

    res->size = need_space;
    free_space -= (int)need_space;
  }

  return (char *)res + HEADER_SIZE;
}
void insert_free_sorted(struct header *h) {
  if (!free_head || h < free_head) {
    h->next = free_head;
    free_head = h;
    return;
  }
  struct header *cur = free_head;
  while (cur->next && cur->next < h)
    cur = cur->next;
  h->next = cur->next;
  cur->next = h;
}

void coalesce(void) {
  struct header *cur = free_head;
  struct header *prev = NULL;
  struct header *end = free_head + free_head->size;
  struct header *free_front = NULL;
  struct header *free_back = NULL;
  struct header *back_prev = NULL;
  while (cur != NULL) {
    char *end_cur = (char *)cur + cur->size;
    if (end_cur == (char *)free_head) {
      free_front = cur;
    } else if ((char *)cur == (char *)end) {
      free_back = cur;
      back_prev = prev;
    }
    prev = cur;
    cur = cur->next;
  }
  if (free_back != NULL) {
    struct header *h = free_head;
    back_prev->next = free_back->next;
    h->size += free_back->size;
    free_back->next = NULL;
  }
  if (free_front != NULL) {
    struct header *h = free_head;
    free_front->size += h->size;
    free_head = h->next;
  }
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
  coalesce();
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
  uint64_t size = 0;
  uint64_t largest = 0;
  uint64_t smallest = 0;
  uint64_t chunks = 0;

  struct header *cur = free_head;
  while (cur) {
    uint64_t s = cur->size;
    size += s - HEADER_SIZE;
    if (s >= HEADER_SIZE) {
      chunks++;
      if (largest < s)
        largest = s;
      if (smallest == 0 || s < smallest)
        smallest = s;
    }
    cur = cur->next;
  }

  res.free_size = size;
  res.free_chunks = chunks;
  res.largest_free_chunk_size = (chunks ? largest - HEADER_SIZE : 0);
  res.smallest_free_chunk_size = (chunks ? smallest - HEADER_SIZE : 0);
  return res;
}
