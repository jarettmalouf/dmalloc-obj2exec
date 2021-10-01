#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>

#define HEADER_SIZE sizeof(struct header_t)
#define FOOTER_SIZE sizeof(struct footer_t)
#define VERY_LARGE_NUMBER (size_t) -1
#define CANARY (int) 42069
#define TEMP_ALIGN 10

// You may write code here.
// (Helper functions, types, structs, macros, globals, etc.)

struct dmalloc_statistics get_new_stats() {
    struct dmalloc_statistics s;
    s.nactive =       (unsigned long long) 0;           // # active allocations
    s.ntotal =        (unsigned long long) 0;           // # total allocations
    s.active_size =   (unsigned long long) 0;           // # bytes in active allocations
    s.total_size =    (unsigned long long) 0;           // # bytes in total allocations
    s.nfail =         (unsigned long long) 0;           // # failed allocation attempts
    s.fail_size =     (unsigned long long) 0;           // # bytes in failed alloc attempts
    s.heap_min =      (uintptr_t) UINTPTR_MAX;          // smallest allocated addr
    s.heap_max =      (uintptr_t) 0;                   // largest allocated addr

    return s;
}

struct dmalloc_statistics s = get_new_stats();

struct header_t {
    size_t size;
    bool freed;
    const char* file;
    long line;
    uintptr_t footer_addr;
    int underflow;
};

struct footer_t {
    int overflow;
};

uintptr_t get_alignment_gap(uintptr_t curr, size_t align) {
    return curr % align == 0 ? 0 : align - (curr % align);
}

/// dmalloc_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then dmalloc_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.


void* dmalloc_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;    
    // uintptr_t space = get_alignment_gap(HEADER_SIZE + sz, TEMP_ALIGN);
    void *ptr = (void *) base_malloc(HEADER_SIZE + sz + FOOTER_SIZE);
    uintptr_t header = (uintptr_t) ptr;
    uintptr_t payload = header + HEADER_SIZE;
    uintptr_t footer = payload + sz;
    // uintptr_t pre_footer = payload + sz;
    // uintptr_t footer = pre_footer + space;

    if (ptr == nullptr || sz >= VERY_LARGE_NUMBER) {
        s.nfail++;
        s.fail_size += sz;
        return nullptr;
    } 
    
    header_t *h = (header_t *) header;
    footer_t *f = (footer_t *) footer;

    s.nactive++;
    s.ntotal++;
    s.active_size += sz;
    s.total_size += sz;

    if (payload < s.heap_min) s.heap_min = payload;
    if (payload + sz > s.heap_max) s.heap_max = payload + sz;
    
    h->size = sz;
    h->freed = false;
    h->file = file;
    h->line = line;
    h->footer_addr = footer;
    h->underflow = CANARY;
    f->overflow = CANARY;

    return (void *) payload;
}


/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to dmalloc_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

bool in_heap(void *ptr) {
    uintptr_t addr = (uintptr_t) ptr;
    return addr >= s.heap_min && addr <= s.heap_max;
}

// bool is_allocated(void *ptr) {
//     return get_header(ptr) != nullptr;
// }

// bool already_freed(void *ptr) { 
//     return get_header(ptr)->freed;
// }

void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    if (ptr == nullptr) return;

    if (!in_heap(ptr)) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n", file, line, ptr);
        exit(1);
    }

    header_t *header = (header_t *) ((uintptr_t) ptr - HEADER_SIZE);

    if (reinterpret_cast<int*>(header)[0] == '\0') {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        exit(1);
    }

    if (header->freed) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n", file, line, ptr);
        exit(1);
    }

    footer_t *footer = (footer_t *) header->footer_addr;
    if (header->underflow != CANARY || footer->overflow != CANARY) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
        exit(1);
    }

    s.nactive--;
    s.active_size -= header->size;
    header->freed = true;

    base_free(ptr);
}


/// dmalloc_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Your code here (to fix test014).
    if (nmemb >= VERY_LARGE_NUMBER / sz || sz >= VERY_LARGE_NUMBER / nmemb) {
        s.nfail++;
        s.fail_size += sz;
        return nullptr;
    }

    void* ptr = dmalloc_malloc(nmemb * sz, file, line);
    if (ptr != nullptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


/// dmalloc_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void dmalloc_get_statistics(dmalloc_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(dmalloc_statistics));
    // Your code here.
    stats->nactive = s.nactive;
    stats->ntotal = s.ntotal;
    stats->active_size = s.active_size;
    stats->total_size = s.total_size;
    stats->nfail = s.nfail;
    stats->fail_size = s.fail_size;
    stats->heap_min = s.heap_min;
    stats->heap_max = s.heap_max;
}


/// dmalloc_print_statistics()
///    Print the current memory statistics.

void dmalloc_print_statistics() {
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// dmalloc_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void dmalloc_print_leak_report() {
    // Your code here.
}


/// dmalloc_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void dmalloc_print_heavy_hitter_report() {
    // Your heavy-hitters code here
}
