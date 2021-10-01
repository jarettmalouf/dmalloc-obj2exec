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
#define CANARY (char *) "Here now, don't make a sound\nSay, have you heard the news today?\nOne flag was taken down\nTo raise another in its place\nA heavy cross you bear\nA stubborn heart remains unchanged\nNo harm, no life, no love\nNo stranger singing in your name\nBut maybe the season\nThe colors change in the valley skies\nDear God, I've sealed my fate\nRunning through hell, heaven can wait\nLong road to ruin there in your eyes\nUnder the cold streetlights\nNo tomorrow, no dead end in sight\nLet's say we take this town\nNo king or queen of any state\nGet up to shut it down\nOpen the streets and raise the gates\nI know a wall to scale\nI know a field without a name\nHead on without a care\nBefore it's way too late\nMaybe the season\nThe colors change in the valley skies\nOh God, I've sealed my fate\nRunning through hell, heaven can wait\nLong road to ruin there in your eyes\nUnder the cold streetlights\nNo tomorrow, no dead ends\nLong road to ruin there in your eyes\nUnder the cold streetlights\nNo tomorrow, no dead end in sight\nFor every piece to fall in place\nForever gone without a trace\nYour horizon takes its shape\nNo turning back, don't turn that page\nCome now, I'm leaving here tonight\nCome now, let's leave it all behind\nIs that the price you pay?\nRunning through hell, heaven can wait\nLong road to ruin there in your eyes\nUnder the cold streetlights\nNo tomorrow, no dead ends\nLong road to ruin there in your eyes\nUnder the cold streetlights\nNo tomorrow, no dead ends\nLong road to ruin there in your eyes\nUnder the cold streetlights\nNo tomorrow, no dead end in sight"

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
    uintptr_t header_addr;
    uintptr_t payload_addr;
    uintptr_t footer_addr;
    uintptr_t final_addr;
    char* underflow;
};

struct footer_t {
    char* overflow;
};

// DLL

struct node {
    struct header_t *info;
    struct node *prev;
    struct node *next;
};

struct node *new_node() {
    struct node *n = (struct node *) malloc (sizeof(struct node));
    n->prev = NULL;
    n->next = NULL;
    return n;
}

struct node *new_node(header_t *info) {
    struct node *n = (struct node *) malloc (sizeof(struct node));
    n->prev = NULL;
    n->next = NULL;
    n->info = info;
    return n;
}

void link(struct node *head, struct node *tail) {
    head->next = tail;
    tail->prev = head;
}

struct node *head = NULL;
struct node *tail = NULL;

void add_node(node *n) {
    if (head == NULL && tail == NULL) {
        head = new_node();
        tail = new_node();
        head->next = tail;
        tail->prev = head;
    }
    n->prev = head;
    n->next = head->next;
    head->next = n;
    n->next->prev = n;
}

void add_record(header_t *info) {
    add_node(new_node(info));
}

void remove_node(node *n) {
    n->prev->next = n->next;
    n->next->prev = n->prev;
}

void remove_record(header_t *info) {
    struct node *curr = head->next;
    for (int i = 1; i < (int) s.nactive + 1; i++) {
        if (curr->info == info) remove_node(curr);
        curr = curr->next;
    }
}

/// dmalloc_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then dmalloc_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

uintptr_t get_alignment_gap(uintptr_t curr, size_t align) {
    return curr % align == 0 ? 0 : align - (curr % align);
}

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
    h->header_addr = header;
    h->payload_addr = payload;
    h->footer_addr = footer;
    h->final_addr = footer + FOOTER_SIZE;
    h->underflow = CANARY;
    f->overflow = CANARY;

    add_record(h);

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

struct node *get_allocated_block(void* ptr) {
    struct node *curr = head->next;
    uintptr_t addr = (uintptr_t) ptr;
    for (int i = 1; i < (int) s.nactive + 1; i++) {
        if (addr >= curr->info->header_addr && addr <= curr->info->final_addr) return curr;
        curr = curr->next;
    }
    return nullptr;
}

void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    if (ptr == nullptr) return;

    if (!in_heap(ptr)) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n", file, line, ptr);
        exit(1);
    }

    header_t *header = (header_t *) ((uintptr_t) ptr - HEADER_SIZE);
    node *allocated_node = get_allocated_block(ptr);



    if (* (int*) header == '\0') {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        
        if (allocated_node != nullptr) {
            size_t inside = (size_t) ((uintptr_t) ptr - allocated_node->info->payload_addr);
            size_t size = allocated_node->info->size;
            long l = allocated_node->info->line;
            fprintf(stderr, "  %s:%ld: %p is %zu bytes inside a %zu byte region allocated here\n", file, l, ptr, inside, size);
        }

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

    if (allocated_node->info->payload_addr != (uintptr_t) ptr) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        exit(1); 
    }


    s.nactive--;
    s.active_size -= header->size;
    header->freed = true;

    remove_record(header);

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
    struct node *curr = head->next;
    for (int i = 1; i < (int) s.nactive + 1; i++) {
        header_t *h = curr->info;
        printf("LEAK CHECK: %s:%ld: allocated object %p with size %zu\n", h->file, h->line, (void *) h->payload_addr, h->size);
        curr = curr->next;
    }
}

/// dmalloc_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void dmalloc_print_heavy_hitter_report() {
    // Your heavy-hitters code here
}
