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
#define CANARY (char *) "Here now, don't make a sound"
#define THRESHOLD 5
#define SAMPLING_PERCENTAGE 10

struct dmalloc_statistics get_new_stats() {
    struct dmalloc_statistics s;
    s.nactive =       (unsigned long long) 0;           // # active allocations
    s.ntotal =        (unsigned long long) 0;           // # total allocations
    s.active_size =   (unsigned long long) 0;           // # bytes in active allocations
    s.total_size =    (unsigned long long) 0;           // # bytes in total allocations
    s.nfail =         (unsigned long long) 0;           // # failed allocation attempts
    s.fail_size =     (unsigned long long) 0;           // # bytes in failed alloc attempts
    s.heap_min =      (uintptr_t) UINTPTR_MAX;          // smallest allocated addr
    s.heap_max =      (uintptr_t) 0;                    // largest allocated addr
    return s;
}

struct dmalloc_statistics s = get_new_stats();

struct header_t {
    size_t size;
    int freed;
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

void *last_freed = nullptr;

// DLL

struct node {
    struct header_t *info;
    struct node *prev;
    struct node *next;
};

struct node *new_node() {
    struct node *n = (struct node *) malloc(sizeof(struct node));
    n->prev = NULL;
    n->next = NULL;
    return n;
}

struct node *new_node(header_t *info) {
    struct node *n = (struct node *) malloc(sizeof(struct node));
    n->prev = NULL;
    n->next = NULL;
    n->info = info;
    return n;
}

struct node *head = NULL;
struct node *tail = NULL;
bool list_init = false;

void add_node(node *n) {
    if (!list_init) {
        head = new_node();
        tail = new_node();
        head->next = tail;
        tail->prev = head;
        list_init = true;
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
    free(n);
}

void remove_record(header_t *info) {
    struct node *curr = head->next;
    for (int i = 1; i < (int) s.nactive + 1; i++) {
        if (curr->info == info) remove_node(curr);
        curr = curr->next;
    }
}

// heavy hitter

struct file_line_pair {
    const char *file;
    long line;
};

struct HH_element {
    struct file_line_pair pair;
    long alloc;
};

struct file_line_pair K[THRESHOLD];
struct HH_element HH[THRESHOLD];
size_t count[THRESHOLD];
int min_index = 100;
int k_size = 0;

struct file_line_pair new_file_line_pair(const char *file, long line) {
    struct file_line_pair x;
    x.file = file;
    x.line = line;
    return x;
}

int cmpfunc (const void *a, const void *b) {
   if (((struct HH_element *) a)->alloc == ((struct HH_element *) b)->alloc) return 0;
   return (((struct HH_element *) a)->alloc > ((struct HH_element *) b)->alloc) ? -1 : 1;
}

void sort_HH() {
    // populating HH with K[] and count[]
    for (int i = 0; i < k_size; i++) {
        HH[i].pair = K[i];
        HH[i].alloc = count[i];
    }
    qsort(HH, k_size, sizeof(HH_element), cmpfunc);
}

float total_random_size = 0;

void update_heavy_hitters(const char *file, long line, size_t sz) {
    // random sampling
    if (rand() % 100 > SAMPLING_PERCENTAGE) return;

    total_random_size += sz;

    // checking if already present
    int index_in_K = -1;
    struct file_line_pair pair = new_file_line_pair(file, line);
    for (int i = 0; i < k_size; i++) {
        if (K[i].file == pair.file && K[i].line == pair.line) {
            index_in_K = i; break;
        }
    }

    // if this pair is already in K, update it
    if (index_in_K != -1) {
        count[index_in_K] += sz;
        // K[index_in_K].alloc += sz;
        return;
    }

    // if there's space to add it, add it and update min_index if it's the smallest
    if (k_size < THRESHOLD) {
        K[k_size] = pair;
        count[k_size] = sz;
        if (sz < count[min_index]) min_index = k_size;
        k_size++;
        return; 
    }

    // if there's no space to add it but it doesn't deserve it, exit 
    if (sz <= count[min_index]) return;
    

    // if there's no space to add it and it does deserve it, put it in place of the smallest entry and calculate new min_index
    K[min_index] = pair;
    count[min_index] = sz;
    size_t new_min = count[0];
    int new_min_index = 0;
    for (int i = 1; i < k_size; i++) {
        if (count[i] < new_min) {
            new_min = count[i];
            new_min_index = i;
        }
    }
    min_index = new_min_index;
}

float *generate_percentages() {
    float *percentages = (float *) malloc(sizeof(float) * k_size);
    for (int i = 0; i < k_size; i++) {
        percentages[i] = 100 * HH[i].alloc / total_random_size;
    }
    
    return percentages;
}

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;    
    void *ptr = (void *) base_malloc(HEADER_SIZE + sz + FOOTER_SIZE);
    uintptr_t header = (uintptr_t) ptr;
    uintptr_t payload = header + HEADER_SIZE;
    uintptr_t footer = payload + sz;

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
    h->freed = 0;
    h->file = file;
    h->line = line;
    h->header_addr = header;
    h->payload_addr = payload;
    h->footer_addr = footer;
    h->final_addr = footer + FOOTER_SIZE;
    h->underflow = CANARY;
    f->overflow = CANARY;

    add_record(h);
    update_heavy_hitters(file, line, sz);

    return (void *) payload;
}

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

    if (header->freed == 1 || allocated_node == nullptr) {
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
    header->freed = 1;
    last_freed = ptr;

    remove_record(header);
    base_free(header);
}

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
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

void dmalloc_get_statistics(dmalloc_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(dmalloc_statistics));
    stats->nactive = s.nactive;
    stats->ntotal = s.ntotal;
    stats->active_size = s.active_size;
    stats->total_size = s.total_size;
    stats->nfail = s.nfail;
    stats->fail_size = s.fail_size;
    stats->heap_min = s.heap_min;
    stats->heap_max = s.heap_max;
}

void dmalloc_print_statistics() {
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

void dmalloc_print_leak_report() {
    struct node *curr = head->next;
    for (int i = 1; i < (int) s.nactive + 1; i++) {
        header_t *h = curr->info;
        printf("LEAK CHECK: %s:%ld: allocated object %p with size %zu\n", h->file, h->line, (void *) h->payload_addr, h->size);
        curr = curr->next;
    }
}

void dmalloc_print_heavy_hitter_report() {
    sort_HH();
    float *percentages = generate_percentages();
    for (int i = 0; i < k_size; i++) {
        struct HH_element el = HH[i];
        if (percentages[i] < 10) break;
        printf("HEAVY HITTER: %s:%ld: %zu bytes (~%.1f%%)\n", el.pair.file, el.pair.line, el.alloc, percentages[i]); 
    }
    free(percentages);
}
