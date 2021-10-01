#include "dmalloc.hh"
#include <cstdio>
#include <cassert>
#include <cstring>
// heap_min and heap_max checking, simple case.

int main() {
    char* p = (char*) malloc(10);
    dmalloc_statistics stat;
    dmalloc_get_statistics(&stat);
    assert((uintptr_t) p >= stat.heap_min);
    assert((uintptr_t) p + 10 <= stat.heap_max);
    // printf("p: %ld\n", (uintptr_t) p);
    // printf("p + 10: %ld\n", (uintptr_t) p + 10);
    // printf("heap_min: %ld\n", stat.heap_min);
    // printf("heap_max: %ld\n", stat.heap_max);
    // printf("diff between p and min: %ld\n", (uintptr_t) p - stat.heap_min);
    // printf("diff between p + 10 and max: %ld\n", (uintptr_t) p + 10 - stat.heap_max);
}
