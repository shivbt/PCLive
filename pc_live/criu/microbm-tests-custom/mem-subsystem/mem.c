#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096
#define SLEEP_COUNTER 20

// NUM_PAGES must be greater than 10 because some hard coded numnbers are used
// in the code to munmap.
#define NUM_PAGES 21

void test_mapping_unmapping_start () {

    // Simple mapping and unmapping at start.
    int size = NUM_PAGES * PAGE_SIZE;
    void *addr = mmap (NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    munmap(addr, PAGE_SIZE);

}

void test_mapping_unmapping_end () {

    // Simple mapping and unmapping at end.
    int size = NUM_PAGES * PAGE_SIZE;
    void *addr = mmap (NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    addr = addr + size - PAGE_SIZE;
    munmap(addr, PAGE_SIZE);

}

void test_mapping_unmapping_middle () {

    // Simple mapping and unmapping at middle.
    int size = NUM_PAGES * PAGE_SIZE;
    void *addr = mmap (NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    addr = addr + (size / 2) - PAGE_SIZE;
    munmap(addr, 2 * PAGE_SIZE);

}

void test_mapping_unmapping_all () {

    // Mapping and unmapping all regions.
    int size = NUM_PAGES * PAGE_SIZE;
    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    munmap(addr, size);

}

void test_mapping_unmapping_all_pages () {

    // Mapping and unmapping with all pages in.
    int size = NUM_PAGES * PAGE_SIZE;
    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    munmap(addr, 3 * PAGE_SIZE);

}

void test_mapping_on_demand () {

    // Mapping with few pages in (on-demand).
    int size = NUM_PAGES * PAGE_SIZE;
    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // Access on-demand pages.
    memset(addr + PAGE_SIZE, 0, PAGE_SIZE * 2);

}

void test_mapping_content_change () {

    // Mapping with all pages in and change in content.
    int size = NUM_PAGES * PAGE_SIZE;
    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // Modify content.
    strcpy(addr, "Happy MemSubsystem Testing!!");

}

void test_mapping_content_change_on_demand () {

    // Mapping with few pages in, content change, and on-demand pages in.
    int size = NUM_PAGES * PAGE_SIZE;
    void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // Modify content.
    strcpy(addr, "Initial Content");

    // Access on-demand pages.
    memset(addr + PAGE_SIZE, 0, PAGE_SIZE);

}

void test_mapping_protection () {

    // Mapping and protection changes.
    int size = NUM_PAGES * PAGE_SIZE;
    void *addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // Change protection to read-write.
    if (mprotect(addr, 3 * PAGE_SIZE, PROT_READ | PROT_WRITE) == -1) {
        perror("mprotect");
        exit(1);
    }

}

int main () {

    sleep (SLEEP_COUNTER);
    test_mapping_unmapping_start();
    sleep (SLEEP_COUNTER);
    test_mapping_unmapping_end();
    sleep (SLEEP_COUNTER);
    test_mapping_unmapping_middle();
    sleep (SLEEP_COUNTER);
    test_mapping_unmapping_all();
    sleep (SLEEP_COUNTER);
    test_mapping_unmapping_all_pages();
    sleep (SLEEP_COUNTER);
    test_mapping_on_demand();
    sleep (SLEEP_COUNTER);
    test_mapping_content_change();
    sleep (SLEEP_COUNTER);
    test_mapping_content_change_on_demand();
    sleep (SLEEP_COUNTER);
    test_mapping_protection();

    // Infinite wait.
    while (1);

    // Simple return.
    return 0;

}
