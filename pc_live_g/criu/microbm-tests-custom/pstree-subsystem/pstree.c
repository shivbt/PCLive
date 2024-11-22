#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define SLEEP_COUNTER 20
#define NUM_LEVELS 2

void create_process_tree (int levels, int processes_per_level) {

    // Create process tree.
    for (int i = 1; i <= levels; i++) {
        for (int j = 1; j <= processes_per_level; j++) {
            pid_t child_pid = fork ();
            if (child_pid < 0) {
                perror ("Fork error");
                exit (-1);
            } else if (child_pid == 0) {
                break; // Children don't fork further
            }
        }
    }

}

int main (int argc, char *argv[]) {

    int levels = 1;
    int processes_per_level = 1;
    int root_pid = getpid();

    while (1) {
        sleep (SLEEP_COUNTER);
        create_process_tree (levels, processes_per_level);
        if (getpid() != root_pid)
            break;
        levels += 1;
        if (levels > NUM_LEVELS)
            break;
    }

    // Infinite wait.
    while (1) {
        printf ("Waiting %d\n", getpid());
        sleep (1);
    }

    // Simple return.
    return 0;

}
