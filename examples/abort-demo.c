/* A deliberate SIGABRT for learning core-dump analysis; no firmware code. */
#include <signal.h>
#include <stdio.h>

static void finish_experiment(int marker)
{
    fprintf(stderr, "abort-demo: marker=%d; raising SIGABRT\n", marker);
    raise(SIGABRT);
}

int main(void)
{
    finish_experiment(2024);
    return 0;
}
