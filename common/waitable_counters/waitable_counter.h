#include <linux/wait.h>

void increment(void);
void decrement(wait_queue_head_t *wq);
int read_counter(void);