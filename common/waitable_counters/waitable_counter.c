#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/sched/task.h>

DEFINE_MUTEX(counter_lock);
static int counter = 0;

void increment(void) {
    mutex_lock(&counter_lock);
    counter += 1;
    mutex_unlock(&counter_lock);
}

void decrement(wait_queue_head_t *wq) {
    mutex_lock(&counter_lock);
    counter -= 1;

    if (counter == 0) {
        wake_up_all(wq);
    }
    mutex_unlock(&counter_lock);
}

int read_counter(void) {
    mutex_lock(&counter_lock);
    int current_value = counter;
    mutex_unlock(&counter_lock);

    return current_value;
}