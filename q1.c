#if !defined(__x86_64__)
#error "This program only works for x86_64"
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/**
 * @brief Spin Lock object
 */
typedef struct {
    volatile int lock;
    unsigned int locker;
} spin_t;

/**
 * @brief Mutex object
 */
typedef struct {
    volatile int lock;
    unsigned int locker;
} mutex_t;

#define gettid() syscall(SYS_gettid)

/**
 * @brief Initialize the spinlock object
 * @param lock Spinlock object
 */
static inline int spin_init(spin_t *l)
{
    volatile int out;
    volatile int *lck = &(l->lock);
    asm("movl $0x0,(%1);" : "=r"(out) : "r"(lck));
    l->locker = 0;
    return 0;
}

/**
 * @brief Acquire a lock and wait atomically for the lock object
 * @param lock Spinlock object
 */
static inline int spin_acquire(spin_t *l)
{
    int out;
    volatile int *lck = &(l->lock);
    asm("whileloop:"
        "xchg %%al, (%1);"
        "test %%al,%%al;"
        "jne whileloop;"
        : "=r"(out)
        : "r"(lck));
    return 0;
}

/**
 * @brief Release lock atomically
 * @param lock Spinlock object
 */
static inline int spin_release(spin_t *l)
{
    int out;
    volatile int *lck = &(l->lock);
    asm("movl $0x0,(%1);" : "=r"(out) : "r"(lck));
    l->locker = 0;
    return 0;
}

/**
 * @brief Initialize the mutex lock object
 * @param lock Mutex Lock object
 */
static inline int mutex_init(mutex_t *m)
{
    volatile int *lck = &(m->lock);
    int out;
    asm("movl $0x0,(%1);" : "=r"(out) : "r"(lck));
    m->locker = 0;
    return 0;
}

/**
 * @brief Atomically acquire the lock and wait by sleeping if not available
 * @param lock Mutex Lock object
 */
static __attribute__((noinline)) int mutex_acquire(mutex_t *m)
{
    volatile int out;
    volatile int *lck = &(m->lock);
    asm("mutexloop:"
        "mov $1, %%eax;"
        "xchg %%al, (%%rdi);"
        "test %%al,%%al;"
        "je end"
        : "=r"(out)
        : "r"(lck));
    
    syscall(SYS_futex, m, FUTEX_WAIT, 1, NULL, NULL, 0);
    /*
    This  operation tests that the value at the futex word pointed to by the address uaddr still contains the expected value val, and if so, then sleeps waiting for a FUTEX_WAKE operation
    on the futex word.
    If the futex value does not match val, then the call fails immediately with the error EAGAIN.
    */
    asm("jmp mutexloop");
    asm("end:");
    return 0;
}

/**
 * @brief Release the lock object atomically and wake up waiting threads
 * @param lock Mutex Lock object
 */
static inline int mutex_release(mutex_t *m)
{
    volatile int out;
    volatile int *lck = &(m->lock);
    asm("movl $0x0,(%1);" : "=r"(out) : "r"(lck));
    m->locker = 0;
    syscall(SYS_futex, m, FUTEX_WAKE, 1, NULL, NULL, 0);
    return 0;
}

/**
 * @brief Default stack size for a thread
 */
#define STACK_SZ 65536

/**
 * @brief Default guard page size for a thread
 */
#define GUARD_SZ getpagesize()

/**
 * @brief Flags passed to clone system call in one-one implementation
 */
#define CLONE_FLAGS                                                     \
    (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | \
     CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID)
#define TGKILL 234

/**
 * @brief Thread Object
 */
typedef unsigned long thread_t;

/**
 * @brief Arguments passed to the wrapper function
 */
typedef struct {
    void (*f)(void *);
    void *arg;
    void *stack;
} funcargs_t;

/**
 * @brief Node in the TCB of the thread
 */
typedef struct __node {
    unsigned long int tid, tid_copy;
    void *ret_val;
    struct __node *next;
    funcargs_t *fa; //function, including its input parameter
} node_t;

/**
 * @brief Singly-linked list of thread control blocks (TCB)
 */
typedef struct {
    node_t *head, *tail;
} list_t;

#define INIT_SIGNALS()                              \
    do {                                            \
        sigset_t signal_mask;                       \
        sigfillset(&signal_mask);                   \
        sigdelset(&signal_mask, SIGINT);            \
        sigdelset(&signal_mask, SIGSTOP);           \
        sigdelset(&signal_mask, SIGCONT);           \
        sigprocmask(SIG_BLOCK, &signal_mask, NULL); \
    } while (0)

/**
 * @brief Initialize the singly-linked list
 * @param ll Pointer to a linked list object
 * @return 0 on sucess, -1 on failure -1
 */
int list_init(list_t *ll)
{
    if (!ll)
        return -1;
    ll->head = ll->tail = NULL;
    return 0;
}

/**
 * @brief Insert a node into the linked list
 * @param ll Pointer to the linked list
 * @param tid Thread ID of the new node
 * @return Pointer to new node on success, NULL on failure
 */
node_t *list_insert(list_t *ll, unsigned long int tid)
{
    node_t *tmp;
    if (posix_memalign((void **) &tmp, 8, sizeof(node_t))) {
        perror("ll alloc");
        return NULL;
    }

    tmp->tid = tid;
    tmp->next = NULL;
    tmp->ret_val = NULL;
    if (!ll->head) {
        ll->head = ll->tail = tmp;
    } else {
        ll->tail->next = tmp;
        ll->tail = tmp;
    }
    return tmp;
}

/**
 * @brief Delete a node from the linked list
 * @param ll Pointer to the linked list
 * @param tid Thread ID of the node
 * @return 0 on deletion, -1 on not found
 */
int list_delete(list_t *ll, unsigned long int tid)
{
    node_t *tmp = ll->head;
    if (!tmp)
        return -1;

    if (tmp->tid_copy == tid) {
        ll->head = ll->head->next;
        if (tmp->fa && munmap(tmp->fa->stack, STACK_SZ + getpagesize()))
            return errno;
        free(tmp->fa);
        free(tmp);
        if (!ll->head)
            ll->tail = NULL;
        return 0;
    }

    for (; tmp->next; tmp = tmp->next) {
        if (tmp->next->tid_copy == tid) {
            node_t *tmpNext = tmp->next->next;
            if (tmp->next == ll->tail)
                ll->tail = tmp;
            if (tmp->next->fa &&
                munmap(tmp->next->fa->stack, STACK_SZ + getpagesize()))
                return errno;
            free(tmp->next->fa);
            free(tmp->next);
            tmp->next = tmpNext;
            break;
        }
    }
    return 0;
}

/**
 * @brief Get the address of the node with a given tid
 * @param ll Pointer to linked list
 * @param tid Thread ID of the node
 * @return address of tail on success, NULL on failure
 */
static unsigned long int *get_tid_addr(list_t *ll, unsigned long int tid)
{
    for (node_t *tmp = ll->head; tmp; tmp = tmp->next) {
        if (tmp->tid_copy == tid)
            return &(tmp->tid);
    }
    return NULL;
}

static inline node_t *get_node_from_tid(list_t *ll, unsigned long int tid)
{
    for (node_t *tmp = ll->head; tmp; tmp = tmp->next) {
        if (tmp->tid_copy == tid)
            return tmp;
    }
    return NULL;
}

/**
 * @brief Send process wide signal dispositions to all active threads
 * @param ll Pointer to linked list
 * @param signum Signal number
 * @return 0 on success, errno on failure
 */
static int kill_all_threads(list_t *ll, int signum)
{
    pid_t pid = getpid(), delpid[100];
    int counter = 0;
    for (node_t *tmp = ll->head; tmp; tmp = tmp->next) {
        if (tmp->tid == gettid()) { //except itself
            tmp = tmp->next;
            continue;
        }

        printf("Killed thread %lu\n", tmp->tid);
        int ret = syscall(TGKILL, pid, tmp->tid, signum);
        if (ret == -1) {
            perror("tgkill");
            return errno;
        }
        if (signum == SIGINT || signum == SIGKILL)
            delpid[counter++] = tmp->tid;
    }
    if (signum == SIGINT || signum == SIGKILL) {
        for (int i = 0; i < counter; i++)
            list_delete(ll, delpid[i]);
    }
    return 0;
}

/**
 * @brief Umbrella function to free resources used by threads
 * @param l Pointer to list_t list
 */
static void delete_all_threads(list_t *l)
{
    int *deleted = NULL;
    int n_deleted = 0;
    for (node_t *tmp = l->head; tmp; tmp = tmp->next) {
        if (tmp->tid == 0) {
            deleted = realloc(deleted, (++n_deleted) * sizeof(int));
            deleted[n_deleted - 1] = tmp->tid_copy;
        }
    }

    for (int i = 0; i < n_deleted; i++)
        list_delete(l, deleted[i]);
    free(deleted);
}

/**
 * @brief Thread object
 */
typedef unsigned long int thread_t;

/**
 * @brief Macro for installing custom signal handlers for threads
 */
#define WRAP_SIGNALS(signum)                        \
    do {                                            \
        signal(signum, sig_handler);                \
        sigemptyset(&base_mask);                    \
        sigaddset(&base_mask, signum);              \
        sigprocmask(SIG_UNBLOCK, &base_mask, NULL); \
    } while (0)

#define RED "\033[1;31m"
#define RESET "\033[0m"

/**
 * @brief Custom signal handler function
 * @param signum Signal Number
 */
static void sig_handler(int signum)
{
    printf(RED "Signal Dispatched\n" RESET);
    printf("Thread tid %ld handled signal\n", (long) gettid());
    fflush(stdout);
}

static spin_t global_lock;
static list_t tid_list;

/**
 * @brief Cleanup handler for freeing resources of all threads at exit
 */
static void cleanup()
{
    delete_all_threads(&tid_list);
    free(tid_list.head);
}

/**
 * @brief Library initialzer for setting up data structures and handlers
 */
static void init()
{
    spin_init(&global_lock);
    INIT_SIGNALS();
    list_init(&tid_list);
    node_t *node = list_insert(&tid_list, getpid());
    node->tid_copy = node->tid;
    node->fa = NULL;
    atexit(cleanup);
}

/**
 * @brief Function to allocate a stack to One One threads
 * @param size Size of stack excluding the guard size
 * @param guard Size of guard page
 */
static void *alloc_stack(size_t size, size_t guard)
{
    /* Align the memory to a 64 bit compatible page size and associate a guard
     * area for the stack.
     */
    void *stack = mmap(NULL, size + guard, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) {
        perror("Stack Allocation");
        return NULL;
    }

    if (mprotect(stack, guard, PROT_NONE)) {
        munmap(stack, size + guard);
        perror("Stack Allocation");
        return NULL;
    }
    return stack;
}

void thread_exit(void *ret);

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/**
 * @brief Wrapper for the routine passed to the thread
 * @param fa Function pointer of the routine passed to the thread
 */
static int wrap(void *fa)
{
    funcargs_t *tmp = (funcargs_t *) fa;
    sigset_t base_mask;
    int sig_arr[] = {SIGTERM, SIGFPE, SIGSYS, SIGABRT, SIGPIPE};
    sigset_t mask_arr[ARRAY_SIZE(sig_arr)];
    for (int i = 0; i < ARRAY_SIZE(sig_arr); i++) {
        base_mask = mask_arr[i];
        WRAP_SIGNALS(sig_arr[i]);
    }
    (tmp->f)(tmp->arg);
    thread_exit(NULL);
    return 0;
}

/**
 * @brief Create a One One mapped thread
 * @param t Reference to the thread
 * @param routine Function associated with the thread
 * @param arg Arguments to the routine
 */
int thread_create(thread_t *t, void *routine, void *arg)
{
    spin_acquire(&global_lock);
    static bool init_state = false;
    if (!t || !routine) {
        spin_release(&global_lock);
        return EINVAL;
    }
    if (!init_state) {
        init_state = true;
        init();
    }

    node_t *node = list_insert(&tid_list, 0);
    if (!node) {
        printf("Thread address not found\n");
        spin_release(&global_lock);
        return -1;
    }

    funcargs_t *fa = malloc(sizeof(funcargs_t));
    if (!fa) {
        printf("Malloc failed\n");
        spin_release(&global_lock);
        return -1;
    }

    fa->f = routine;
    fa->arg = arg;
    void *thread_stack = alloc_stack(STACK_SZ, GUARD_SZ);
    if (!thread_stack) {
        perror("thread create");
        spin_release(&global_lock);
        free(fa);
        return errno;
    }
    fa->stack = thread_stack;
    /*
        since parent and child use the same space(CLONE_VM),
        parent_tid and child_tid point to the same tid.
    */
    thread_t tid = clone(wrap, (char *) thread_stack + STACK_SZ + GUARD_SZ,
                         CLONE_FLAGS, fa, &(node->tid), NULL, &(node->tid));
    node->tid_copy = tid;
    node->fa = fa;

    if (tid == -1) {
        perror("thread create");
        free(thread_stack);
        spin_release(&global_lock);
        return errno;
    }
    *t = tid;
    spin_release(&global_lock);
    return 0;
}

/**
 * @brief Function to send signals to a specific thread
 * @param tid TID of the thread to which the signal has to be sent
 * @param signum Signal number of the signal to be sent to the thread
 */
int thread_kill(pid_t tid, int signum)
{
    if (signum == 0)
        return -1;

    int ret;
    node_t *node = get_node_from_tid(&tid_list, tid);
    if (signum == SIGINT || signum == SIGCONT || signum == SIGSTOP) {
        kill_all_threads(&tid_list, signum);
        pid_t pid = getpid();
        ret = syscall(TGKILL, pid, gettid(), signum);
        if (ret == -1) {
            perror("tgkill");
            return ret;
        }
        return ret;
    }
    if (node->tid == 0)
        return -1;

    ret = syscall(TGKILL, getpid(), tid, signum);
    if (ret == -1) {
        perror("tgkill");
        return ret;
    }
    return ret;
}

/**
 * @brief Function to wait for a specific thread to terminate
 * @param t TID of the thread to wait for
 * @param guard Size of guard pag
 */
int thread_join(thread_t t, void **retval)
{
    spin_acquire(&global_lock);
    void *addr = get_tid_addr(&tid_list, t);
    if (!addr) {
        spin_release(&global_lock);
        return ESRCH;
    }
    if (*((pid_t *) addr) == 0) {
        spin_release(&global_lock);
        return EINVAL;
    }

    int ret = 0;
    /*
        thread_join will sleep until addr!=t, which means thread to be joined has finished its job.
        CLONE_CHILD_CLEARTID: Clear (zero) the child thread ID at the location pointed
                              to by child_tid (clone()) or cl_args.child_tid (clone3())
                              in child memory when the child exits, and do a wakeup on
                              the futex at that address.
    */
    while (*((pid_t *) addr) == t) {
        spin_release(&global_lock);
        ret = syscall(SYS_futex, addr, FUTEX_WAIT, t, NULL, NULL, 0);
        spin_acquire(&global_lock);
    }
    syscall(SYS_futex, addr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    if (retval)
        *retval = get_node_from_tid(&tid_list, t)->ret_val;

    spin_release(&global_lock);
    return ret;
}

/**
 * @brief Function to make a thread terminate itself
 * @param ret return value of the thread to be available to thread_join()
 * @note Implicit call to thread_exit is made by each thread after completing
 * the execution of routine
 */
void thread_exit(void *ret)
{
    spin_acquire(&global_lock);
    void *addr = get_tid_addr(&tid_list, gettid());
    if (!addr) {
        spin_release(&global_lock);
        return;
    }

    if (ret) {
        node_t *node = get_node_from_tid(&tid_list, gettid());
        node->ret_val = ret;
    }
    syscall(SYS_futex, addr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);

    spin_release(&global_lock);
    kill(SIGINT, gettid());
}

#define safe_printf(print_lock, f_, ...) \
    do {                                 \
        spin_acquire(print_lock);        \
        printf((f_), ##__VA_ARGS__);     \
        spin_release(print_lock);        \
    } while (0)

static mutex_t lock, rwlock;
static spin_t print_lock;

static int n_readers = 0, n_readers_in = 0, n_writers_in = 0;

static void f1(void)
{
    mutex_acquire(&lock);
    if (++n_readers == 1)
        mutex_acquire(&rwlock);
    mutex_release(&lock);

    safe_printf(&print_lock, "Reader process in\n");
    atomic_fetch_add(&n_readers_in, 1);
    mutex_acquire(&lock);
    if (--n_readers == 0)
        mutex_release(&rwlock);
    mutex_release(&lock);

    atomic_fetch_sub(&n_readers_in, 1);
    safe_printf(&print_lock, "Reader process out\n");
}

static void f2(void)
{
    mutex_acquire(&rwlock);
    atomic_fetch_add(&n_writers_in, 1);
    safe_printf(&print_lock, "Writer process in\n");
    mutex_release(&rwlock);

    atomic_fetch_sub(&n_writers_in, 1);
    safe_printf(&print_lock, "Writers process out\n");
}

int main()
{
    mutex_init(&lock);
    mutex_init(&rwlock);
    spin_init(&print_lock);

    atomic_init(&n_readers_in, 0);
    atomic_init(&n_writers_in, 0);

    thread_t readers[5], writers[5];
    for (int i = 0; i < 5; i++) {
        thread_create(&readers[i], f1, NULL);
        thread_create(&writers[i], f2, NULL);
    }

    for (int i = 0; i < 5; i++) {
        thread_join(writers[i], NULL);
        thread_join(readers[i], NULL);
    }

    return 0;
}