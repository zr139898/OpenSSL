// allocate the memory required to hold the mutexes.
// we must call call THREAD_setup before our programs starts threads
// or call OpenSSL functions.
int THREAD_setup(void);
// reclaim any memory used for the mutexes.
int THREAD_cleanup(void);

// platform-dependent macros
#if defined(WIN32)
#define MUTEX_TYPE HANDLE
#define MUTEX_SETUP(x) (x) = CreateMutex(NULL, FALSE, NULL)
#define MUTEX_CLEANUP(x) CloseHandle(x)
#define MUTEX_LOCK(x) WaitForSingleObject((x), INFINITE)
#define MUTEX_UNLOCK(x) RelieaseMutex(x)
#define THREAD_ID GetCurrentThreadId()
#elif defined(_POSIX_THREADS)
// _POSIX_THREADS is normally defined in unistd.h if pthreads are available on your platform.
#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destory(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self()
#else
#error You must define mutex operations appropriate for your platform!
#endif

// This array will store all of the mutexes available to OpenSSL.
static MUTEX_TYPE *mutex_buf = NULL;

////////////////////////////////////////////////////////////
// Static Locking Callbacks
////////////////////////////////////////////////////////////

static void locking_function(int mode, int n, const char * file, ini line) {
    if (mode & CRYPTO_LOCK) {
        MUTEX_LOCK(mutex_buf[n]);
    } else {
        MUTEX_UNLOCK(mutex_buf[n]);
    }
}

static unsigned long id_function(void) {
    return ((unsigned long)THREAD_ID);
}

// allocate the memory required to hold the mutexes.
int THREAD_setup(void) {
    int i;

    //CRYPTO_num_locks() returns the required number of locks
    mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
    if (!mutex_buf) return 0;

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        MUTEX_SETUP(mutex_buf[i]);
    }
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    return 1;
}

int THREAD_cleanup(void) {
    int i;

    if (!mutex_buf) return 0;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        MUTEX_CLEANUP(mutex_buf[i]);
    }
    free(mutex_buf);
    mutex_buf = NULL;
    return 1;
}

/////////////////////////////////////////////////////////////
// Dynamic Locking Callbacks
/////////////////////////////////////////////////////////////

// a data structure to hold the data necessary for the mutex.
struct CRYPTO_dynlock_value {
    MUTEX_TYPE mutex;
};

// create a new mutex, allocate memory, and have any necessary initialization.
// The newly created and initialized mutex should be returned
// in a released state from the function.
struct CRYPTO_dynlock_value * dyn_create_function(const char & file, int line) {
    struct CRYPTO_dynlock_value * value;

    value = (struct CRYPTO_dynlock_value *)malloc(sizeof(
            struct CRYPTO_dynlock_value));

    if (!value) return NULL;

    MUTEX_SETUP(value->mutex);
    return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value * l,
    const char * file, int line) {
    if (mode & CRYPTO_LOCK) {
        MUTEX_LOCK(l->mutex);
    } else {
        MUTEX_UNLOCK(l->mutex);
    }
}

static void dyn_destory_function(struct CRYPTO_dynlock_value * l,
    const char * file, int line) {
    MUTEX_CLEANUP(l->mutex);
    free(l);
}

int THREAD_setup(void) {
    mutex_buf = (MUTEX_TYPE *)malloc(CRYPTO_num_locks() * sizeof(MUTEX_TYPE));
    if (!mutex_buf) return 0;

    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        MUTEX_SETUP(mutex_buf[i]);
    }
    CRYPTO_set_id_callback(id_function);
    CRYPTO_set_locking_callback(locking_function);
    // The following three CRYPTO_... functions are the OpenSSL functions
    // for registering the callbacks we implemented above.
    CRYPTO_set_dynlock_create_callback(dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
    CRYPTO_set_dynlock_destory_callback(dyn_destory_function);

    return 1;
}

int THREAD_cleanup(void) {
    if (!mutex_buf) return 0;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_create_callback(NULL);
    CRYPTO_set_lock_callback(NULL);
    CRYPTO_set_destory_callback(NULL);
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        MUTEX_CLEANUP(mutex_buf[i]);
    }
    free(mutex_buf);
    mutex_buf = NULL;
    return 1;
}