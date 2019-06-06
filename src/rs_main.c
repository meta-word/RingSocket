// SPDX-License-Identifier: MIT
// Copyright © 2019 William Budd

#define _GNU_SOURCE // getgroups(), setresgid(), and setresuid()

#include "rs_conf.h"
#include "rs_event.h" // work()
#include "rs_socket.h" // listen_to_ports()

#include <dlfcn.h> // dlopen(), dlsym()
#include <fcntl.h> // open()
#include <grp.h> // setgroups()
#include <pwd.h> // getpwnam()
#include <signal.h> // signal()
#include <sys/capability.h> // cap_*()
#include <sys/eventfd.h> // eventfd()
#include <sys/prctl.h> // prctl()
#include <sys/resource.h> // setrlimit()
#include <sys/stat.h> // umask()

// As a security precaution, RingSocket requires to be run as user "ringsocket".
// This function assumes said user has been previously created (e.g., as part
// of the RingSocket installation procedures), and attempts to:
// 1) Obtain the passwd struct associated with "ringsocket" through getpwnam().
// 2) Verify that this user does not have access to a login shell.
// 3) Return the passwd struct's UID and GID to the caller, so that this process
//    can switch to running as "ringsocket", in case it's currently running as a
//    different user such as "root".
static rs_ret get_ringsocket_credentials(
    uid_t * uid,
    gid_t * gid
) {
    // getpwnam() is not thread-safe (unlike its more cumbersome cousin
    // getpwnam_r()), but RingSocket is still single-threaded at this point, so
    // that's OK.
    struct passwd * pw = getpwnam("ringsocket");
    if (!pw) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccesful getpwnam(\"ringsocket\"). "
            "RingSocket requires the existence of a system user named "
            "\"ringsocket\". Please make sure that such a user has been "
            "created.");
            return RS_FATAL;
    }
    *uid = pw->pw_uid;
    *gid = pw->pw_gid;
    // Verify that pw->pw_shell equals "/(usr/)(s)bin/['false'|'nologin']"
    char * ch = pw->pw_shell;
    if (*ch++ == '/' && (*ch != 'u' || (ch++, *ch++ == 's' && *ch++ == 'r' &&
                                        *ch++ == '/'))) {
        // Verify that the remainder equals "(s)bin/['false'|'nologin']"
        switch (*ch++) {
        case 's':
            if (*ch++ != 'b') {
                break;
            }
            // fall through
        case 'b':
            if (*ch++ != 'i' || *ch++ != 'n' || *ch++ != '/') {
                break;
            }
            // Verify that the remainder equals "false" or "nologin"
            if (!strcmp(ch, "false") || !strcmp(ch, "nologin")) {
                return RS_OK;
            }
        }
    }
    RS_LOG(LOG_CRIT, "The system user \"ringsocket\" should have no login "
        "shell: its shell path must be either (/usr)/(s)bin/false or "
        "(/usr)/(s)bin/nologin, but \"%s\" was found instead.", pw->pw_shell);
    return RS_FATAL;
}

static rs_ret remove_supplementary_groups(
    gid_t effective_gid
) {
    switch (getgroups(0, NULL)) {
    case -1:
        RS_LOG(LOG_CRIT, "Unsuccessful getgroups(0, NULL)");
        return RS_FATAL;
    case 0:
        return RS_OK;
    case 1:
        {
            gid_t gid = -1;
            if (getgroups(1, &gid) == -1) {
                RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful getgroups(1, &gid)");
                return RS_FATAL;
            }
            if (gid == effective_gid) {
                return RS_OK;
            }
        }
        break;
    default:
        if (!setgroups(0, NULL)) {
            return RS_OK;
        }
    }
    RS_LOG(LOG_CRIT, "Failed to remove supplementary groups: the RingSocket "
        "executable must be executed by either a user with the CAP_SETGID "
        "capability set (e.g., user \"root\"), such that it can remove such "
        "groups; or by a user that does not belong to any such groups in the "
        "first place.");
    return RS_FATAL;
}

static rs_ret remove_all_capabilities_except(
    cap_value_t * caps, // remove all capabilities except what's in this array
    int cap_c
) {
    cap_t cap = cap_init();
    if (!cap) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful cap_init()");
        return RS_FATAL;
    }
    if (cap_set_flag(cap, CAP_PERMITTED, cap_c, caps, CAP_SET) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful cap_set_flag(cap, CAP_PERMITTED, "
            "%d, caps, CAP_SET)", cap_c);
        return RS_FATAL;
    }
    if (cap_set_flag(cap, CAP_EFFECTIVE, cap_c, caps, CAP_SET) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful cap_set_flag(cap, CAP_EFFECTIVE, "
            "%d, caps, CAP_SET)", cap_c);
        return RS_FATAL;
    }
    if (cap_set_proc(cap) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful cap_set_proc(cap)");
        return RS_FATAL;
    }
    if (cap_free(cap) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful cap_free(cap)");
        return RS_FATAL;
    }
    return RS_OK;
}

static rs_ret set_credentials_and_capabilities(
    void
) {
    uid_t uid = -1;
    gid_t gid = -1;
    RS_GUARD(get_ringsocket_credentials(&uid, &gid));
    RS_GUARD(remove_supplementary_groups(gid));
    // Until now RingSocket may have been running as a user more privileged than
    // "ringsocket" such as root. Call setresgid() and setresuid() to switch to
    // running as "ringsocket" from here on.
    if (setresgid(gid, gid, gid) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful setresgid(%u, %u, %u)",
            gid, gid, gid);
        return RS_FATAL;
    }
    // "Drop down" to user "ringsocket" without losing privileged capabilities
    // just yet, because we need to whitelist the contents of the caps array
    // below while losing the rest. However, if we do that before calling
    // setresuid(), we lose the privilege needed to call setresuid() itself.
    if (prctl(PR_SET_KEEPCAPS, 1) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful prctl(PR_SET_KEEPCAPS, 1)");
        return RS_FATAL;
    }
    if (setresuid(uid, uid, uid) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful setresuid(%u, %u, %u)",
            uid, uid, uid);
        return RS_FATAL;
    }
    cap_value_t caps[] = {
        CAP_DAC_READ_SEARCH, // For reading configuration and certificate files
        CAP_NET_BIND_SERVICE, // For binding to privileged ports
        CAP_NET_RAW, // For setsockopt SO_BINDTODEVICE
        CAP_SYS_NICE, // For setting CPU affinity (currently not implemented)
        CAP_SYS_RESOURCE // For setting RLIMIT_NOFILE above the default maximum
    };
    return remove_all_capabilities_except(caps, RS_ELEM_C(caps));
}

// Daemonize the traditional way
static rs_ret daemonize(
    void
) {
    switch (fork()) {
    case -1:
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful fork()");
        return RS_FATAL;
    case 0:
        break;
    default:
        _exit(EXIT_SUCCESS);
    }
    if (setsid() == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful setsid()");
        return RS_FATAL;
    }
    signal(SIGHUP, SIG_IGN);
    switch (fork()) {
    case -1:
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful 2nd fork()");
        return RS_FATAL;
    case 0:
        break;
    default:
        _exit(EXIT_SUCCESS);
    }
    if (chdir("/") == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful chdir(\"/\")");
        return RS_FATAL;
    }
    umask(0);
    if (close(STDIN_FILENO) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful close(STDIN_FILENO)");
        return RS_FATAL;
    }
    if (close(STDOUT_FILENO) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful close(STDOUT_FILENO)");
        return RS_FATAL;
    }
    if (close(STDERR_FILENO) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful close(STDERR_FILENO)");
        return RS_FATAL;
    }
    if (open("/dev/null", O_RDONLY) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "failed to open /dev/null as stdin");
        return RS_FATAL;
    }
    if (open("/dev/null", O_WRONLY) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "failed to open /dev/null as stdout");
        return RS_FATAL;
    }
    if (open("/dev/null", O_RDWR) == -1) {
        RS_LOG_ERRNO(LOG_CRIT, "failed to open /dev/null as stderr");
        return RS_FATAL;
    }
    return RS_OK;
}

static rs_ret set_limits(
    struct rs_conf const * conf
) {
    // RLIMIT_NOFILE is the only limit configuration implemented as of yet,
    // but that may change...
    struct rlimit rlim = {
        .rlim_cur = conf->fd_alloc_c,
        .rlim_max = conf->fd_alloc_c
    };
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        RS_LOG(LOG_CRIT, "Unsuccessful setrlimit(RLIMIT_NOFILE, &rlim)");
        return RS_FATAL;
    }
    return RS_OK;
}

static rs_ret start_app(
    char const * so_path,
    struct rs_app_args * app_args
) {
    // Load the app DLL
    dlerror();
    void * so = dlopen(so_path, RTLD_NOLOAD | RTLD_NOW);
    if (!so) {
        RS_LOG(LOG_ERR, "Unsuccessful dlopen(\"%s\", RTLD_NOLOAD | RTLD_NOW). "
            "Failed to load the app as a dynamic library: %s", so_path,
            dlerror());
        return RS_FATAL;
    }
    int (*cb)(void *) = NULL;
    *(void * *) (&cb) = dlsym(so, "ringsocket_cb");
    if (!cb) {
        RS_LOG(LOG_ERR, "Unsuccessful dlsym(so, \"ringsocket_cb\"). \"%s\" "
            "does not seem to expose the required \"ringsocket_cb\" callback "
            "function (as defined by RS_APP()): %s", so_path, dlerror());
        return RS_FATAL;
    }
    // Run the app callback in a dedicated (long-lived) C11 thread
    if (thrd_create((thrd_t []){0}, cb, app_args) != thrd_success) {
        RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful thrd_create((thrd_t []){0}, "
            "cb, app_args)");
        return RS_FATAL;
    }
    return RS_OK;
}

static rs_ret spawn_app_and_worker_threads(
    struct rs_conf const * conf
) {
    // Each (app thread <-> worker_thread) pair needs access to one allocated
    // rs_shared_io struct.
    //
    // However, the current (and at this point only) thread will soon become the
    // last worker thread, which means allocating the rs_shared_io structs
    // directly here should be avoided because that might cause the array to
    // linger in one of this thread's cache lines, in which case any stores
    // between an app and a different worker thread would cause false sharing
    // with this thread.
    //
    // That scenario is prevented through a layer of indirection: the elements
    // of the all_io_pairs array are not the io_pairs structs themselves, but
    // pointers to said structs that will only change once: when the threads
    // corresponding to their write ends allocate them.
    struct rs_thread_io_pairs * all_io_pairs[conf->app_c];
    memset(all_io_pairs, 0, sizeof(all_io_pairs));

    struct rs_thread_sleep_state * app_sleep_states = NULL;
    struct rs_thread_sleep_state * worker_sleep_states = NULL;
    // The current thread will become a worker thread, which means
    // app_sleep_states can be initialized here, because all worker threads need
    // to know all app sleep states anyway ("true sharing"); but
    // worker_sleep_states should be initialized in a different thread, because
    // worker threads need not know about other worker threads (false sharing).
    RS_CACHE_ALIGNED_CALLOC(app_sleep_states, conf->app_c);
    // worker_sleep_states are initialized by the app thread with app_i == 0.

    // Apps use futex_wait() directly on their app_sleep_states, but dormant
    // worker threads only wake on file descriptor events through epoll_wait(),
    // so they need to be awoken with eventfds instead, to be used in accordance
    // with their worker_sleep_states.
    int worker_eventfds[conf->worker_c];

    for (int * e = worker_eventfds; e < worker_eventfds + conf->worker_c; e++) {
        *e = eventfd(0, EFD_NONBLOCK);
        if (*e == -1) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful eventfd(0, EFD_NONBLOCK)");
        }
    }
    
    struct rs_app_args app_args[conf->app_c];
    for (size_t i = 0; i < conf->app_c; i++) {
        app_args[i].conf = conf;
        app_args[i].app_io_pairs = all_io_pairs + i;
        app_args[i].app_sleep_state = app_sleep_states + i;
        app_args[i].worker_sleep_states = &worker_sleep_states;
        app_args[i].worker_eventfds = worker_eventfds;
        app_args[i].app_i = i;
        app_args[i].log_mask = _rs_log_mask;
        RS_GUARD(start_app(conf->apps[i].app_path, app_args + i));
    }

    // Wait for all apps to sleep on futex_wait(), to ensure that all io_pairs
    // and worker_sleep_states have been allocated, and worker threads get
    // up-to-date thread_io_pairs pointers and worker_sleep_state pointers.
    for (size_t i = 0; i < conf->app_c; i++) {
        while (!app_sleep_states[i].is_asleep) {
            thrd_sleep(&(struct timespec){ .tv_nsec = 1000000 }, NULL); // 1 ms
        }
    }

    struct rs_worker_args worker_args[conf->worker_c];
    for (size_t i = 0;; i++) {
        worker_args[i].conf = conf;
        worker_args[i].all_io_pairs = all_io_pairs;
        worker_args[i].app_sleep_states = app_sleep_states;
        worker_args[i].worker_sleep_state = worker_sleep_states + i;
        worker_args[i].worker_eventfd = worker_eventfds[i];
        worker_args[i].worker_i = i;
        if (i + 1 >= conf->worker_c) {
            // All apps and workers have been spawned, except for the last
            // worker, so now this thread will assume the role of that last
            // worker.
            return work(worker_args + i) == thrd_success ? RS_OK : RS_FATAL;
        }
        // Spawn a dedicated (long-lived) C11 worker thread
        if (thrd_create((thrd_t []){0}, (int (*)(void *)) work,
            worker_args + i) != thrd_success) {
            RS_LOG_ERRNO(LOG_CRIT, "Unsuccessful thrd_create((thrd_t []){0}, "
                "work, worker_args + %u)", i);
            return RS_FATAL;
        }
    }
}

static rs_ret start(
    int arg_c,
    char * const * args
) {
    openlog("RingSocket", LOG_PID, LOG_DAEMON);
    if (arg_c > 2) {
        RS_LOG(LOG_WARNING, "RingSocket received %d command-line arguments, "
            "but can handle only one: the path to the RingSocket configuration "
            "file -- which in this case is assumed to be: \"%s\". "
            "Ignoring all other arguments!",
            arg_c, args[1]);
    }
    RS_GUARD(set_credentials_and_capabilities());
    RS_GUARD(daemonize());
    struct rs_conf conf = {0};
    RS_GUARD(get_configuration(&conf, arg_c > 1 ? args[1] : NULL));
    RS_GUARD(set_limits(&conf));
    RS_GUARD(bind_to_ports(&conf));
    // todo: remove_capabilities_no_longer_needed()
    return spawn_app_and_worker_threads(&conf);
}
    
int main(
    int arg_c, // 1 or 2
    char * * args // "ringsocket" and optionally the path to the conf file
) {
    // todo: start() currently isn't capable of returning RS_OK, because there
    // is no code yet to catch any signal needed to shutdown gracefully...
    return start(arg_c, args) == RS_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
