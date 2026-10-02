/*
 * pam_host.c — a non-Rust host for the pam_wsl_webauthn.so ABI/FFI tiers.
 *
 * The audit's two availability defects (L9-1 SIGPIPE host-kill, L9-2 stderr
 * spin) lived in the gap between "runs under `cargo test`" (a Rust host, where
 * the runtime installs SIGPIPE=SIG_IGN) and "runs under sudo/su/sshd" (a C host
 * that leaves SIGPIPE at SIG_DFL). This program closes that gap: it is compiled
 * and invoked by `tests/c_host.rs` (never checked in as a binary) and drives the
 * real `pam_wsl_webauthn.so`.
 *
 * Invocation:
 *
 *   pam_host abi <so-path>
 *       dlopen(3) the built module, dlsym(3) all six `pam_sm_*` exports, and call
 *       the five non-authentication entry points through the loaded object (they
 *       are safe with a NULL handle and must return PAM_SUCCESS / PAM_IGNORE).
 *       Proves the C ABI surface is callable, not merely present.
 *
 *   pam_host libpam <service-confdir> <service> <user> <expect> <require_conv>
 *       Resets SIGPIPE to SIG_DFL, then pam_start_confdir(3) against a service
 *       file that loads the built module and pam_authenticate(3). <expect> is one
 *       of success|deny|failclosed. <require_conv> is 0/1: when 1, at least one
 *       application conversation callback must have been observed (the module's
 *       PAM_CONV pre-prompt path). Exits 0 iff the observed code matches and the
 *       conversation requirement is met.
 *
 *   pam_host concurrent <confdir> <service0> <service1> <user> <nthreads> <expect>
 *       Drive <nthreads> concurrent pam_start_confdir(3)+pam_authenticate(3)
 *       calls from as many pthreads, alternating between <service0> (no module
 *       args) and <service1> (a `debug` module argument), all against a
 *       provisioned store. Proves the module is callable concurrently from a
 *       non-Rust host with *distinct* per-handle arguments and does not crash,
 *       deadlock, or cross-contaminate. Every call must return <expect>.
 *
 * Exit codes (libpam/concurrent modes): 0 = match; 2 = setup error; 3 = PAM code
 * mismatch; 4 = conversation callback missing; 5 = concurrency setup failure.
 */

#include <security/pam_appl.h>

#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PAM_SUCCESS
#define PAM_SUCCESS 0
#endif

/* Minimal ABI constants (mirror <security/_pam_types.h>). */
#define PAM_IGNORE 25

/* Thread-local so concurrent PAM calls do not race on the counter. */
static __thread int conv_calls = 0;

static int conversation(int num_msg, const struct pam_message **msg,
                        struct pam_response **resp, void *appdata_ptr) {
    (void)appdata_ptr;
    conv_calls += 1;
    if (resp != NULL) {
        *resp = NULL; /* info/error messages need no reply */
    }
    for (int i = 0; i < num_msg; i++) {
        const struct pam_message *m = msg[i];
        const char *text = (m != NULL && m->msg != NULL) ? m->msg : "";
        fprintf(stderr, "conv[%d] style=%d msg=%s\n", i,
                m != NULL ? m->msg_style : -1, text);
    }
    return PAM_SUCCESS;
}

typedef int (*pam_sm_fn)(pam_handle_t *, int, int, const char **);

static void *must_dlsym(void *handle, const char *name) {
    void *sym = dlsym(handle, name);
    if (sym == NULL) {
        fprintf(stderr, "dlsym(%s) failed: %s\n", name, dlerror());
        exit(2);
    }
    return sym;
}

static int run_abi(const char *so_path) {
    void *handle = dlopen(so_path, RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", so_path, dlerror());
        return 2;
    }

    /* All six exports must be resolvable. */
    static const char *exports[] = {
        "pam_sm_authenticate",  "pam_sm_setcred",
        "pam_sm_acct_mgmt",     "pam_sm_open_session",
        "pam_sm_close_session", "pam_sm_chauthtok",
    };
    for (size_t i = 0; i < sizeof(exports) / sizeof(exports[0]); i++) {
        (void)must_dlsym(handle, exports[i]);
    }

    /* Invoke the five non-authentication entry points through the loaded object.
     * With a NULL handle these do not touch libpam; they exercise the real guarded
     * FFI frame and must return the contract values. */
    pam_sm_fn setcred = (pam_sm_fn)must_dlsym(handle, "pam_sm_setcred");
    pam_sm_fn acct = (pam_sm_fn)must_dlsym(handle, "pam_sm_acct_mgmt");
    pam_sm_fn open_session = (pam_sm_fn)must_dlsym(handle, "pam_sm_open_session");
    pam_sm_fn close_session = (pam_sm_fn)must_dlsym(handle, "pam_sm_close_session");
    pam_sm_fn chauthtok = (pam_sm_fn)must_dlsym(handle, "pam_sm_chauthtok");

    int rc_setcred = setcred(NULL, 0, 0, NULL);
    int rc_acct = acct(NULL, 0, 0, NULL);
    int rc_open = open_session(NULL, 0, 0, NULL);
    int rc_close = close_session(NULL, 0, 0, NULL);
    int rc_chauthtok = chauthtok(NULL, 0, 0, NULL);

    printf("setcred=%d acct=%d open=%d close=%d chauthtok=%d\n", rc_setcred,
           rc_acct, rc_open, rc_close, rc_chauthtok);

    int ok = rc_setcred == PAM_SUCCESS && rc_acct == PAM_IGNORE &&
             rc_open == PAM_IGNORE && rc_close == PAM_IGNORE &&
             rc_chauthtok == PAM_IGNORE;

    dlclose(handle);
    return ok ? 0 : 3;
}

static int expect_matches(const char *expect, int rc) {
    if (strcmp(expect, "success") == 0) {
        return rc == PAM_SUCCESS;
    }
    if (strcmp(expect, "deny") == 0) {
        return rc == PAM_AUTH_ERR;
    }
    if (strcmp(expect, "failclosed") == 0) {
        return rc == PAM_AUTHINFO_UNAVAIL || rc == PAM_USER_UNKNOWN;
    }
    fprintf(stderr, "unknown expectation %s\n", expect);
    return -1;
}

static int run_libpam(const char *confdir, const char *service, const char *user,
                      const char *expect, int require_conv) {
    /* A real sudo/su/sshd host leaves SIGPIPE at SIG_DFL. Rust's runtime would
     * have set it to SIG_IGN, masking an EPIPE that kills a C host. */
    signal(SIGPIPE, SIG_DFL);

    struct pam_conv conv = {conversation, NULL};
    pam_handle_t *pamh = NULL;
    int rc = pam_start_confdir(service, user, &conv, confdir, &pamh);
    if (rc != PAM_SUCCESS) {
        fprintf(stderr, "pam_start_confdir=%d\n", rc);
        return 2;
    }

    int auth = pam_authenticate(pamh, 0);
    fprintf(stderr, "pam_authenticate=%d (%s) conv_calls=%d\n", auth,
            pam_strerror(pamh, auth), conv_calls);
    pam_end(pamh, auth);

    int matched = expect_matches(expect, auth);
    if (matched <= 0) {
        return matched == 0 ? 3 : 2;
    }
    if (require_conv && conv_calls == 0) {
        fprintf(stderr, "module did not invoke the PAM conversation\n");
        return 4;
    }
    return 0;
}

struct worker {
    const char *confdir;
    const char *service;
    const char *user;
    const char *expect;
    int rc;
    int auth;
    int conv;
};

static void *worker_main(void *arg) {
    struct worker *w = (struct worker *)arg;
    struct pam_conv conv = {conversation, NULL};
    pam_handle_t *pamh = NULL;
    int rc = pam_start_confdir(w->service, w->user, &conv, w->confdir, &pamh);
    if (rc != PAM_SUCCESS) {
        w->rc = 2;
        return NULL;
    }
    int auth = pam_authenticate(pamh, 0);
    w->auth = auth;
    w->conv = conv_calls;
    pam_end(pamh, auth);
    w->rc = expect_matches(w->expect, auth) == 1 ? 0 : 3;
    return NULL;
}

static int run_concurrent(const char *confdir, const char *svc0,
                          const char *svc1, const char *user, int nthreads,
                          const char *expect) {
    signal(SIGPIPE, SIG_DFL);
    if (nthreads < 2) {
        nthreads = 2;
    }
    pthread_t *tids = calloc((size_t)nthreads, sizeof(*tids));
    struct worker *ws = calloc((size_t)nthreads, sizeof(*ws));
    if (tids == NULL || ws == NULL) {
        free(tids);
        free(ws);
        return 5;
    }
    for (int i = 0; i < nthreads; i++) {
        ws[i].confdir = confdir;
        ws[i].service = (i % 2 == 0) ? svc0 : svc1;
        ws[i].user = user;
        ws[i].expect = expect;
        ws[i].rc = -1;
        ws[i].auth = -2;
        if (pthread_create(&tids[i], NULL, worker_main, &ws[i]) != 0) {
            free(tids);
            free(ws);
            return 5;
        }
    }
    int failures = 0;
    for (int i = 0; i < nthreads; i++) {
        pthread_join(tids[i], NULL);
        if (ws[i].rc != 0) {
            failures++;
            fprintf(stderr, "thread %d (%s): rc=%d auth=%d conv=%d\n", i,
                    ws[i].service, ws[i].rc, ws[i].auth, ws[i].conv);
        }
    }
    free(tids);
    free(ws);
    return failures == 0 ? 0 : 3;
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "abi") == 0) {
        return run_abi(argv[2]);
    }
    if (argc >= 7 && strcmp(argv[1], "libpam") == 0) {
        return run_libpam(argv[2], argv[3], argv[4], argv[5], atoi(argv[6]));
    }
    if (argc >= 8 && strcmp(argv[1], "concurrent") == 0) {
        return run_concurrent(argv[2], argv[3], argv[4], argv[5], atoi(argv[6]),
                              argv[7]);
    }
    fprintf(stderr,
            "usage: pam_host abi <so>\n"
            "       pam_host libpam <confdir> <service> <user> "
            "<success|deny|failclosed> <require_conv 0|1>\n"
            "       pam_host concurrent <confdir> <svc0> <svc1> <user> "
            "<nthreads> <success|deny|failclosed>\n");
    return 2;
}
