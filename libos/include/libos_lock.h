/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#pragma once

#include <stdbool.h>

#include "assert.h"
#include "libos_thread.h"
#include "libos_types.h"
#include "pal.h"

static inline bool lock_created(struct libos_lock* l) {
    return l->lock != NULL;
}

// TODO (MST): change default/revisit conditional
#define LOCK_TRACING
#ifdef LOCK_TRACING
// Note: lock can be moved, in particular for g_process.fs_lock, so we have to take lock->lock as id
// but also have to swap order of log and function call between create and rest as for create value
// is valid only at end (whereas for clear & destroy it is valid only in beginning!).
// To get proper context we have to macro-wrap the lock functions and create_lock is often called
// inside a condition, so we have to do some hoopla with thread-local temporary variable
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static bool __create_lock_result;  // TODO (MST): this variable should really be thread local but
                                   // just adding __thread or _Thread_local did not compile, so for
                                   // now live with the (not so likely) risk of race conditions with
                                   // conflicting create_lock calls ..
#pragma GCC diagnostic pop
#define create_lock(l)                                                                        \
    (__create_lock_result = _create_lock(l), log_trace("_create_lock(%p/" #l ")", (l)->lock), \
     __create_lock_result)
#define LOCK_PRE_TRACE(func, l)  log_trace(#func "(%p/" #l ")", (l)->lock), func(l)
#define LOCK_POST_TRACE(func, l) func(l), log_trace(#func "(%p/" #l ")", (l)->lock)
#define clear_lock(lock)         LOCK_PRE_TRACE(_clear_lock, lock)
#define destroy_lock(lock)       LOCK_PRE_TRACE(_destroy_lock, lock)
#define lock(lock)               LOCK_POST_TRACE(_lock, lock)
#define unlock(lock)             LOCK_PRE_TRACE(_unlock, lock)
#else
#define clear_lock(lock)   _clear_lock((lock))
#define create_lock(lock)  _create_lock((lock))
#define destroy_lock(lock) _destroy_lock((lock))
#define lock(lock)         _lock((lock))
#define unlock(lock)       _unlock((lock))
#endif

static inline void _clear_lock(struct libos_lock* l) {
    l->lock  = NULL;
    l->owner = 0;
}

static inline bool _create_lock(struct libos_lock* l) {
    l->owner = 0;
    return PalEventCreate(&l->lock, /*init_signaled=*/true, /*auto_clear=*/true) == 0;
}

static inline void _destroy_lock(struct libos_lock* l) {
    PalObjectDestroy(l->lock);
    _clear_lock(l);
}

static inline void _lock(struct libos_lock* l) {
    assert(l->lock);

    while (PalEventWait(l->lock, /*timeout=*/NULL) < 0)
        /* nop */;

    l->owner = get_cur_tid();
}

static inline void _unlock(struct libos_lock* l) {
    assert(l->lock);
    l->owner = 0;
    PalEventSet(l->lock);
}

#ifdef DEBUG
static inline bool locked(struct libos_lock* l) {
    if (!l->lock) {
        return false;
    }
    return get_cur_tid() == l->owner;
}
#endif // DEBUG
