#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__
#include <config.h>

typedef struct {
    volatile s16 lock;
} spinlock_t;

#define SPIN_LOCK_UNLOCKED /*(spinlock_t)*/ { 1 }

#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED

#define spin_lock_init(x)	do { *(x) = (spinlock_t) SPIN_LOCK_UNLOCKED; } while(0)

#define spin_is_locked(x)	((x)->lock <= 0)

static always_inline void spin_unlock(spinlock_t *lock)
{
/*    ASSERT(_raw_spin_is_locked(lock));*/
    __asm__ __volatile__ (
        "movw $1,%0"
        : "=m" (lock->lock) : : "memory" );
}

static always_inline int spin_trylock(spinlock_t *lock)
{
    s16 oldval;
    __asm__ __volatile__ (
        "xchgw %w0,%1"
        :"=r" (oldval), "=m" (lock->lock)
        :"0" (0) : "memory" );
    return (oldval > 0);
}

static always_inline void spin_lock(spinlock_t *lock)
{
    while ( unlikely(!spin_trylock(lock)) )
        while ( likely(spin_is_locked(lock)) )
            cpu_relax();
}

#if 0
static inline void _raw_spin_lock(spinlock_t *lock)
{
    __asm__ __volatile__ (
        "1:  lock; decw %0         \n"
        "    js 2f                 \n"
        ".section .text.lock,\"ax\"\n"
        "2:  cmpw $0,%0            \n"
        "    rep; nop              \n"
        "    jle 2b                \n"
        "    jmp 1b                \n"
        ".previous"
        : "=m" (lock->lock) : : "memory" );
}

static inline void _raw_spin_unlock(spinlock_t *lock)
{
/*    ASSERT(spin_is_locked(lock));*/
    __asm__ __volatile__ (
	"movw $1,%0"
        : "=m" (lock->lock) : : "memory" );
}
#define spin_lock(_lock)             _raw_spin_lock(_lock)
#define spin_unlock(_lock)           _raw_spin_unlock(_lock)
#endif

#endif /* __SPINLOCK_H__ */
