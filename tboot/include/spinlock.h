#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__
#include <config.h>

typedef struct {
    volatile s16 lock;
    s8 recurse_cpu;
    u8 recurse_cnt;
} spinlock_t;

#define SPIN_LOCK_UNLOCKED /*(spinlock_t)*/ { 1, -1, 0 }

#define spin_lock_init(x)	do { *(x) = (spinlock_t) SPIN_LOCK_UNLOCKED; } while(0)
#define spin_is_locked(x)	(*(volatile char *)(&(x)->lock) <= 0)
static inline void _raw_spin_lock(spinlock_t *lock)
{
    __asm__ __volatile__ (
        "1:  lock; decb %0         \n"
        "    js 2f                 \n"
        ".section .text.lock,\"ax\"\n"
        "2:  cmpb $0,%0            \n"
        "    rep; nop              \n"
        "    jle 2b                \n"
        "    jmp 1b                \n"
        ".previous"
        : "=m" (lock->lock) : : "memory" );
}

static inline void _raw_spin_unlock(spinlock_t *lock)
{
#if !defined(CONFIG_X86_OOSTORE)
/*    ASSERT(spin_is_locked(lock));*/
    __asm__ __volatile__ (
	"movb $1,%0" 
        : "=m" (lock->lock) : : "memory" );
#else
    char oldval = 1;
/*    ASSERT(spin_is_locked(lock));*/
    __asm__ __volatile__ (
	"xchgb %b0, %1"
        : "=q" (oldval), "=m" (lock->lock) : "0" (oldval) : "memory" );
#endif
}
#define spin_lock(_lock)             _raw_spin_lock(_lock)
#define spin_unlock(_lock)           _raw_spin_unlock(_lock)
#define DEFINE_SPINLOCK(x) spinlock_t x = SPIN_LOCK_UNLOCKED

#endif /* __SPINLOCK_H__ */
