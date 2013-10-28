/* -*- linux-c -*-
 * linux/kernel/ipipe/core.c
 *
 * Copyright (C) 2002-2012 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Architecture-independent I-PIPE core support.
 */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/bitops.h>
#include <linux/tick.h>
#include <linux/interrupt.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#endif	/* CONFIG_PROC_FS */
#include <linux/ipipe_trace.h>
#include <linux/ipipe.h>
#include <ipipe/setup.h>

struct ipipe_domain ipipe_root;
EXPORT_SYMBOL_GPL(ipipe_root);

struct ipipe_domain *ipipe_head_domain = &ipipe_root;
EXPORT_SYMBOL_GPL(ipipe_head_domain);

#ifdef CONFIG_SMP
static __initdata struct ipipe_percpu_domain_data bootup_context = {
	.status = IPIPE_STALL_MASK,
	.domain = &ipipe_root,
};
#else
#define bootup_context ipipe_percpu.root
#endif	/* !CONFIG_SMP */

DEFINE_PER_CPU(struct ipipe_percpu_data, ipipe_percpu) = {
	.root = {
		.status = IPIPE_STALL_MASK,
		.domain = &ipipe_root,
	},
	.curr = &bootup_context,
	.hrtimer_irq = -1,
#ifdef CONFIG_IPIPE_DEBUG_CONTEXT
	.context_check = 1,
#endif
};
EXPORT_PER_CPU_SYMBOL_GPL(ipipe_percpu);

/* Up to 2k of pending work data per CPU. */
#define WORKBUF_SIZE 2048
static DEFINE_PER_CPU_ALIGNED(unsigned char[WORKBUF_SIZE], work_buf);
static DEFINE_PER_CPU(void *, work_tail);
static unsigned int __ipipe_work_virq;

static void __ipipe_do_work(unsigned int virq, void *cookie);

#ifdef CONFIG_SMP

#define IPIPE_CRITICAL_TIMEOUT	1000000
static cpumask_t __ipipe_cpu_sync_map;
static cpumask_t __ipipe_cpu_lock_map;
static cpumask_t __ipipe_cpu_pass_map;
static unsigned long __ipipe_critical_lock;
static IPIPE_DEFINE_SPINLOCK(__ipipe_cpu_barrier);
static atomic_t __ipipe_critical_count = ATOMIC_INIT(0);
static void (*__ipipe_cpu_sync) (void);

#else /* !CONFIG_SMP */
/*
 * Create an alias to the unique root status, so that arch-dep code
 * may get fast access to this percpu variable including from
 * assembly.  A hard-coded assumption is that root.status appears at
 * offset #0 of the ipipe_percpu struct.
 */
extern unsigned long __ipipe_root_status
__attribute__((alias(__stringify(ipipe_percpu))));
EXPORT_SYMBOL_GPL(__ipipe_root_status);

#endif /* !CONFIG_SMP */

IPIPE_DEFINE_SPINLOCK(__ipipe_lock);

static unsigned long __ipipe_virtual_irq_map;

#ifdef CONFIG_PRINTK
unsigned int __ipipe_printk_virq;
int __ipipe_printk_bypass;
#endif /* CONFIG_PRINTK */

#ifdef CONFIG_PROC_FS

struct proc_dir_entry *ipipe_proc_root;

static int __ipipe_version_info_proc(char *page,
				     char **start,
				     off_t off, int count, int *eof, void *data)
{
	int len = sprintf(page, "%d\n", IPIPE_CORE_RELEASE);

	len -= off;

	if (len <= off + count)
		*eof = 1;

	*start = page + off;

	if(len > count)
		len = count;

	if(len < 0)
		len = 0;

	return len;
}

static int __ipipe_common_info_show(struct seq_file *p, void *data)
{
	struct ipipe_domain *ipd = (struct ipipe_domain *)p->private;
	char handling, lockbit, virtuality;
	unsigned long ctlbits;
	unsigned int irq;

	seq_printf(p, "       +--- Handled\n");
	seq_printf(p, "       |+-- Locked\n");
	seq_printf(p, "       ||+- Virtual\n");
	seq_printf(p, "[IRQ]  |||\n");

	mutex_lock(&ipd->mutex);

	for (irq = 0; irq < IPIPE_NR_IRQS; irq++) {
		ctlbits = ipd->irqs[irq].control;
		/*
		 * There might be a hole between the last external IRQ
		 * and the first virtual one; skip it.
		 */
		if (irq >= IPIPE_NR_XIRQS && !ipipe_virtual_irq_p(irq))
			continue;

		if (ipipe_virtual_irq_p(irq)
		    && !test_bit(irq - IPIPE_VIRQ_BASE, &__ipipe_virtual_irq_map))
			/* Non-allocated virtual IRQ; skip it. */
			continue;

		if (ctlbits & IPIPE_HANDLE_MASK)
			handling = 'H';
		else
			handling = '.';

		if (ctlbits & IPIPE_LOCK_MASK)
			lockbit = 'L';
		else
			lockbit = '.';

		if (ipipe_virtual_irq_p(irq))
			virtuality = 'V';
		else
			virtuality = '.';

		seq_printf(p, " %3u:  %c%c%c\n",
			     irq, handling, lockbit, virtuality);
	}

	mutex_unlock(&ipd->mutex);

	return 0;
}

static int __ipipe_common_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, __ipipe_common_info_show, PROC_I(inode)->pde->data);
}

static struct file_operations __ipipe_info_proc_ops = {
	.owner		= THIS_MODULE,
	.open		= __ipipe_common_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void add_domain_proc(struct ipipe_domain *ipd)
{
	struct proc_dir_entry *e = create_proc_entry(ipd->name, 0444, ipipe_proc_root);
	if (e) {
		e->proc_fops = &__ipipe_info_proc_ops;
		e->data = (void*) ipd;
	}
}

void remove_domain_proc(struct ipipe_domain *ipd)
{
	remove_proc_entry(ipd->name,ipipe_proc_root);
}

void __init __ipipe_init_proc(void)
{
	ipipe_proc_root = create_proc_entry("ipipe",S_IFDIR, 0);
	create_proc_read_entry("version",0444,ipipe_proc_root,&__ipipe_version_info_proc,NULL);
	add_domain_proc(ipipe_root_domain);

	__ipipe_init_tracer();
}

#else

static inline void add_domain_proc(struct ipipe_domain *ipd)
{
}

static inline void remove_domain_proc(struct ipipe_domain *ipd)
{
}

#endif	/* CONFIG_PROC_FS */

static void init_stage(struct ipipe_domain *ipd)
{
	memset(&ipd->irqs, 0, sizeof(ipd->irqs));
	mutex_init(&ipd->mutex);
	__ipipe_legacy_init_stage(ipd);
	__ipipe_hook_critical_ipi(ipd);
}

static inline int root_context_offset(void)
{
	void root_context_not_at_start_of_ipipe_percpu(void);

	/* ipipe_percpu.root must be found at offset #0. */

	if (offsetof(struct ipipe_percpu_data, root))
		root_context_not_at_start_of_ipipe_percpu();

	return 0;
}

#ifdef CONFIG_SMP

static inline void fixup_percpu_data(void)
{
	struct ipipe_percpu_data *p;
	int cpu;

	/*
	 * ipipe_percpu.curr cannot be assigned statically to
	 * &ipipe_percpu.root, due to the dynamic nature of percpu
	 * data. So we make ipipe_percpu.curr refer to a temporary
	 * boot up context in static memory, until we can fixup all
	 * context pointers in this routine, after per-cpu areas have
	 * been eventually set up. The temporary context data is
	 * copied to per_cpu(ipipe_percpu, 0).root in the same move.
	 *
	 * Obviously, this code must run over the boot CPU, before SMP
	 * operations start.
	 */
	BUG_ON(smp_processor_id() || !irqs_disabled());

	per_cpu(ipipe_percpu, 0).root = bootup_context;

	for_each_possible_cpu(cpu) {
		p = &per_cpu(ipipe_percpu, cpu);
		p->curr = &p->root;
	}
}

#else /* !CONFIG_SMP */

static inline void fixup_percpu_data(void) { }

#endif /* CONFIG_SMP */

void __init __ipipe_init_early(void)
{
	struct ipipe_domain *ipd = &ipipe_root;
	int cpu;

	fixup_percpu_data();

	/*
	 * A lightweight registration code for the root domain. We are
	 * running on the boot CPU, hw interrupts are off, and
	 * secondary CPUs are still lost in space.
	 */
	ipd->name = "Linux";
	ipd->context_offset = root_context_offset();
	init_stage(ipd);

	/*
	 * Do the early init stuff. First we do the per-arch pipeline
	 * core setup, then we run the per-client setup code. At this
	 * point, the kernel does not provide much services yet: be
	 * careful.
	 */
	__ipipe_early_core_setup();
	__ipipe_early_client_setup();

#ifdef CONFIG_PRINTK
	__ipipe_printk_virq = ipipe_alloc_virq();
	ipd->irqs[__ipipe_printk_virq].handler = __ipipe_flush_printk;
	ipd->irqs[__ipipe_printk_virq].cookie = NULL;
	ipd->irqs[__ipipe_printk_virq].ackfn = NULL;
	ipd->irqs[__ipipe_printk_virq].control = IPIPE_HANDLE_MASK;
#endif /* CONFIG_PRINTK */

	__ipipe_work_virq = ipipe_alloc_virq();
	ipd->irqs[__ipipe_work_virq].handler = __ipipe_do_work;
	ipd->irqs[__ipipe_work_virq].cookie = NULL;
	ipd->irqs[__ipipe_work_virq].ackfn = NULL;
	ipd->irqs[__ipipe_work_virq].control = IPIPE_HANDLE_MASK;

	for_each_possible_cpu(cpu)
		per_cpu(work_tail, cpu) = per_cpu(work_buf, cpu);
}

void __init __ipipe_init(void)
{
	/* Now we may engage the pipeline. */
	__ipipe_enable_pipeline();

	printk(KERN_INFO "Interrupt pipeline (release #%d)\n",
	       IPIPE_CORE_RELEASE);
}

static inline void init_head_stage(struct ipipe_domain *ipd)
{
	struct ipipe_percpu_domain_data *p;
	int cpu;

	/* Must be set first, used in ipipe_percpu_context(). */
	ipd->context_offset = offsetof(struct ipipe_percpu_data, head);

	for_each_online_cpu(cpu) {
		p = ipipe_percpu_context(ipd, cpu);
		memset(p, 0, sizeof(*p));
		p->domain = ipd;
	}

	init_stage(ipd);
}

void ipipe_register_head(struct ipipe_domain *ipd, const char *name)
{
	BUG_ON(!ipipe_root_p || ipd == &ipipe_root);

	ipd->name = name;
	init_head_stage(ipd);
	barrier();
	ipipe_head_domain = ipd;
	add_domain_proc(ipd);

	printk(KERN_INFO "I-pipe: head domain %s registered.\n", name);
}
EXPORT_SYMBOL_GPL(ipipe_register_head);

void ipipe_unregister_head(struct ipipe_domain *ipd)
{
	BUG_ON(!ipipe_root_p || ipd != ipipe_head_domain);

	ipipe_head_domain = &ipipe_root;
	smp_mb();
	mutex_lock(&ipd->mutex);
	remove_domain_proc(ipd);
	mutex_unlock(&ipd->mutex);

	printk(KERN_INFO "I-pipe: head domain %s unregistered.\n", ipd->name);
}
EXPORT_SYMBOL_GPL(ipipe_unregister_head);

void ipipe_unstall_root(void)
{
	struct ipipe_percpu_domain_data *p;

	hard_local_irq_disable();

	/* This helps catching bad usage from assembly call sites. */
	ipipe_root_only();

	p = ipipe_this_cpu_root_context();

	__clear_bit(IPIPE_STALL_FLAG, &p->status);

	if (unlikely(__ipipe_ipending_p(p)))
		__ipipe_sync_stage();

	hard_local_irq_enable();
}
EXPORT_SYMBOL_GPL(ipipe_unstall_root);

void ipipe_restore_root(unsigned long x)
{
	ipipe_root_only();

	if (x)
		ipipe_stall_root();
	else
		ipipe_unstall_root();
}
EXPORT_SYMBOL_GPL(ipipe_restore_root);

void __ipipe_restore_root_nosync(unsigned long x)
{
	struct ipipe_percpu_domain_data *p = ipipe_this_cpu_root_context();

	if (raw_irqs_disabled_flags(x)) {
		__set_bit(IPIPE_STALL_FLAG, &p->status);
		trace_hardirqs_off();
	} else {
		trace_hardirqs_on();
		__clear_bit(IPIPE_STALL_FLAG, &p->status);
	}
}
EXPORT_SYMBOL_GPL(__ipipe_restore_root_nosync);

void ipipe_unstall_head(void)
{
	struct ipipe_percpu_domain_data *p = ipipe_this_cpu_head_context();

	hard_local_irq_disable();

	__clear_bit(IPIPE_STALL_FLAG, &p->status);

	if (unlikely(__ipipe_ipending_p(p)))
		__ipipe_sync_pipeline(ipipe_head_domain);

	hard_local_irq_enable();
}
EXPORT_SYMBOL_GPL(ipipe_unstall_head);

void __ipipe_restore_head(unsigned long x) /* hw interrupt off */
{
	struct ipipe_percpu_domain_data *p = ipipe_this_cpu_head_context();

	if (x) {
#ifdef CONFIG_DEBUG_KERNEL
		static int warned;
		if (!warned &&
		    __test_and_set_bit(IPIPE_STALL_FLAG, &p->status)) {
			/*
			 * Already stalled albeit ipipe_restore_head()
			 * should have detected it? Send a warning once.
			 */
			hard_local_irq_enable();
			warned = 1;
			printk(KERN_WARNING
				   "I-pipe: ipipe_restore_head() optimization failed.\n");
			dump_stack();
			hard_local_irq_disable();
		}
#else /* !CONFIG_DEBUG_KERNEL */
		__set_bit(IPIPE_STALL_FLAG, &p->status);
#endif /* CONFIG_DEBUG_KERNEL */
	} else {
		__clear_bit(IPIPE_STALL_FLAG, &p->status);
		if (unlikely(__ipipe_ipending_p(p)))
			__ipipe_sync_pipeline(ipipe_head_domain);
		hard_local_irq_enable();
	}
}
EXPORT_SYMBOL_GPL(__ipipe_restore_head);

void __ipipe_spin_lock_irq(ipipe_spinlock_t *lock)
{
	hard_local_irq_disable();
	arch_spin_lock(&lock->arch_lock);
	__set_bit(IPIPE_STALL_FLAG, &__ipipe_current_context->status);
}
EXPORT_SYMBOL_GPL(__ipipe_spin_lock_irq);

void __ipipe_spin_unlock_irq(ipipe_spinlock_t *lock)
{
	arch_spin_unlock(&lock->arch_lock);
	__clear_bit(IPIPE_STALL_FLAG, &__ipipe_current_context->status);
	hard_local_irq_enable();
}
EXPORT_SYMBOL_GPL(__ipipe_spin_unlock_irq);

unsigned long __ipipe_spin_lock_irqsave(ipipe_spinlock_t *lock)
{
	unsigned long flags;
	int s;

	flags = hard_local_irq_save();
	arch_spin_lock(&lock->arch_lock);
	s = __test_and_set_bit(IPIPE_STALL_FLAG, &__ipipe_current_context->status);

	return arch_mangle_irq_bits(s, flags);
}
EXPORT_SYMBOL_GPL(__ipipe_spin_lock_irqsave);

int __ipipe_spin_trylock_irqsave(ipipe_spinlock_t *lock,
				 unsigned long *x)
{
	unsigned long flags;
	int s;

	flags = hard_local_irq_save();
	if (!arch_spin_trylock(&lock->arch_lock)) {
		hard_local_irq_restore(flags);
		return 0;
	}
	s = __test_and_set_bit(IPIPE_STALL_FLAG, &__ipipe_current_context->status);
	*x = arch_mangle_irq_bits(s, flags);

	return 1;
}
EXPORT_SYMBOL_GPL(__ipipe_spin_trylock_irqsave);

void __ipipe_spin_unlock_irqrestore(ipipe_spinlock_t *lock,
				    unsigned long x)
{
	arch_spin_unlock(&lock->arch_lock);
	if (!arch_demangle_irq_bits(&x))
		__clear_bit(IPIPE_STALL_FLAG, &__ipipe_current_context->status);
	hard_local_irq_restore(x);
}
EXPORT_SYMBOL_GPL(__ipipe_spin_unlock_irqrestore);

int __ipipe_spin_trylock_irq(ipipe_spinlock_t *lock)
{
	unsigned long flags;

	flags = hard_local_irq_save();
	if (!arch_spin_trylock(&lock->arch_lock)) {
		hard_local_irq_restore(flags);
		return 0;
	}
	__set_bit(IPIPE_STALL_FLAG, &__ipipe_current_context->status);

	return 1;
}
EXPORT_SYMBOL_GPL(__ipipe_spin_trylock_irq);

void __ipipe_spin_unlock_irqbegin(ipipe_spinlock_t *lock)
{
	arch_spin_unlock(&lock->arch_lock);
}

void __ipipe_spin_unlock_irqcomplete(unsigned long x)
{
	if (!arch_demangle_irq_bits(&x))
		__clear_bit(IPIPE_STALL_FLAG, &__ipipe_current_context->status);
	hard_local_irq_restore(x);
}

#ifdef __IPIPE_3LEVEL_IRQMAP

/* Must be called hw IRQs off. */
static inline void __ipipe_set_irq_held(struct ipipe_percpu_domain_data *p,
					unsigned int irq)
{
	__set_bit(irq, p->irqheld_map);
	p->irqall[irq]++;
}

/* Must be called hw IRQs off. */
void __ipipe_set_irq_pending(struct ipipe_domain *ipd, unsigned int irq)
{
	struct ipipe_percpu_domain_data *p = ipipe_this_cpu_context(ipd);
	int l0b, l1b;

	IPIPE_WARN_ONCE(!hard_irqs_disabled());

	l0b = irq / (BITS_PER_LONG * BITS_PER_LONG);
	l1b = irq / BITS_PER_LONG;

	if (likely(!test_bit(IPIPE_LOCK_FLAG, &ipd->irqs[irq].control))) {
		__set_bit(irq, p->irqpend_lomap);
		__set_bit(l1b, p->irqpend_mdmap);
		__set_bit(l0b, &p->irqpend_himap);
	} else
		__set_bit(irq, p->irqheld_map);

	p->irqall[irq]++;
}
EXPORT_SYMBOL_GPL(__ipipe_set_irq_pending);

/* Must be called hw IRQs off. */
void __ipipe_lock_irq(unsigned int irq)
{
	struct ipipe_domain *ipd = ipipe_root_domain;
	struct ipipe_percpu_domain_data *p;
	int l0b, l1b;

	IPIPE_WARN_ONCE(!hard_irqs_disabled());

	/*
	 * Interrupts requested by a registered head domain cannot be
	 * locked, since this would make no sense: interrupts are
	 * globally masked at CPU level when the head domain is
	 * stalled, so there is no way we could encounter the
	 * situation IRQ locks are handling.
	 */
	if (test_and_set_bit(IPIPE_LOCK_FLAG, &ipd->irqs[irq].control))
		return;

	l0b = irq / (BITS_PER_LONG * BITS_PER_LONG);
	l1b = irq / BITS_PER_LONG;

	p = ipipe_this_cpu_context(ipd);
	if (__test_and_clear_bit(irq, p->irqpend_lomap)) {
		__set_bit(irq, p->irqheld_map);
		if (p->irqpend_lomap[l1b] == 0) {
			__clear_bit(l1b, p->irqpend_mdmap);
			if (p->irqpend_mdmap[l0b] == 0)
				__clear_bit(l0b, &p->irqpend_himap);
		}
	}
}
EXPORT_SYMBOL_GPL(__ipipe_lock_irq);

/* Must be called hw IRQs off. */
void __ipipe_unlock_irq(unsigned int irq)
{
	struct ipipe_domain *ipd = ipipe_root_domain;
	struct ipipe_percpu_domain_data *p;
	int l0b, l1b, cpu;

	IPIPE_WARN_ONCE(!hard_irqs_disabled());

	if (!test_and_clear_bit(IPIPE_LOCK_FLAG, &ipd->irqs[irq].control))
		return;

	l0b = irq / (BITS_PER_LONG * BITS_PER_LONG);
	l1b = irq / BITS_PER_LONG;

	for_each_online_cpu(cpu) {
		p = ipipe_this_cpu_root_context();
		if (test_and_clear_bit(irq, p->irqheld_map)) {
			/* We need atomic ops here: */
			set_bit(irq, p->irqpend_lomap);
			set_bit(l1b, p->irqpend_mdmap);
			set_bit(l0b, &p->irqpend_himap);
		}
	}
}
EXPORT_SYMBOL_GPL(__ipipe_unlock_irq);

static inline int __ipipe_next_irq(struct ipipe_percpu_domain_data *p)
{
	int l0b, l1b, l2b;
	unsigned long l0m, l1m, l2m;
	unsigned int irq;

	l0m = p->irqpend_himap;
	if (unlikely(l0m == 0))
		return -1;

	l0b = __ipipe_ffnz(l0m);
	l1m = p->irqpend_mdmap[l0b];
	if (unlikely(l1m == 0))
		return -1;

	l1b = __ipipe_ffnz(l1m) + l0b * BITS_PER_LONG;
	l2m = p->irqpend_lomap[l1b];
	if (unlikely(l2m == 0))
		return -1;

	l2b = __ipipe_ffnz(l2m);
	irq = l1b * BITS_PER_LONG + l2b;

	__clear_bit(irq, p->irqpend_lomap);
	if (p->irqpend_lomap[l1b] == 0) {
		__clear_bit(l1b, p->irqpend_mdmap);
		if (p->irqpend_mdmap[l0b] == 0)
			__clear_bit(l0b, &p->irqpend_himap);
	}

	return irq;
}

#else /* __IPIPE_2LEVEL_IRQMAP */

/* Must be called hw IRQs off. */
static inline void __ipipe_set_irq_held(struct ipipe_percpu_domain_data *p,
					unsigned int irq)
{
	__set_bit(irq, p->irqheld_map);
	p->irqall[irq]++;
}

/* Must be called hw IRQs off. */
void __ipipe_set_irq_pending(struct ipipe_domain *ipd, unsigned int irq)
{
	struct ipipe_percpu_domain_data *p = ipipe_this_cpu_context(ipd);
	int l0b = irq / BITS_PER_LONG;

	IPIPE_WARN_ONCE(!hard_irqs_disabled());

	if (likely(!test_bit(IPIPE_LOCK_FLAG, &ipd->irqs[irq].control))) {
		__set_bit(irq, p->irqpend_lomap);
		__set_bit(l0b, &p->irqpend_himap);
	} else
		__set_bit(irq, p->irqheld_map);

	p->irqall[irq]++;
}
EXPORT_SYMBOL_GPL(__ipipe_set_irq_pending);

/* Must be called hw IRQs off. */
void __ipipe_lock_irq(unsigned int irq)
{
	struct ipipe_percpu_domain_data *p;
	int l0b = irq / BITS_PER_LONG;

	IPIPE_WARN_ONCE(!hard_irqs_disabled());

	if (test_and_set_bit(IPIPE_LOCK_FLAG,
			     &ipipe_root_domain->irqs[irq].control))
		return;

	p = ipipe_this_cpu_root_context();
	if (__test_and_clear_bit(irq, p->irqpend_lomap)) {
		__set_bit(irq, p->irqheld_map);
		if (p->irqpend_lomap[l0b] == 0)
			__clear_bit(l0b, &p->irqpend_himap);
	}
}
EXPORT_SYMBOL_GPL(__ipipe_lock_irq);

/* Must be called hw IRQs off. */
void __ipipe_unlock_irq(unsigned int irq)
{
	struct ipipe_domain *ipd = ipipe_root_domain;
	struct ipipe_percpu_domain_data *p;
	int l0b = irq / BITS_PER_LONG, cpu;

	IPIPE_WARN_ONCE(!hard_irqs_disabled());

	if (!test_and_clear_bit(IPIPE_LOCK_FLAG, &ipd->irqs[irq].control))
		return;

	for_each_online_cpu(cpu) {
		p = ipipe_percpu_context(ipd, cpu);
		if (test_and_clear_bit(irq, p->irqheld_map)) {
			/* We need atomic ops here: */
			set_bit(irq, p->irqpend_lomap);
			set_bit(l0b, &p->irqpend_himap);
		}
	}
}
EXPORT_SYMBOL_GPL(__ipipe_unlock_irq);

static inline int __ipipe_next_irq(struct ipipe_percpu_domain_data *p)
{
	unsigned long l0m, l1m;
	int l0b, l1b;

	l0m = p->irqpend_himap;
	if (unlikely(l0m == 0))
		return -1;

	l0b = __ipipe_ffnz(l0m);
	l1m = p->irqpend_lomap[l0b];
	if (unlikely(l1m == 0))
		return -1;

	l1b = __ipipe_ffnz(l1m);
	__clear_bit(l1b, &p->irqpend_lomap[l0b]);
	if (p->irqpend_lomap[l0b] == 0)
		__clear_bit(l0b, &p->irqpend_himap);

	return l0b * BITS_PER_LONG + l1b;
}

#endif /* __IPIPE_2LEVEL_IRQMAP */

void __ipipe_do_sync_pipeline(struct ipipe_domain *top)
{
	struct ipipe_percpu_domain_data *p;
	struct ipipe_domain *ipd;

	/* We must enter over the root domain. */
	IPIPE_WARN_ONCE(__ipipe_current_domain != ipipe_root_domain);
	ipd = top;
next:
	p = ipipe_this_cpu_context(ipd);
	if (test_bit(IPIPE_STALL_FLAG, &p->status))
		return;

	if (__ipipe_ipending_p(p)) {
		if (ipd == ipipe_root_domain)
			__ipipe_sync_stage();
		else {
			/* Switching to head. */
			p->coflags &= ~__IPIPE_ALL_R;
			__ipipe_set_current_context(p);
			__ipipe_sync_stage();
			__ipipe_set_current_domain(ipipe_root_domain);
		}
	}

	if (ipd != ipipe_root_domain) {
		ipd = ipipe_root_domain;
		goto next;
	}
}
EXPORT_SYMBOL_GPL(__ipipe_do_sync_pipeline);

unsigned int ipipe_alloc_virq(void)
{
	unsigned long flags, irq = 0;
	int ipos;

	spin_lock_irqsave(&__ipipe_lock, flags);

	if (__ipipe_virtual_irq_map != ~0) {
		ipos = ffz(__ipipe_virtual_irq_map);
		set_bit(ipos, &__ipipe_virtual_irq_map);
		irq = ipos + IPIPE_VIRQ_BASE;
	}

	spin_unlock_irqrestore(&__ipipe_lock, flags);

	return irq;
}
EXPORT_SYMBOL_GPL(ipipe_alloc_virq);

void ipipe_free_virq(unsigned int virq)
{
	clear_bit(virq - IPIPE_VIRQ_BASE, &__ipipe_virtual_irq_map);
	smp_mb__after_clear_bit();
}
EXPORT_SYMBOL_GPL(ipipe_free_virq);

int ipipe_request_irq(struct ipipe_domain *ipd,
		      unsigned int irq,
		      ipipe_irq_handler_t handler,
		      void *cookie,
		      ipipe_irq_ackfn_t ackfn)
{
	unsigned long flags;
	int ret = 0;

#ifndef CONFIG_IPIPE_LEGACY
	ipipe_root_only();
#endif /* CONFIG_IPIPE_LEGACY */

	if (handler == NULL ||
	    (irq >= IPIPE_NR_XIRQS && !ipipe_virtual_irq_p(irq)))
		return -EINVAL;

	spin_lock_irqsave(&__ipipe_lock, flags);

	if (ipd->irqs[irq].handler) {
		ret = -EBUSY;
		goto out;
	}

	if (ackfn == NULL)
		ackfn = ipipe_root_domain->irqs[irq].ackfn;

	ipd->irqs[irq].handler = handler;
	ipd->irqs[irq].cookie = cookie;
	ipd->irqs[irq].ackfn = ackfn;
	ipd->irqs[irq].control = IPIPE_HANDLE_MASK;

	if (irq < NR_IRQS)
		__ipipe_enable_irqdesc(ipd, irq);
out:
	spin_unlock_irqrestore(&__ipipe_lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(ipipe_request_irq);

void ipipe_free_irq(struct ipipe_domain *ipd,
		    unsigned int irq)
{
	unsigned long flags;

#ifndef CONFIG_IPIPE_LEGACY
	ipipe_root_only();
#endif /* CONFIG_IPIPE_LEGACY */

	spin_lock_irqsave(&__ipipe_lock, flags);

	if (ipd->irqs[irq].handler == NULL)
		goto out;

	ipd->irqs[irq].handler = NULL;
	ipd->irqs[irq].cookie = NULL;
	ipd->irqs[irq].ackfn = NULL;
	ipd->irqs[irq].control = 0;

	if (irq < NR_IRQS)
		__ipipe_disable_irqdesc(ipd, irq);
out:
	spin_unlock_irqrestore(&__ipipe_lock, flags);
}
EXPORT_SYMBOL_GPL(ipipe_free_irq);

void ipipe_set_hooks(struct ipipe_domain *ipd, int enables)
{
	struct ipipe_percpu_domain_data *p;
	unsigned long flags;
	int cpu, wait;

	if (ipd == ipipe_root_domain) {
		IPIPE_WARN(enables & __IPIPE_TRAP_E);
		enables &= ~__IPIPE_TRAP_E;
	} else {
		IPIPE_WARN(enables & __IPIPE_KEVENT_E);
		enables &= ~__IPIPE_KEVENT_E;
	}

	flags = ipipe_critical_enter(NULL);

	for_each_online_cpu(cpu) {
		p = ipipe_percpu_context(ipd, cpu);
		p->coflags &= ~__IPIPE_ALL_E;
		p->coflags |= enables;
	}

	wait = (enables ^ __IPIPE_ALL_E) << __IPIPE_SHIFT_R;
	if (wait == 0 || !__ipipe_root_p) {
		ipipe_critical_exit(flags);
		return;
	}

	ipipe_this_cpu_context(ipd)->coflags &= ~wait;

	ipipe_critical_exit(flags);

	/*
	 * In case we cleared some hooks over the root domain, we have
	 * to wait for any ongoing execution to finish, since our
	 * caller might subsequently unmap the target domain code.
	 *
	 * We synchronize with the relevant __ipipe_notify_*()
	 * helpers, disabling all hooks before we start waiting for
	 * completion on all CPUs.
	 */
	for_each_online_cpu(cpu) {
		while (ipipe_percpu_context(ipd, cpu)->coflags & wait)
			schedule_timeout_interruptible(HZ / 50);
	}
}
EXPORT_SYMBOL_GPL(ipipe_set_hooks);

int __weak ipipe_syscall_hook(struct ipipe_domain *ipd, struct pt_regs *regs)
{
	return 0;
}

int __ipipe_notify_syscall(struct pt_regs *regs)
{
	struct ipipe_domain *caller_domain, *this_domain, *ipd;
	struct ipipe_percpu_domain_data *p;
	unsigned long flags;
	int ret = 0;

	flags = hard_local_irq_save();
	caller_domain = this_domain = __ipipe_current_domain;
	ipd = ipipe_head_domain;
next:
	p = ipipe_this_cpu_context(ipd);
	if (likely(p->coflags & __IPIPE_SYSCALL_E)) {
		__ipipe_set_current_context(p);
		p->coflags |= __IPIPE_SYSCALL_R;
		hard_local_irq_restore(flags);
		ret = ipipe_syscall_hook(caller_domain, regs);
		flags = hard_local_irq_save();
		p->coflags &= ~__IPIPE_SYSCALL_R;
		if (__ipipe_current_domain != ipd)
			/* Account for domain migration. */
			this_domain = __ipipe_current_domain;
		else
			__ipipe_set_current_domain(this_domain);
	}

	if (this_domain == ipipe_root_domain &&
	    ipd != ipipe_root_domain && ret == 0) {
		ipd = ipipe_root_domain;
		goto next;
	}

	hard_local_irq_restore(flags);

	return ret;
}

int __weak ipipe_trap_hook(struct ipipe_trap_data *data)
{
	return 0;
}

int __ipipe_notify_trap(int exception, struct pt_regs *regs)
{
	struct ipipe_percpu_domain_data *p;
	struct ipipe_trap_data data;
	unsigned long flags;
	int ret = 0;

	flags = hard_local_irq_save();

	/*
	 * We send a notification about all traps raised over a
	 * registered head domain only.
	 */
	if (__ipipe_root_p)
		goto out;

	p = ipipe_this_cpu_head_context();
	if (likely(p->coflags & __IPIPE_TRAP_E)) {
		p->coflags |= __IPIPE_TRAP_R;
		hard_local_irq_restore(flags);
		data.exception = exception;
		data.regs = regs;
		ret = ipipe_trap_hook(&data);
		flags = hard_local_irq_save();
		p->coflags &= ~__IPIPE_TRAP_R;
	}
out:
	hard_local_irq_restore(flags);

	return ret;
}

int __weak ipipe_kevent_hook(int kevent, void *data)
{
	return 0;
}

int __ipipe_notify_kevent(int kevent, void *data)
{
	struct ipipe_percpu_domain_data *p;
	unsigned long flags;
	int ret = 0;

	ipipe_root_only();

	flags = hard_local_irq_save();

	p = ipipe_this_cpu_root_context();
	if (likely(p->coflags & __IPIPE_KEVENT_E)) {
		p->coflags |= __IPIPE_KEVENT_R;
		hard_local_irq_restore(flags);
		ret = ipipe_kevent_hook(kevent, data);
		flags = hard_local_irq_save();
		p->coflags &= ~__IPIPE_KEVENT_R;
	}

	hard_local_irq_restore(flags);

	return ret;
}

void __weak ipipe_migration_hook(struct task_struct *p)
{
}

#ifdef CONFIG_IPIPE_LEGACY

static inline void complete_domain_migration(void) /* hw IRQs off */
{
	current->state &= ~TASK_HARDENING;
}

#else /* !CONFIG_IPIPE_LEGACY */

static void complete_domain_migration(void) /* hw IRQs off */
{
	struct ipipe_percpu_domain_data *p;
	struct ipipe_percpu_data *pd;
	struct task_struct *t;

	ipipe_root_only();
	pd = __this_cpu_ptr(&ipipe_percpu);
	t = pd->task_hijacked;
	if (t == NULL)
		return;

	pd->task_hijacked = NULL;
	t->state &= ~TASK_HARDENING;
	if (t->state != TASK_INTERRUPTIBLE)
		/* Migration aborted (by signal). */
		return;

	p = ipipe_this_cpu_head_context();
	IPIPE_WARN_ONCE(test_bit(IPIPE_STALL_FLAG, &p->status));
	/*
	 * hw IRQs are disabled, but the completion hook assumes the
	 * head domain is logically stalled: fix it up.
	 */
	__set_bit(IPIPE_STALL_FLAG, &p->status);
	ipipe_migration_hook(t);
	__clear_bit(IPIPE_STALL_FLAG, &p->status);
}

#endif /* !CONFIG_IPIPE_LEGACY */

void __ipipe_complete_domain_migration(void)
{
	unsigned long flags;

	flags = hard_local_irq_save();
	complete_domain_migration();
	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(__ipipe_complete_domain_migration);

int __ipipe_switch_tail(void)
{
	int x;

#ifdef CONFIG_IPIPE_WANT_PREEMPTIBLE_SWITCH
	hard_local_irq_disable();
#endif
	x = __ipipe_root_p;
#ifndef CONFIG_IPIPE_LEGACY
	if (x)
#endif
		complete_domain_migration();

#ifndef CONFIG_IPIPE_WANT_PREEMPTIBLE_SWITCH
	if (x)
#endif
		hard_local_irq_enable();

	return !x;
}

void __ipipe_notify_vm_preemption(void)
{
	struct ipipe_vm_notifier *vmf;
	struct ipipe_percpu_data *p;

	ipipe_check_irqoff();
	p = __ipipe_this_cpu_ptr(&ipipe_percpu);
	vmf = p->vm_notifier;
	if (unlikely(vmf))
		vmf->handler(vmf);
}
EXPORT_SYMBOL_GPL(__ipipe_notify_vm_preemption);

static void dispatch_irq_head(unsigned int irq) /* hw interrupts off */
{
	struct ipipe_percpu_domain_data *p = ipipe_this_cpu_head_context(), *old;
	struct ipipe_domain *head = p->domain;

	if (unlikely(test_bit(IPIPE_STALL_FLAG, &p->status))) {
		__ipipe_set_irq_pending(head, irq);
		return;
	}

	/* Switch to the head domain if not current. */
	old = __ipipe_current_context;
	if (old != p)
		__ipipe_set_current_context(p);

	p->irqall[irq]++;
	__set_bit(IPIPE_STALL_FLAG, &p->status);
	barrier();
	head->irqs[irq].handler(irq, head->irqs[irq].cookie);
	__ipipe_run_irqtail(irq);
	hard_local_irq_disable();
	p = ipipe_this_cpu_head_context();
	__clear_bit(IPIPE_STALL_FLAG, &p->status);

	/* Are we still running in the head domain? */
	if (likely(__ipipe_current_context == p)) {
		/* Did we enter this code over the head domain? */
		if (old->domain == head) {
			/* Yes, do immediate synchronization. */
			if (__ipipe_ipending_p(p))
				__ipipe_sync_stage();
			return;
		}
		__ipipe_set_current_context(ipipe_this_cpu_root_context());
	}

	/*
	 * We must be running over the root domain, synchronize
	 * the pipeline for high priority IRQs (slow path).
	 */
	__ipipe_do_sync_pipeline(head);
}

void __ipipe_dispatch_irq(unsigned int irq, int flags) /* hw interrupts off */
{
	struct ipipe_domain *ipd;
	struct irq_desc *desc;
	unsigned long control;
	int chained_irq;

	/*
	 * Survival kit when reading this code:
	 *
	 * - we have two main situations, leading to three cases for
	 *   handling interrupts:
	 *
	 *   a) the root domain is alone, no registered head domain
	 *      => all interrupts are delivered via the fast dispatcher.
	 *   b) a head domain is registered
	 *      => head domain IRQs go through the fast dispatcher
	 *      => root domain IRQs go through the interrupt log
	 *
	 * - when no head domain is registered, ipipe_head_domain ==
	 *   ipipe_root_domain == &ipipe_root.
	 *
	 * - the caller tells us whether we should acknowledge this
	 *   IRQ. Even virtual IRQs may require acknowledge on some
	 *   platforms (e.g. arm/SMP).
	 *
	 * - the caller tells us whether we may try to run the IRQ log
	 *   syncer. Typically, demuxed IRQs won't be synced
	 *   immediately.
	 *
	 * - multiplex IRQs most likely have a valid acknowledge
	 *   handler and we may not be called with IPIPE_IRQF_NOACK
	 *   for them. The ack handler for the multiplex IRQ actually
	 *   decodes the demuxed interrupts.
	 */

#ifdef CONFIG_IPIPE_DEBUG
	if (unlikely(irq >= IPIPE_NR_IRQS) ||
	    (irq < NR_IRQS && irq_to_desc(irq) == NULL)) {
		printk(KERN_ERR "I-pipe: spurious interrupt %u\n", irq);
		return;
	}
#endif
	/*
	 * CAUTION: on some archs, virtual IRQs may have acknowledge
	 * handlers. Multiplex IRQs should have one too.
	 */
	if (unlikely(irq >= NR_IRQS)) {
		desc = NULL;
		chained_irq = 0;
	} else {
		desc = irq_to_desc(irq);
		chained_irq = desc ? ipipe_chained_irq_p(desc) : 0;
	}
	if (flags & IPIPE_IRQF_NOACK)
		IPIPE_WARN_ONCE(chained_irq);
	else {
		ipd = ipipe_head_domain;
		control = ipd->irqs[irq].control;
		if ((control & IPIPE_HANDLE_MASK) == 0)
			ipd = ipipe_root_domain;
		if (ipd->irqs[irq].ackfn)
			ipd->irqs[irq].ackfn(irq, desc);
		if (chained_irq) {
			if ((flags & IPIPE_IRQF_NOSYNC) == 0)
				/* Run demuxed IRQ handlers. */
				goto sync;
			return;
		}
	}

	/*
	 * Sticky interrupts must be handled early and separately, so
	 * that we always process them on the current domain.
	 */
	ipd = __ipipe_current_domain;
	control = ipd->irqs[irq].control;
	if (control & IPIPE_STICKY_MASK)
		goto log;

	/*
	 * In case we have no registered head domain
	 * (i.e. ipipe_head_domain == &ipipe_root), we always go
	 * through the interrupt log, and leave the dispatching work
	 * ultimately to __ipipe_sync_pipeline().
	 */
	ipd = ipipe_head_domain;
	control = ipd->irqs[irq].control;
	if (ipd == ipipe_root_domain)
		/*
		 * The root domain must handle all interrupts, so
		 * testing the HANDLE bit would be pointless.
		 */
		goto log;

	if (control & IPIPE_HANDLE_MASK) {
		if (unlikely(flags & IPIPE_IRQF_NOSYNC))
			__ipipe_set_irq_pending(ipd, irq);
		else
			dispatch_irq_head(irq);
		return;
	}

	ipd = ipipe_root_domain;
log:
	__ipipe_set_irq_pending(ipd, irq);

	if (flags & IPIPE_IRQF_NOSYNC)
		return;

	/*
	 * Optimize if we preempted a registered high priority head
	 * domain: we don't need to synchronize the pipeline unless
	 * there is a pending interrupt for it.
	 */
	if (!__ipipe_root_p &&
	    !__ipipe_ipending_p(ipipe_this_cpu_head_context()))
		return;
sync:
	__ipipe_sync_pipeline(ipipe_head_domain);
}

#ifdef CONFIG_PREEMPT

asmlinkage void preempt_schedule_irq(void);

asmlinkage void __sched __ipipe_preempt_schedule_irq(void)
{
	struct ipipe_percpu_domain_data *p;
	unsigned long flags;

	BUG_ON(!hard_irqs_disabled());
	local_irq_save(flags);
	hard_local_irq_enable();
	preempt_schedule_irq(); /* Ok, may reschedule now. */
	hard_local_irq_disable();

	/*
	 * Flush any pending interrupt that may have been logged after
	 * preempt_schedule_irq() stalled the root stage before
	 * returning to us, and now.
	 */
	p = ipipe_this_cpu_root_context();
	if (unlikely(__ipipe_ipending_p(p))) {
		add_preempt_count(PREEMPT_ACTIVE);
		trace_hardirqs_on();
		__clear_bit(IPIPE_STALL_FLAG, &p->status);
		__ipipe_sync_stage();
		sub_preempt_count(PREEMPT_ACTIVE);
	}

	__ipipe_restore_root_nosync(flags);
}

#else /* !CONFIG_PREEMPT */

#define __ipipe_preempt_schedule_irq()	do { } while (0)

#endif	/* !CONFIG_PREEMPT */

#ifdef CONFIG_TRACE_IRQFLAGS
#define root_stall_after_handler()	local_irq_disable()
#else
#define root_stall_after_handler()	do { } while (0)
#endif

/*
 * __ipipe_do_sync_stage() -- Flush the pending IRQs for the current
 * domain (and processor). This routine flushes the interrupt log (see
 * "Optimistic interrupt protection" from D. Stodolsky et al. for more
 * on the deferred interrupt scheme). Every interrupt that occurred
 * while the pipeline was stalled gets played.
 *
 * WARNING: CPU migration may occur over this routine.
 */
void __ipipe_do_sync_stage(void)
{
	struct ipipe_percpu_domain_data *p;
	struct ipipe_domain *ipd;
	int irq;

	p = __ipipe_current_context;
	ipd = p->domain;

	__set_bit(IPIPE_STALL_FLAG, &p->status);
	smp_wmb();

	if (ipd == ipipe_root_domain)
		trace_hardirqs_off();

	for (;;) {
		irq = __ipipe_next_irq(p);
		if (irq < 0)
			break;
		/*
		 * Make sure the compiler does not reorder wrongly, so
		 * that all updates to maps are done before the
		 * handler gets called.
		 */
		barrier();

		if (test_bit(IPIPE_LOCK_FLAG, &ipd->irqs[irq].control))
			continue;

		if (ipd != ipipe_head_domain)
			hard_local_irq_enable();

		if (likely(ipd != ipipe_root_domain)) {
			ipd->irqs[irq].handler(irq, ipd->irqs[irq].cookie);
			__ipipe_run_irqtail(irq);
			hard_local_irq_disable();
		} else if (ipipe_virtual_irq_p(irq)) {
			irq_enter();
			ipd->irqs[irq].handler(irq, ipd->irqs[irq].cookie);
			irq_exit();
			root_stall_after_handler();
			hard_local_irq_disable();
			while (__ipipe_check_root_resched())
				__ipipe_preempt_schedule_irq();
		} else {
			ipd->irqs[irq].handler(irq, ipd->irqs[irq].cookie);
			root_stall_after_handler();
			hard_local_irq_disable();
		}

		p = __ipipe_current_context;
	}

	if (ipd == ipipe_root_domain)
		trace_hardirqs_on();

	__clear_bit(IPIPE_STALL_FLAG, &p->status);
}

#ifdef CONFIG_SMP

/* Always called with hw interrupts off. */
void __ipipe_do_critical_sync(unsigned int irq, void *cookie)
{
	int cpu = ipipe_processor_id();

	cpu_set(cpu, __ipipe_cpu_sync_map);

	/*
	 * Now we are in sync with the lock requestor running on
	 * another CPU. Enter a spinning wait until he releases the
	 * global lock.
	 */
	spin_lock(&__ipipe_cpu_barrier);

	/* Got it. Now get out. */

	/* Call the sync routine if any. */
	if (__ipipe_cpu_sync)
		__ipipe_cpu_sync();

	cpu_set(cpu, __ipipe_cpu_pass_map);

	spin_unlock(&__ipipe_cpu_barrier);

	cpu_clear(cpu, __ipipe_cpu_sync_map);
}

#endif	/* CONFIG_SMP */

unsigned long ipipe_critical_enter(void (*syncfn)(void))
{
	cpumask_t allbutself __maybe_unused, online __maybe_unused;
	int cpu __maybe_unused, n __maybe_unused;
	unsigned long flags, loops __maybe_unused;

	flags = hard_local_irq_save();

	if (num_online_cpus() == 1)
		return flags;

#ifdef CONFIG_SMP

	cpu = ipipe_processor_id();
	if (!cpu_test_and_set(cpu, __ipipe_cpu_lock_map)) {
		while (test_and_set_bit(0, &__ipipe_critical_lock)) {
			n = 0;
			hard_local_irq_enable();

			do
				cpu_relax();
			while (++n < cpu);

			hard_local_irq_disable();
		}
restart:
		online = *cpu_online_mask;
		spin_lock(&__ipipe_cpu_barrier);

		__ipipe_cpu_sync = syncfn;

		cpus_clear(__ipipe_cpu_pass_map);
		cpu_set(cpu, __ipipe_cpu_pass_map);

		/*
		 * Send the sync IPI to all processors but the current
		 * one.
		 */
		cpus_andnot(allbutself, online, __ipipe_cpu_pass_map);
		ipipe_send_ipi(IPIPE_CRITICAL_IPI, allbutself);
		loops = IPIPE_CRITICAL_TIMEOUT;

		while (!cpus_equal(__ipipe_cpu_sync_map, allbutself)) {
			if (--loops > 0) {
				cpu_relax();
				continue;
			}
			/*
			 * We ran into a deadlock due to a contended
			 * rwlock. Cancel this round and retry.
			 */
			__ipipe_cpu_sync = NULL;

			spin_unlock(&__ipipe_cpu_barrier);
			/*
			 * Ensure all CPUs consumed the IPI to avoid
			 * running __ipipe_cpu_sync prematurely. This
			 * usually resolves the deadlock reason too.
			 */
			while (!cpus_equal(online, __ipipe_cpu_pass_map))
				cpu_relax();

			goto restart;
		}
	}

	atomic_inc(&__ipipe_critical_count);

#endif	/* CONFIG_SMP */

	return flags;
}
EXPORT_SYMBOL_GPL(ipipe_critical_enter);

void ipipe_critical_exit(unsigned long flags)
{
	if (num_online_cpus() == 1) {
		hard_local_irq_restore(flags);
		return;
	}

#ifdef CONFIG_SMP
	if (atomic_dec_and_test(&__ipipe_critical_count)) {
		spin_unlock(&__ipipe_cpu_barrier);
		while (!cpus_empty(__ipipe_cpu_sync_map))
			cpu_relax();
		cpu_clear(ipipe_processor_id(), __ipipe_cpu_lock_map);
		clear_bit(0, &__ipipe_critical_lock);
		smp_mb__after_clear_bit();
	}
#endif /* CONFIG_SMP */

	hard_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(ipipe_critical_exit);

#ifdef CONFIG_IPIPE_DEBUG_CONTEXT

void ipipe_root_only(void)
{
	struct ipipe_domain *this_domain;
	unsigned long flags;

	flags = hard_smp_local_irq_save();

	this_domain = __ipipe_current_domain;
	if (likely(this_domain == ipipe_root_domain &&
		   !test_bit(IPIPE_STALL_FLAG, &__ipipe_head_status))) {
		hard_smp_local_irq_restore(flags);
		return;
	}

	if (!__this_cpu_read(ipipe_percpu.context_check)) {
		hard_smp_local_irq_restore(flags);
		return;
	}

	hard_smp_local_irq_restore(flags);

	ipipe_prepare_panic();
	ipipe_trace_panic_freeze();

	if (this_domain != ipipe_root_domain)
		printk(KERN_ERR
		       "I-pipe: Detected illicit call from head domain '%s'\n"
		       KERN_ERR "        into a regular Linux service\n",
		       this_domain->name);
	else
		printk(KERN_ERR "I-pipe: Detected stalled head domain, "
				"probably caused by a bug.\n"
				"        A critical section may have been "
				"left unterminated.\n");
	dump_stack();
	ipipe_trace_panic_dump();
}
EXPORT_SYMBOL_GPL(ipipe_root_only);

#endif /* CONFIG_IPIPE_DEBUG_CONTEXT */

#if defined(CONFIG_IPIPE_DEBUG_INTERNAL) && defined(CONFIG_SMP)

int notrace __ipipe_check_percpu_access(void)
{
	struct ipipe_percpu_domain_data *p;
	struct ipipe_domain *this_domain;
	unsigned long flags;
	int ret = 0;

	flags = hard_local_irq_save_notrace();

	/*
	 * Don't use __ipipe_current_domain here, this would recurse
	 * indefinitely.
	 */
	this_domain = __this_cpu_read(ipipe_percpu.curr)->domain;

	/*
	 * Only the root domain may implement preemptive CPU migration
	 * of tasks, so anything above in the pipeline should be fine.
	 */
	if (this_domain != ipipe_root_domain)
		goto out;

	if (raw_irqs_disabled_flags(flags))
		goto out;

	/*
	 * Last chance: hw interrupts were enabled on entry while
	 * running over the root domain, but the root stage might be
	 * currently stalled, in which case preemption would be
	 * disabled, and no migration could occur.
	 */
	if (this_domain == ipipe_root_domain) {
		p = ipipe_this_cpu_root_context();
		if (test_bit(IPIPE_STALL_FLAG, &p->status))
			goto out;
	}
	/*
	 * Our caller may end up accessing the wrong per-cpu variable
	 * instance due to CPU migration; tell it to complain about
	 * this.
	 */
	ret = 1;
out:
	hard_local_irq_restore_notrace(flags);

	return ret;
}
EXPORT_SYMBOL_GPL(__ipipe_check_percpu_access);

void __ipipe_spin_unlock_debug(unsigned long flags)
{
	/*
	 * We catch a nasty issue where spin_unlock_irqrestore() on a
	 * regular kernel spinlock is about to re-enable hw interrupts
	 * in a section entered with hw irqs off. This is clearly the
	 * sign of a massive breakage coming. Usual suspect is a
	 * regular spinlock which was overlooked, used within a
	 * section which must run with hw irqs disabled.
	 */
	IPIPE_WARN_ONCE(!raw_irqs_disabled_flags(flags) && hard_irqs_disabled());
}
EXPORT_SYMBOL_GPL(__ipipe_spin_unlock_debug);

#endif /* CONFIG_IPIPE_DEBUG_INTERNAL && CONFIG_SMP */

void ipipe_prepare_panic(void)
{
#ifdef CONFIG_PRINTK
	__ipipe_printk_bypass = 1;
#endif
	ipipe_context_check_off();
}
EXPORT_SYMBOL_GPL(ipipe_prepare_panic);

static void __ipipe_do_work(unsigned int virq, void *cookie)
{
	struct ipipe_work_header *work;
	unsigned long flags;
	void *curr, *tail;
	int cpu;

	/*
	 * Work is dispatched in enqueuing order. This interrupt
	 * context can't migrate to another CPU.
	 */
	cpu = smp_processor_id();
	curr = per_cpu(work_buf, cpu);

	for (;;) {
		flags = hard_local_irq_save();
		tail = per_cpu(work_tail, cpu);
		if (curr == tail) {
			per_cpu(work_tail, cpu) = per_cpu(work_buf, cpu);
			hard_local_irq_restore(flags);
			return;
		}
		work = curr;
		curr += work->size;
		hard_local_irq_restore(flags);
		work->handler(work);
	}
}

void __ipipe_post_work_root(struct ipipe_work_header *work)
{
	unsigned long flags;
	void *tail;
	int cpu;

	/*
	 * Subtle: we want to use the head stall/unstall operators,
	 * not the hard_* routines to protect against races. This way,
	 * we ensure that a root-based caller will trigger the virq
	 * handling immediately when unstalling the head stage, as a
	 * result of calling __ipipe_sync_pipeline() under the hood.
	 */
	flags = ipipe_test_and_stall_head();
	cpu = ipipe_processor_id();
	tail = per_cpu(work_tail, cpu);

	if (WARN_ON_ONCE((unsigned char *)tail + work->size >=
			 per_cpu(work_buf, cpu) + WORKBUF_SIZE))
		goto out;

	/* Work handling is deferred, so data has to be copied. */
	memcpy(tail, work, work->size);
	per_cpu(work_tail, cpu) = tail + work->size;
	ipipe_post_irq_root(__ipipe_work_virq);
out:
	ipipe_restore_head(flags);
}
EXPORT_SYMBOL_GPL(__ipipe_post_work_root);
