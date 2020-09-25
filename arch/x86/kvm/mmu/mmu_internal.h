/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_X86_MMU_INTERNAL_H
#define __KVM_X86_MMU_INTERNAL_H

#include <linux/types.h>

#include <asm/kvm_host.h>

struct kvm_mmu_page {
	struct list_head link;
	struct hlist_node hash_link;
	struct list_head lpage_disallowed_link;

	bool unsync;
	u8 mmu_valid_gen;
	bool mmio_cached;
	bool lpage_disallowed; /* Can't be replaced by an equiv large page */

	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */
	union kvm_mmu_page_role role;
	gfn_t gfn;

	u64 *spt;
	/* hold the gfn of each spte inside spt */
	gfn_t *gfns;
	int root_count;          /* Currently serving as active root */
	unsigned int unsync_children;
	struct kvm_rmap_head parent_ptes; /* rmap pointers to parent sptes */
	DECLARE_BITMAP(unsync_child_bitmap, 512);

#ifdef CONFIG_X86_32
	/*
	 * Used out of the mmu-lock to avoid reading spte values while an
	 * update is in progress; see the comments in __get_spte_lockless().
	 */
	int clear_spte_count;
#endif

	/* Number of writes since the last time traversal visited this page.  */
	atomic_t write_flooding_count;

	bool tdp_mmu_page;
};

extern struct kmem_cache *mmu_page_header_cache;

static inline struct kvm_mmu_page *to_shadow_page(hpa_t shadow_page)
{
	struct page *page = pfn_to_page(shadow_page >> PAGE_SHIFT);

	return (struct kvm_mmu_page *)page_private(page);
}

static inline struct kvm_mmu_page *sptep_to_sp(u64 *sptep)
{
	return to_shadow_page(__pa(sptep));
}

void kvm_mmu_gfn_disallow_lpage(struct kvm_memory_slot *slot, gfn_t gfn);
void kvm_mmu_gfn_allow_lpage(struct kvm_memory_slot *slot, gfn_t gfn);
bool kvm_mmu_slot_gfn_write_protect(struct kvm *kvm,
				    struct kvm_memory_slot *slot, u64 gfn);

#define PT64_LEVEL_BITS 9

#define PT64_LEVEL_SHIFT(level) \
		(PAGE_SHIFT + (level - 1) * PT64_LEVEL_BITS)

#define PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))
#define SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)

#define PT64_LVL_ADDR_MASK(level) \
	(PT64_BASE_ADDR_MASK & ~((1ULL << (PAGE_SHIFT + (((level) - 1) \
						* PT64_LEVEL_BITS))) - 1))
#define PT64_LVL_OFFSET_MASK(level) \
	(PT64_BASE_ADDR_MASK & ((1ULL << (PAGE_SHIFT + (((level) - 1) \
						* PT64_LEVEL_BITS))) - 1))

#ifdef CONFIG_DYNAMIC_PHYSICAL_MASK
#define PT64_BASE_ADDR_MASK (physical_mask & ~(u64)(PAGE_SIZE-1))
#else
#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(u64)(PAGE_SIZE-1))
#endif

extern u64 shadow_user_mask;
extern u64 shadow_accessed_mask;
extern u64 shadow_present_mask;
extern u64 shadow_dirty_mask;

#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

#define PT_FIRST_AVAIL_BITS_SHIFT 10
#define PT64_SECOND_AVAIL_BITS_SHIFT 54

#define SPTE_HOST_WRITEABLE	(1ULL << PT_FIRST_AVAIL_BITS_SHIFT)
#define SPTE_MMU_WRITEABLE	(1ULL << (PT_FIRST_AVAIL_BITS_SHIFT + 1))

/* Functions for interpreting SPTEs */
kvm_pfn_t spte_to_pfn(u64 pte);
bool is_mmio_spte(u64 spte);
int is_shadow_present_pte(u64 pte);
int is_last_spte(u64 pte, int level);
bool is_dirty_spte(u64 spte);
int is_large_pte(u64 pte);
bool is_access_track_spte(u64 spte);
bool is_accessed_spte(u64 spte);
bool spte_ad_enabled(u64 spte);
bool is_executable_pte(u64 spte);
bool spte_ad_need_write_protect(u64 spte);

void kvm_flush_remote_tlbs_with_address(struct kvm *kvm, u64 start_gfn,
					u64 pages);

/*
 * Return values of handle_mmio_page_fault and mmu.page_fault:
 * RET_PF_RETRY: let CPU fault again on the address.
 * RET_PF_EMULATE: mmio page fault, emulate the instruction directly.
 *
 * For handle_mmio_page_fault only:
 * RET_PF_INVALID: the spte is invalid, let the real page fault path update it.
 */
enum {
	RET_PF_RETRY = 0,
	RET_PF_EMULATE = 1,
	RET_PF_INVALID = 2,
};

/* Bits which may be returned by set_spte() */
#define SET_SPTE_WRITE_PROTECTED_PT	BIT(0)
#define SET_SPTE_NEED_REMOTE_TLB_FLUSH	BIT(1)

u64 make_spte(struct kvm_vcpu *vcpu, unsigned int pte_access, int level,
	      gfn_t gfn, kvm_pfn_t pfn, u64 old_spte, bool speculative,
	      bool can_unsync, bool host_writable, bool ad_disabled, int *ret);
u64 make_mmio_spte(struct kvm_vcpu *vcpu, u64 gfn, unsigned int access);
u64 make_nonleaf_spte(u64 *child_pt, bool ad_disabled);

int kvm_mmu_hugepage_adjust(struct kvm_vcpu *vcpu, gfn_t gfn,
			    int max_level, kvm_pfn_t *pfnp);
void disallowed_hugepage_adjust(u64 spte, gfn_t gfn, int cur_level,
				kvm_pfn_t *pfnp, int *goal_levelp);

bool is_nx_huge_page_enabled(void);

void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc);

u64 mark_spte_for_access_track(u64 spte);
u64 kvm_mmu_changed_pte_notifier_make_spte(u64 old_spte, kvm_pfn_t new_pfn);

#endif /* __KVM_X86_MMU_INTERNAL_H */
