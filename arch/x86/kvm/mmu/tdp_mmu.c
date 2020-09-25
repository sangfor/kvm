/* SPDX-License-Identifier: GPL-2.0 */

#include "mmu.h"
#include "mmu_internal.h"
#include "tdp_iter.h"
#include "tdp_mmu.h"

static bool __read_mostly tdp_mmu_enabled = true;
module_param_named(tdp_mmu, tdp_mmu_enabled, bool, 0644);

static bool is_tdp_mmu_enabled(void)
{
	if (!READ_ONCE(tdp_mmu_enabled))
		return false;

	if (WARN_ONCE(!tdp_enabled,
		      "Creating a VM with TDP MMU enabled requires TDP."))
		return false;

	return true;
}

/* Initializes the TDP MMU for the VM, if enabled. */
void kvm_mmu_init_tdp_mmu(struct kvm *kvm)
{
	if (!is_tdp_mmu_enabled())
		return;

	/* This should not be changed for the lifetime of the VM. */
	kvm->arch.tdp_mmu_enabled = true;

	INIT_LIST_HEAD(&kvm->arch.tdp_mmu_roots);
}

void kvm_mmu_uninit_tdp_mmu(struct kvm *kvm)
{
	if (!kvm->arch.tdp_mmu_enabled)
		return;

	WARN_ON(!list_empty(&kvm->arch.tdp_mmu_roots));
}

#define for_each_tdp_mmu_root(_kvm, _root)			    \
	list_for_each_entry(_root, &_kvm->arch.tdp_mmu_roots, link)

bool is_tdp_mmu_root(struct kvm *kvm, hpa_t hpa)
{
	struct kvm_mmu_page *root;

	if (!kvm->arch.tdp_mmu_enabled)
		return false;

	root = to_shadow_page(hpa);

	if (WARN_ON(!root))
		return false;

	return root->tdp_mmu_page;
}

static bool zap_gfn_range(struct kvm *kvm, struct kvm_mmu_page *root,
			  gfn_t start, gfn_t end);

static void free_tdp_mmu_root(struct kvm *kvm, struct kvm_mmu_page *root)
{
	gfn_t max_gfn = 1ULL << (boot_cpu_data.x86_phys_bits - PAGE_SHIFT);

	lockdep_assert_held(&kvm->mmu_lock);

	WARN_ON(root->root_count);
	WARN_ON(!root->tdp_mmu_page);

	list_del(&root->link);

	zap_gfn_range(kvm, root, 0, max_gfn);

	free_page((unsigned long)root->spt);
	kmem_cache_free(mmu_page_header_cache, root);
}

static void put_tdp_mmu_root(struct kvm *kvm, struct kvm_mmu_page *root)
{
	lockdep_assert_held(&kvm->mmu_lock);

	root->root_count--;
	if (!root->root_count)
		free_tdp_mmu_root(kvm, root);
}

static void get_tdp_mmu_root(struct kvm *kvm, struct kvm_mmu_page *root)
{
	lockdep_assert_held(&kvm->mmu_lock);
	WARN_ON(!root->root_count);

	root->root_count++;
}

void kvm_tdp_mmu_put_root_hpa(struct kvm *kvm, hpa_t root_hpa)
{
	struct kvm_mmu_page *root;

	root = to_shadow_page(root_hpa);

	if (WARN_ON(!root))
		return;

	put_tdp_mmu_root(kvm, root);
}

static struct kvm_mmu_page *find_tdp_mmu_root_with_role(
		struct kvm *kvm, union kvm_mmu_page_role role)
{
	struct kvm_mmu_page *root;

	lockdep_assert_held(&kvm->mmu_lock);
	for_each_tdp_mmu_root(kvm, root) {
		WARN_ON(!root->root_count);

		if (root->role.word == role.word)
			return root;
	}

	return NULL;
}

static struct kvm_mmu_page *alloc_tdp_mmu_root(struct kvm_vcpu *vcpu,
					       union kvm_mmu_page_role role)
{
	struct kvm_mmu_page *new_root;
	struct kvm_mmu_page *root;

	new_root = kvm_mmu_memory_cache_alloc(
			&vcpu->arch.mmu_page_header_cache);
	new_root->spt = kvm_mmu_memory_cache_alloc(
			&vcpu->arch.mmu_shadow_page_cache);
	set_page_private(virt_to_page(new_root->spt), (unsigned long)new_root);

	new_root->role.word = role.word;
	new_root->root_count = 1;
	new_root->gfn = 0;
	new_root->tdp_mmu_page = true;

	spin_lock(&vcpu->kvm->mmu_lock);

	/* Check that no matching root exists before adding this one. */
	root = find_tdp_mmu_root_with_role(vcpu->kvm, role);
	if (root) {
		get_tdp_mmu_root(vcpu->kvm, root);
		spin_unlock(&vcpu->kvm->mmu_lock);
		free_page((unsigned long)new_root->spt);
		kmem_cache_free(mmu_page_header_cache, new_root);
		return root;
	}

	list_add(&new_root->link, &vcpu->kvm->arch.tdp_mmu_roots);
	spin_unlock(&vcpu->kvm->mmu_lock);

	return new_root;
}

static struct kvm_mmu_page *get_tdp_mmu_vcpu_root(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_page *root;
	union kvm_mmu_page_role role;

	role = vcpu->arch.mmu->mmu_role.base;
	role.level = vcpu->arch.mmu->shadow_root_level;
	role.direct = true;
	role.gpte_is_8_bytes = true;
	role.access = ACC_ALL;

	spin_lock(&vcpu->kvm->mmu_lock);

	/* Search for an already allocated root with the same role. */
	root = find_tdp_mmu_root_with_role(vcpu->kvm, role);
	if (root) {
		get_tdp_mmu_root(vcpu->kvm, root);
		spin_unlock(&vcpu->kvm->mmu_lock);
		return root;
	}

	spin_unlock(&vcpu->kvm->mmu_lock);

	/* If there is no appropriate root, allocate one. */
	root = alloc_tdp_mmu_root(vcpu, role);

	return root;
}

hpa_t kvm_tdp_mmu_get_vcpu_root_hpa(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu_page *root;

	root = get_tdp_mmu_vcpu_root(vcpu);
	if (!root)
		return INVALID_PAGE;

	return __pa(root->spt);
}

static void handle_changed_spte(struct kvm *kvm, int as_id, gfn_t gfn,
				u64 old_spte, u64 new_spte, int level);

static int kvm_mmu_page_as_id(struct kvm_mmu_page *sp)
{
	return sp->role.smm ? 1 : 0;
}

/**
 * handle_changed_spte - handle bookkeeping associated with an SPTE change
 * @kvm: kvm instance
 * @as_id: the address space of the paging structure the SPTE was a part of
 * @gfn: the base GFN that was mapped by the SPTE
 * @old_spte: The value of the SPTE before the change
 * @new_spte: The value of the SPTE after the change
 * @level: the level of the PT the SPTE is part of in the paging structure
 *
 * Handle bookkeeping that might result from the modification of a SPTE.
 * This function must be called for all TDP SPTE modifications.
 */
static void handle_changed_spte(struct kvm *kvm, int as_id, gfn_t gfn,
				u64 old_spte, u64 new_spte, int level)
{
	bool was_present = is_shadow_present_pte(old_spte);
	bool is_present = is_shadow_present_pte(new_spte);
	bool was_leaf = was_present && is_last_spte(old_spte, level);
	bool is_leaf = is_present && is_last_spte(new_spte, level);
	bool pfn_changed = spte_to_pfn(old_spte) != spte_to_pfn(new_spte);
	u64 *pt;
	u64 old_child_spte;
	int i;

	WARN_ON(level > PT64_ROOT_MAX_LEVEL);
	WARN_ON(level < PG_LEVEL_4K);
	WARN_ON(gfn % KVM_PAGES_PER_HPAGE(level));

	/*
	 * If this warning were to trigger it would indicate that there was a
	 * missing MMU notifier or a race with some notifier handler.
	 * A present, leaf SPTE should never be directly replaced with another
	 * present leaf SPTE pointing to a differnt PFN. A notifier handler
	 * should be zapping the SPTE before the main MM's page table is
	 * changed, or the SPTE should be zeroed, and the TLBs flushed by the
	 * thread before replacement.
	 */
	if (was_leaf && is_leaf && pfn_changed) {
		pr_err("Invalid SPTE change: cannot replace a present leaf\n"
		       "SPTE with another present leaf SPTE mapping a\n"
		       "different PFN!\n"
		       "as_id: %d gfn: %llx old_spte: %llx new_spte: %llx level: %d",
		       as_id, gfn, old_spte, new_spte, level);

		/*
		 * Crash the host to prevent error propagation and guest data
		 * courruption.
		 */
		BUG();
	}

	if (old_spte == new_spte)
		return;

	/*
	 * The only times a SPTE should be changed from a non-present to
	 * non-present state is when an MMIO entry is installed/modified/
	 * removed. In that case, there is nothing to do here.
	 */
	if (!was_present && !is_present) {
		/*
		 * If this change does not involve a MMIO SPTE, it is
		 * unexpected. Log the change, though it should not impact the
		 * guest since both the former and current SPTEs are nonpresent.
		 */
		if (WARN_ON(!is_mmio_spte(old_spte) && !is_mmio_spte(new_spte)))
			pr_err("Unexpected SPTE change! Nonpresent SPTEs\n"
			       "should not be replaced with another,\n"
			       "different nonpresent SPTE, unless one or both\n"
			       "are MMIO SPTEs.\n"
			       "as_id: %d gfn: %llx old_spte: %llx new_spte: %llx level: %d",
			       as_id, gfn, old_spte, new_spte, level);
		return;
	}


	if (was_leaf && is_dirty_spte(old_spte) &&
	    (!is_dirty_spte(new_spte) || pfn_changed))
		kvm_set_pfn_dirty(spte_to_pfn(old_spte));

	/*
	 * Recursively handle child PTs if the change removed a subtree from
	 * the paging structure.
	 */
	if (was_present && !was_leaf && (pfn_changed || !is_present)) {
		pt = spte_to_child_pt(old_spte, level);

		for (i = 0; i < PT64_ENT_PER_PAGE; i++) {
			old_child_spte = *(pt + i);
			*(pt + i) = 0;
			handle_changed_spte(kvm, as_id,
				gfn + (i * KVM_PAGES_PER_HPAGE(level - 1)),
				old_child_spte, 0, level - 1);
		}

		kvm_flush_remote_tlbs_with_address(kvm, gfn,
						   KVM_PAGES_PER_HPAGE(level));

		free_page((unsigned long)pt);
	}
}

#define for_each_tdp_pte_root(_iter, _root, _start, _end) \
	for_each_tdp_pte(_iter, _root->spt, _root->role.level, _start, _end)

#define for_each_tdp_pte_vcpu(_iter, _vcpu, _start, _end)		   \
	for_each_tdp_pte(_iter, __va(_vcpu->arch.mmu->root_hpa),	   \
			 _vcpu->arch.mmu->shadow_root_level, _start, _end)

/*
 * If the MMU lock is contended or this thread needs to yield, flushes
 * the TLBs, releases, the MMU lock, yields, reacquires the MMU lock,
 * restarts the tdp_iter's walk from the root, and returns true.
 * If no yield is needed, returns false.
 */
static bool tdp_mmu_iter_cond_resched(struct kvm *kvm, struct tdp_iter *iter)
{
	if (need_resched() || spin_needbreak(&kvm->mmu_lock)) {
		kvm_flush_remote_tlbs(kvm);
		cond_resched_lock(&kvm->mmu_lock);
		tdp_iter_refresh_walk(iter);
		return true;
	} else {
		return false;
	}
}

/*
 * Tears down the mappings for the range of gfns, [start, end), and frees the
 * non-root pages mapping GFNs strictly within that range. Returns true if
 * SPTEs have been cleared and a TLB flush is needed before releasing the
 * MMU lock.
 */
static bool zap_gfn_range(struct kvm *kvm, struct kvm_mmu_page *root,
			  gfn_t start, gfn_t end)
{
	struct tdp_iter iter;
	bool flush_needed = false;
	int as_id = kvm_mmu_page_as_id(root);

	for_each_tdp_pte_root(iter, root, start, end) {
		if (!is_shadow_present_pte(iter.old_spte))
			continue;

		/*
		 * If this is a non-last-level SPTE that covers a larger range
		 * than should be zapped, continue, and zap the mappings at a
		 * lower level.
		 */
		if ((iter.gfn < start ||
		     iter.gfn + KVM_PAGES_PER_HPAGE(iter.level) > end) &&
		    !is_last_spte(iter.old_spte, iter.level))
			continue;

		*iter.sptep = 0;
		handle_changed_spte(kvm, as_id, iter.gfn, iter.old_spte, 0,
				    iter.level);

		flush_needed = !tdp_mmu_iter_cond_resched(kvm, &iter);
	}
	return flush_needed;
}

/*
 * Tears down the mappings for the range of gfns, [start, end), and frees the
 * non-root pages mapping GFNs strictly within that range. Returns true if
 * SPTEs have been cleared and a TLB flush is needed before releasing the
 * MMU lock.
 */
bool kvm_tdp_mmu_zap_gfn_range(struct kvm *kvm, gfn_t start, gfn_t end)
{
	struct kvm_mmu_page *root;
	bool flush = false;

	for_each_tdp_mmu_root(kvm, root) {
		/*
		 * Take a reference on the root so that it cannot be freed if
		 * this thread releases the MMU lock and yields in this loop.
		 */
		get_tdp_mmu_root(kvm, root);

		flush = zap_gfn_range(kvm, root, start, end) || flush;

		put_tdp_mmu_root(kvm, root);
	}

	return flush;
}

void kvm_tdp_mmu_zap_all(struct kvm *kvm)
{
	gfn_t max_gfn = 1ULL << (boot_cpu_data.x86_phys_bits - PAGE_SHIFT);
	bool flush;

	flush = kvm_tdp_mmu_zap_gfn_range(kvm, 0, max_gfn);
	if (flush)
		kvm_flush_remote_tlbs(kvm);
}

/*
 * Installs a last-level SPTE to handle a TDP page fault.
 * (NPT/EPT violation/misconfiguration)
 */
static int page_fault_handle_target_level(struct kvm_vcpu *vcpu, int write,
					  int map_writable, int as_id,
					  struct tdp_iter *iter,
					  kvm_pfn_t pfn, bool prefault)
{
	u64 new_spte;
	int ret = 0;
	int make_spte_ret = 0;

	if (unlikely(is_noslot_pfn(pfn)))
		new_spte = make_mmio_spte(vcpu, iter->gfn, ACC_ALL);
	else
		new_spte = make_spte(vcpu, ACC_ALL, iter->level, iter->gfn,
				     pfn, iter->old_spte, prefault, true,
				     map_writable, !shadow_accessed_mask,
				     &make_spte_ret);

	/*
	 * If the page fault was caused by a write but the page is write
	 * protected, emulation is needed. If the emulation was skipped,
	 * the vCPU would have the same fault again.
	 */
	if ((make_spte_ret & SET_SPTE_WRITE_PROTECTED_PT) && write)
		ret = RET_PF_EMULATE;

	/* If a MMIO SPTE is installed, the MMIO will need to be emulated. */
	if (unlikely(is_mmio_spte(new_spte)))
		ret = RET_PF_EMULATE;

	*iter->sptep = new_spte;
	handle_changed_spte(vcpu->kvm, as_id, iter->gfn, iter->old_spte,
			    new_spte, iter->level);

	if (!prefault)
		vcpu->stat.pf_fixed++;

	return ret;
}

/*
 * Handle a TDP page fault (NPT/EPT violation/misconfiguration) by installing
 * page tables and SPTEs to translate the faulting guest physical address.
 */
int kvm_tdp_mmu_page_fault(struct kvm_vcpu *vcpu, int write, int map_writable,
			   int max_level, gpa_t gpa, kvm_pfn_t pfn,
			   bool prefault, bool account_disallowed_nx_lpage)
{
	struct tdp_iter iter;
	struct kvm_mmu_memory_cache *pf_pt_cache =
			&vcpu->arch.mmu_shadow_page_cache;
	u64 *child_pt;
	u64 new_spte;
	int ret;
	int as_id = kvm_arch_vcpu_memslots_id(vcpu);
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int level;

	if (WARN_ON(!VALID_PAGE(vcpu->arch.mmu->root_hpa)))
		return RET_PF_RETRY;

	if (WARN_ON(!is_tdp_mmu_root(vcpu->kvm, vcpu->arch.mmu->root_hpa)))
		return RET_PF_RETRY;

	level = kvm_mmu_hugepage_adjust(vcpu, gfn, max_level, &pfn);

	for_each_tdp_pte_vcpu(iter, vcpu, gfn, gfn + 1) {
		disallowed_hugepage_adjust(iter.old_spte, gfn, iter.level,
					   &pfn, &level);

		if (iter.level == level)
			break;

		/*
		 * If there is an SPTE mapping a large page at a higher level
		 * than the target, that SPTE must be cleared and replaced
		 * with a non-leaf SPTE.
		 */
		if (is_shadow_present_pte(iter.old_spte) &&
		    is_large_pte(iter.old_spte)) {
			*iter.sptep = 0;
			handle_changed_spte(vcpu->kvm, as_id, iter.gfn,
					    iter.old_spte, 0, iter.level);
			kvm_flush_remote_tlbs_with_address(vcpu->kvm, iter.gfn,
					KVM_PAGES_PER_HPAGE(iter.level));

			/*
			 * The iter must explicitly re-read the spte here
			 * because the new is needed before the next iteration
			 * of the loop.
			 */
			iter.old_spte = READ_ONCE(*iter.sptep);
		}

		if (!is_shadow_present_pte(iter.old_spte)) {
			child_pt = kvm_mmu_memory_cache_alloc(pf_pt_cache);
			clear_page(child_pt);
			new_spte = make_nonleaf_spte(child_pt,
						     !shadow_accessed_mask);

			*iter.sptep = new_spte;
			handle_changed_spte(vcpu->kvm, as_id, iter.gfn,
					    iter.old_spte, new_spte,
					    iter.level);
		}
	}

	if (WARN_ON(iter.level != level))
		return RET_PF_RETRY;

	ret = page_fault_handle_target_level(vcpu, write, map_writable,
					     as_id, &iter, pfn, prefault);

	/* If emulating, flush this vcpu's TLB. */
	if (ret == RET_PF_EMULATE)
		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);

	return ret;
}
