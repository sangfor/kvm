/* SPDX-License-Identifier: GPL-2.0 */

#include "mmu.h"
#include "mmu_internal.h"
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

static void free_tdp_mmu_root(struct kvm *kvm, struct kvm_mmu_page *root)
{
	lockdep_assert_held(&kvm->mmu_lock);

	WARN_ON(root->root_count);
	WARN_ON(!root->tdp_mmu_page);

	list_del(&root->link);

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
