/* SPDX-License-Identifier: GPL-2.0 */

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
}

void kvm_mmu_uninit_tdp_mmu(struct kvm *kvm)
{
	if (!kvm->arch.tdp_mmu_enabled)
		return;
}
