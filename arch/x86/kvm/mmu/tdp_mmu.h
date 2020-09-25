/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __KVM_X86_MMU_TDP_MMU_H
#define __KVM_X86_MMU_TDP_MMU_H

#include <linux/kvm_host.h>

void kvm_mmu_init_tdp_mmu(struct kvm *kvm);
void kvm_mmu_uninit_tdp_mmu(struct kvm *kvm);

bool is_tdp_mmu_root(struct kvm *kvm, hpa_t root);
hpa_t kvm_tdp_mmu_get_vcpu_root_hpa(struct kvm_vcpu *vcpu);
void kvm_tdp_mmu_put_root_hpa(struct kvm *kvm, hpa_t root_hpa);

bool kvm_tdp_mmu_zap_gfn_range(struct kvm *kvm, gfn_t start, gfn_t end);
void kvm_tdp_mmu_zap_all(struct kvm *kvm);

int kvm_tdp_mmu_page_fault(struct kvm_vcpu *vcpu, int write, int map_writable,
			   int level, gpa_t gpa, kvm_pfn_t pfn, bool prefault,
			   bool lpage_disallowed);

int kvm_tdp_mmu_zap_hva_range(struct kvm *kvm, unsigned long start,
			      unsigned long end);
#endif /* __KVM_X86_MMU_TDP_MMU_H */
