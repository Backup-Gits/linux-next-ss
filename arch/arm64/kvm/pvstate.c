// SPDX-License-Identifier: GPL-2.0-only

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>

#include <asm/kvm_mmu.h>
#include <asm/paravirt.h>

#include <kvm/arm_hypercalls.h>

int kvm_init_vcpu_state(struct kvm_vcpu *vcpu, gpa_t addr)
{
	if (kvm_arm_is_vcpu_state_enabled(&vcpu->arch))
		return 0;

	if (kvm_gfn_to_hva_cache_init(vcpu->kvm,
				      &vcpu->arch.pv_state.ghc,
				      addr,
				      sizeof(struct pvstate_vcpu_info)))
		return -EINVAL;

	vcpu->arch.pv_state.base = addr;
	return 0;
}

int kvm_release_vcpu_state(struct kvm_vcpu *vcpu)
{
	if (!kvm_arm_is_vcpu_state_enabled(&vcpu->arch))
		return 0;

	vcpu->arch.pv_state.base = GPA_INVALID;
	return 0;
}

void kvm_update_vcpu_preempted(struct kvm_vcpu *vcpu, bool preempted)
{
	struct kvm *kvm = vcpu->kvm;
	u64 idx;

	if (!kvm_arm_is_vcpu_state_enabled(&vcpu->arch))
		return;

	/*
	 * This function is called from atomic context, so we need to
	 * disable page faults. kvm_write_guest_cached() will call
	 * might_fault().
	 */
	pagefault_disable();
	/*
	 * Need to take the SRCU lock because kvm_write_guest_offset_cached()
	 * calls kvm_memslots();
	 */
	idx = srcu_read_lock(&kvm->srcu);
	kvm_write_guest_cached(kvm, &vcpu->arch.pv_state.ghc,
			       &preempted, sizeof(bool));
	srcu_read_unlock(&kvm->srcu, idx);
	pagefault_enable();
}
