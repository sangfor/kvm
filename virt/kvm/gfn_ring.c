#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/vmalloc.h>
#include <linux/kvm_gfn_ring.h>

int kvm_gfn_ring_alloc(struct kvm_gfn_ring *gfnring, u32 size, u32 limit)
{
	gfnring->dirty_ring = vmalloc(size);
	if (!gfnring->dirty_ring)
		return -ENOMEM;
	memset(gfnring->dirty_ring, 0, size);

	gfnring->size = size/sizeof(struct kvm_dirty_gfn);
	gfnring->soft_limit = limit;
	gfnring->dirty_index = 0;
	gfnring->reset_index = 0;
	spin_lock_init(&gfnring->lock);

	return 0;
}

int kvm_gfn_ring_reset(struct kvm *kvm, struct kvm_gfn_ring *gfnring)
{
	u32 cur_slot, next_slot;
	u64 cur_offset, next_offset;
	unsigned long mask;
	u32 fetch;
	int count = 0;
	struct kvm_dirty_gfn *entry;
	struct kvm_dirty_ring *ring = gfnring->dirty_ring;

	fetch = READ_ONCE(ring->indices.fetch_index);
	if (fetch == gfnring->reset_index)
		return 0;

	entry = &ring->dirty_gfns[gfnring->reset_index &
			(gfnring->size - 1)];
	/*
	 * The ring buffer is shared with userspace, which might mmap
	 * it and concurrently modify slot and offset.  Userspace must
	 * not be trusted!  READ_ONCE prevents the compiler from changing
	 * the values after they've been range-checked (the checks are
	 * in kvm_reset_dirty_gfn).
	 */
	smp_read_barrier_depends();
	cur_slot = READ_ONCE(entry->slot);
	cur_offset = READ_ONCE(entry->offset);
	mask = 1;
	count++;
	gfnring->reset_index++;
	while (gfnring->reset_index != fetch) {
		entry = &ring->dirty_gfns[gfnring->reset_index &
			(gfnring->size - 1)];
		smp_read_barrier_depends();
		next_slot = READ_ONCE(entry->slot);
		next_offset = READ_ONCE(entry->offset);
		gfnring->reset_index++;
		count++;
		/*
		 * Try to coalesce the reset operations when the guest is
		 * scanning pages in the same slot.
		 */
		if (next_slot == cur_slot) {
			int delta = next_offset - cur_offset;

			if (delta >= 0 && delta < BITS_PER_LONG) {
				mask |= 1ull << delta;
				continue;
			}

			/* Backwards visit, careful about overflows!  */
			if (delta > -BITS_PER_LONG && delta < 0 &&
			    (mask << -delta >> -delta) == mask) {
				cur_offset = next_offset;
				mask = (mask << -delta) | 1;
				continue;
			}
		}
		kvm_reset_dirty_gfn(kvm, cur_slot, cur_offset, mask);
		cur_slot = next_slot;
		cur_offset = next_offset;
		mask = 1;
	}
	kvm_reset_dirty_gfn(kvm, cur_slot, cur_offset, mask);

	return count;
}

int kvm_gfn_ring_push(struct kvm_gfn_ring *gfnring,
		      u32 slot,
		      u64 offset,
		      bool locked)
{
	int ret;
	u16 num;
	struct kvm_dirty_gfn *entry;

	if (locked)
		spin_lock(&gfnring->lock);

	num = (u16)(gfnring->dirty_index - gfnring->reset_index);
	if (num >= gfnring->size) {
		WARN_ON_ONCE(num > gfnring->size);
		ret = -EBUSY;
		goto out;
	}

	entry = &gfnring->dirty_ring->dirty_gfns[gfnring->dirty_index &
			(gfnring->size - 1)];
	entry->slot = slot;
	entry->offset = offset;
	smp_wmb();
	gfnring->dirty_index++;
	num = gfnring->dirty_index - gfnring->reset_index;
	gfnring->dirty_ring->indices.avail_index = gfnring->dirty_index;
	ret = num >= gfnring->soft_limit;

out:
	if (locked)
		spin_unlock(&gfnring->lock);

	return ret;
}

struct page *kvm_gfn_ring_get_page(struct kvm_gfn_ring *ring, u32 i)
{
	return vmalloc_to_page((void *)ring->dirty_ring+i*PAGE_SIZE);

}

void kvm_gfn_ring_free(struct kvm_gfn_ring *gfnring)
{
	if (gfnring->dirty_ring)
		vfree(gfnring->dirty_ring);
}
