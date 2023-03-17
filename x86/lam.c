/*
 * Intel LAM unit test
 *
 * Copyright (C) 2023 Intel
 *
 * Author: Robert Hoo <robert.hu@linux.intel.com>
 *         Binbin Wu <binbin.wu@linux.intel.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or
 * later.
 */

#include "libcflat.h"
#include "processor.h"
#include "desc.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "vm.h"
#include "asm/io.h"
#include "ioram.h"
#include "usermode.h"

#define LAM57_BITS 6
#define LAM48_BITS 15
#define LAM57_MASK	GENMASK_ULL(62, 57)
#define LAM48_MASK	GENMASK_ULL(62, 48)
#define CR3_LAM_BITS_MASK (X86_CR3_LAM_U48 | X86_CR3_LAM_U57)

struct invpcid_desc {
    u64 pcid : 12;
    u64 rsv  : 52;
    u64 addr : 64;
};

static int get_sup_lam_bits(void)
{
	if (this_cpu_has(X86_FEATURE_LA57) && read_cr4() & X86_CR4_LA57)
		return LAM57_BITS;
	else
		return LAM48_BITS;
}

/* According to LAM mode, set metadata in high bits */
static u64 set_metadata(u64 src, unsigned long lam)
{
	u64 metadata;

	switch (lam) {
	case LAM57_BITS: /* Set metadata in bits 62:57 */
		metadata = (NONCANONICAL & ((1UL << LAM57_BITS) - 1)) << 57;
		metadata |= (src & ~(LAM57_MASK));
		break;
	case LAM48_BITS: /* Set metadata in bits 62:48 */
		metadata = (NONCANONICAL & ((1UL << LAM48_BITS) - 1)) << 48;
		metadata |= (src & ~(LAM48_MASK));
		break;
	default:
		metadata = src;
		break;
	}

	return metadata;
}

static void cr4_set_lam_sup(void *data)
{
	unsigned long cr4;

	cr4 = read_cr4();
	write_cr4_safe(cr4 | X86_CR4_LAM_SUP);
}

static void cr4_clear_lam_sup(void *data)
{
	unsigned long cr4;

	cr4 = read_cr4();
	write_cr4_safe(cr4 & ~X86_CR4_LAM_SUP);
}

static void test_cr4_lam_set_clear(bool lam_enumerated)
{
	bool fault;

	fault = test_for_exception(GP_VECTOR, &cr4_set_lam_sup, NULL);
	if (lam_enumerated)
		report(!fault && (read_cr4() & X86_CR4_LAM_SUP),
		       "Set CR4.LAM_SUP");
	else
		report(fault, "Set CR4.LAM_SUP causes #GP");

	fault = test_for_exception(GP_VECTOR, &cr4_clear_lam_sup, NULL);
	report(!fault, "Clear CR4.LAM_SUP");
}

static void do_strcpy(void *mem)
{
	strcpy((char *)mem, "LAM SUP Test string.");
}

static inline uint64_t test_tagged_ptr(uint64_t arg1, uint64_t arg2,
	uint64_t arg3, uint64_t arg4)
{
	bool lam_enumerated = !!arg1;
	int lam_bits = (int)arg2;
	u64 *ptr = (u64 *)arg3;
	bool la_57 = !!arg4;
	bool fault;

	fault = test_for_exception(GP_VECTOR, do_strcpy, ptr);
	report(!fault, "strcpy to untagged addr");

	ptr = (u64 *)set_metadata((u64)ptr, lam_bits);
	fault = test_for_exception(GP_VECTOR, do_strcpy, ptr);
	if (lam_enumerated)
		report(!fault, "strcpy to tagged addr");
	else
		report(fault, "strcpy to tagged addr causes #GP");

	if (lam_enumerated && (lam_bits==LAM57_BITS) && !la_57) {
		ptr = (u64 *)set_metadata((u64)ptr, LAM48_BITS);
		fault = test_for_exception(GP_VECTOR, do_strcpy, ptr);
		report(fault, "strcpy to non-LAM-canonical addr causes #GP");
	}

	return 0;
}

/* Refer to emulator.c */
static void do_mov_mmio(void *mem)
{
	unsigned long t1, t2;

	// test mov reg, r/m and mov r/m, reg
	t1 = 0x123456789abcdefull & -1ul;
	asm volatile("mov %[t1], (%[mem])\n\t"
		     "mov (%[mem]), %[t2]"
		     : [t2]"=r"(t2)
		     : [t1]"r"(t1), [mem]"r"(mem)
		     : "memory");
	report(t1==t2, "MOV MMIO result comparison");
}

static inline uint64_t test_tagged_mmio_ptr(uint64_t arg1, uint64_t arg2,
	uint64_t arg3, uint64_t arg4)
{
	bool lam_enumerated = !!arg1;
	int lam_bits = (int)arg2;
	u64 *ptr = (u64 *)arg3;
	bool la_57 = !!arg4;
	bool fault;

	fault = test_for_exception(GP_VECTOR, do_mov_mmio, ptr);
	report(!fault, "Access MMIO with untagged addr");

	ptr = (u64 *)set_metadata((u64)ptr, lam_bits);
	fault = test_for_exception(GP_VECTOR, do_mov_mmio, ptr);
	if (lam_enumerated)
		report(!fault,  "Access MMIO with tagged addr");
	else
		report(fault,  "Access MMIO with tagged addr causes #GP");

	if (lam_enumerated && (lam_bits==LAM57_BITS) && !la_57) {
		ptr = (u64 *)set_metadata((u64)ptr, LAM48_BITS);
		fault = test_for_exception(GP_VECTOR, do_mov_mmio, ptr);
		report(fault,  "Access MMIO with non-LAM-canonical addr"
		               " causes #GP");
	}

	return 0;
}

static void do_invlpg(void *mem)
{
	invlpg(mem);
}

static void do_invlpg_fep(void *mem)
{
	asm volatile(KVM_FEP "invlpg (%0)" ::"r" (mem) : "memory");
}

/* invlpg with tagged address is same as NOP, no #GP */
static void test_invlpg(void *va, bool fep)
{
	bool fault;
	u64 *ptr;

	ptr = (u64 *)set_metadata((u64)va, get_sup_lam_bits());
	if (fep)
		fault = test_for_exception(GP_VECTOR, do_invlpg_fep, ptr);
	else
		fault = test_for_exception(GP_VECTOR, do_invlpg, ptr);

	report(!fault, "%sINVLPG with tagged addr", fep?"fep: ":"");
}

static void do_invpcid(void *desc)
{
	unsigned long type = 0;
	struct invpcid_desc *desc_ptr = (struct invpcid_desc *)desc;

	asm volatile("invpcid %0, %1" :
	                              : "m" (*desc_ptr), "r" (type)
	                              : "memory");
}

static void test_invpcid(bool lam_enumerated, void *data)
{
	struct invpcid_desc *desc_ptr = (struct invpcid_desc *) data;
	int lam_bits = get_sup_lam_bits();
	bool fault;

	if (!this_cpu_has(X86_FEATURE_PCID) ||
	    !this_cpu_has(X86_FEATURE_INVPCID)) {
		report_skip("INVPCID not supported");
		return;
	}

	memset(desc_ptr, 0, sizeof(struct invpcid_desc));
	desc_ptr->addr = (u64)data + 16;

	fault = test_for_exception(GP_VECTOR, do_invpcid, desc_ptr);
	report(!fault, "INVPCID: untagged pointer + untagged addr");

	desc_ptr->addr = set_metadata(desc_ptr->addr, lam_bits);
	fault = test_for_exception(GP_VECTOR, do_invpcid, desc_ptr);
	report(fault, "INVPCID: untagged pointer + tagged addr causes #GP");

	desc_ptr->addr = (u64)data + 16;
	desc_ptr = (struct invpcid_desc *)set_metadata((u64)desc_ptr, lam_bits);
	fault = test_for_exception(GP_VECTOR, do_invpcid, desc_ptr);
	if (lam_enumerated && (read_cr4() & X86_CR4_LAM_SUP))
		report(!fault, "INVPCID: tagged pointer + untagged addr");
	else
		report(fault, "INVPCID: tagged pointer + untagged addr"
		              " causes #GP");

	desc_ptr = (struct invpcid_desc *)data;
	desc_ptr->addr = (u64)data + 16;
	desc_ptr->addr = set_metadata(desc_ptr->addr, lam_bits);
	desc_ptr = (struct invpcid_desc *)set_metadata((u64)desc_ptr, lam_bits);
	fault = test_for_exception(GP_VECTOR, do_invpcid, desc_ptr);
	report(fault, "INVPCID: tagged pointer + tagged addr causes #GP");
}

static void test_lam_sup(bool lam_enumerated, bool fep_available)
{
	void *vaddr, *vaddr_mmio;
	phys_addr_t paddr;
	bool fault;
	bool la_57 = read_cr4() & X86_CR4_LA57;
	int lam_bits = get_sup_lam_bits();

	vaddr = alloc_vpage();
	vaddr_mmio = alloc_vpage();
	paddr = virt_to_phys(alloc_page());
	install_page(current_page_table(), paddr, vaddr);
	install_page(current_page_table(), IORAM_BASE_PHYS, vaddr_mmio);

	test_cr4_lam_set_clear(lam_enumerated);

	/* Set for the following LAM_SUP tests */
	if (lam_enumerated) {
		fault = test_for_exception(GP_VECTOR, &cr4_set_lam_sup, NULL);
		report(!fault && (read_cr4() & X86_CR4_LAM_SUP),
		       "Set CR4.LAM_SUP");
	}

	test_tagged_ptr(lam_enumerated, lam_bits, (u64)vaddr, la_57);
	test_tagged_mmio_ptr(lam_enumerated, lam_bits, (u64)vaddr_mmio, la_57);
	test_invlpg(vaddr, false);
	test_invpcid(lam_enumerated, vaddr);

	if (fep_available)
		test_invlpg(vaddr, true);
}

static void test_lam_user(bool lam_enumerated)
{
	unsigned long cr3;
	bool is_la57;
	unsigned r;
	bool raised_vector = false;
	phys_addr_t paddr;

	/*
	 * The physical address width is within 36 bits, so that using identical
	 * mapping, the linear address will be considered as user mode address
	 * from the view of LAM.
	 */
	paddr = virt_to_phys(alloc_page());
	install_page((void *)(read_cr3()& ~CR3_LAM_BITS_MASK), paddr, (void *)paddr);
	install_page((void *)(read_cr3()& ~CR3_LAM_BITS_MASK), IORAM_BASE_PHYS,
		     (void *)IORAM_BASE_PHYS);

	cr3 = read_cr3();
	is_la57 = !!(read_cr4() & X86_CR4_LA57);

	/* Test LAM_U48 */
	if(lam_enumerated) {
		r = write_cr3_safe((cr3 & ~X86_CR3_LAM_U57) | X86_CR3_LAM_U48);
		report(r==0 && ((read_cr3() & CR3_LAM_BITS_MASK) == X86_CR3_LAM_U48),
		       "Set LAM_U48");
	}

	run_in_user((usermode_func)test_tagged_ptr, GP_VECTOR, lam_enumerated,
		    LAM48_BITS, paddr, is_la57, &raised_vector);
	run_in_user((usermode_func)test_tagged_mmio_ptr, GP_VECTOR, lam_enumerated,
		    LAM48_BITS, IORAM_BASE_PHYS, is_la57, &raised_vector);


	/* Test LAM_U57 */
	if(lam_enumerated) {
		r = write_cr3_safe(cr3 | X86_CR3_LAM_U57);
		report(r==0 && (read_cr3() & X86_CR3_LAM_U57), "Set LAM_U57");
	}

	run_in_user((usermode_func)test_tagged_ptr, GP_VECTOR, lam_enumerated,
		    LAM57_BITS, paddr, is_la57, &raised_vector);
	run_in_user((usermode_func)test_tagged_mmio_ptr, GP_VECTOR, lam_enumerated,
		    LAM57_BITS, IORAM_BASE_PHYS, is_la57, &raised_vector);
}

int main(int ac, char **av)
{
	bool lam_enumerated;
	bool fep_available = is_fep_available();

	setup_vm();

	lam_enumerated = this_cpu_has(X86_FEATURE_LAM);
	if (!lam_enumerated)
		report_info("This CPU doesn't support LAM feature\n");
	else
		report_info("This CPU supports LAM feature\n");

	if (!fep_available)
		report_skip("Skipping tests the forced emulation, "
			    "use kvm.force_emulation_prefix=1 to enable\n");

	test_lam_sup(lam_enumerated, fep_available);
	test_lam_user(lam_enumerated);

	return report_summary();
}
