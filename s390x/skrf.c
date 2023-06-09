/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Storage key removal facility tests
 *
 * Copyright (c) 2019 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
#include <libcflat.h>
#include <bitops.h>
#include <asm/asm-offsets.h>
#include <asm-generic/barrier.h>
#include <asm/interrupt.h>
#include <asm/page.h>
#include <asm/facility.h>
#include <asm/mem.h>
#include <asm/sigp.h>
#include <smp.h>

static uint8_t pagebuf[PAGE_SIZE * 2] __attribute__((aligned(PAGE_SIZE * 2)));
static int testflag = 0;

static void test_facilities(void)
{
	report_prefix_push("facilities");
	report(!test_facility(10), "!10");
	report(!test_facility(14), "!14");
	report(!test_facility(66), "!66");
	report(!test_facility(145), "!145");
	report(!test_facility(140), "!149");
	report_prefix_pop();
}

static void test_skey(void)
{
	report_prefix_push("sske");
	expect_pgm_int();
	set_storage_key(pagebuf, 0x30, 0);
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	expect_pgm_int();
	report_prefix_pop();
	report_prefix_push("iske");
	get_storage_key(pagebuf);
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_pfmf(void)
{
	union pfmf_r1 r1;

	report_prefix_push("pfmf");
	r1.val = 0;
	r1.reg.sk = 1;
	r1.reg.fsc = PFMF_FSC_4K;
	r1.reg.key = 0x30;
	expect_pgm_int();
	pfmf(r1.val, pagebuf);
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_psw_key(void)
{
	report_prefix_push("psw key");
	expect_pgm_int();
	psw_mask_set_bits(PSW_MASK_KEY);
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_mvcos(void)
{
	uint64_t r3 = 64;
	uint8_t *src = pagebuf;
	uint8_t *dst = pagebuf + PAGE_SIZE;
	/* K bit set, as well as keys */
	register unsigned long oac asm("0") = 0xf002f002;

	report_prefix_push("mvcos");
	expect_pgm_int();
	asm volatile("mvcos	%[dst],%[src],%[len]"
		     : [dst] "+Q" (*(dst))
		     : [src] "Q" (*(src)), [len] "d" (r3), "d" (oac)
		     : "cc", "memory");
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_spka(void)
{
	report_prefix_push("spka");
	expect_pgm_int();
	asm volatile("spka	0xf0(0)\n");
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void test_tprot(void)
{
	report_prefix_push("tprot");
	expect_pgm_int();
	tprot((unsigned long)pagebuf, 0xf);
	check_pgm_int_code(PGM_INT_CODE_SPECIAL_OPERATION);
	report_prefix_pop();
}

static void wait_for_flag(void)
{
	while (!testflag)
		mb();
}

static void set_flag(int val)
{
	mb();
	testflag = val;
	mb();
}

static void ecall_cleanup(struct stack_frame_int *stack)
{
	lowcore.ext_new_psw.mask = PSW_MASK_64;
	lowcore.sw_int_crs[0] = BIT_ULL(CTL0_AFP);

	/*
	 * PGM old contains the ext new PSW, we need to clean it up,
	 * so we don't get a special operation exception on the lpswe
	 * of pgm old.
	 */
	lowcore.pgm_old_psw.mask = PSW_MASK_64;

	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	set_flag(1);
}

/* Set a key into the external new psw mask and open external call masks */
static void ecall_setup(void)
{
	register_pgm_cleanup_func(ecall_cleanup);
	expect_pgm_int();
	/* Put a skey into the ext new psw */
	lowcore.ext_new_psw.mask = PSW_MASK_KEY | PSW_MASK_64;
	/* Open up ext masks */
	ctl_set_bit(0, CTL0_EXTERNAL_CALL);
	psw_mask_set_bits(PSW_MASK_EXT);
	/* Tell cpu 0 that we're ready */
	set_flag(1);
}

static void test_exception_ext_new(void)
{
	report_prefix_push("exception external new");
	if (smp_query_num_cpus() < 2) {
		report_skip("Need second cpu for exception external new test.");
		report_prefix_pop();
		return;
	}

	smp_cpu_setup(1, PSW_WITH_CUR_MASK(ecall_setup));
	wait_for_flag();
	set_flag(0);

	smp_sigp(1, SIGP_EXTERNAL_CALL, 0, NULL);
	wait_for_flag();
	smp_cpu_stop(1);
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("skrf");
	if (!test_facility(169)) {
		report_skip("storage key removal facility not available\n");
		goto done;
	}

	test_facilities();
	test_skey();
	test_pfmf();
	test_psw_key();
	test_mvcos();
	test_spka();
	test_tprot();
	test_exception_ext_new();

done:
	report_prefix_pop();
	return report_summary();
}
