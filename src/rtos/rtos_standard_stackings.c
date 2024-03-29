// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2011 by Broadcom Corporation                            *
 *   Evan Hunter - ehunter@broadcom.com                                    *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rtos.h"
#include "target/armv7m.h"

static const struct stack_register_offset rtos_standard_cortex_m3_stack_offsets[ARMV7M_NUM_CORE_REGS] = {
	{ ARMV7M_R0,   0x20, 32 },		/* r0   */
	{ ARMV7M_R1,   0x24, 32 },		/* r1   */
	{ ARMV7M_R2,   0x28, 32 },		/* r2   */
	{ ARMV7M_R3,   0x2c, 32 },		/* r3   */
	{ ARMV7M_R4,   0x00, 32 },		/* r4   */
	{ ARMV7M_R5,   0x04, 32 },		/* r5   */
	{ ARMV7M_R6,   0x08, 32 },		/* r6   */
	{ ARMV7M_R7,   0x0c, 32 },		/* r7   */
	{ ARMV7M_R8,   0x10, 32 },		/* r8   */
	{ ARMV7M_R9,   0x14, 32 },		/* r9   */
	{ ARMV7M_R10,  0x18, 32 },		/* r10  */
	{ ARMV7M_R11,  0x1c, 32 },		/* r11  */
	{ ARMV7M_R12,  0x30, 32 },		/* r12  */
	{ ARMV7M_R13,  -2,   32 },		/* sp   */
	{ ARMV7M_R14,  0x34, 32 },		/* lr   */
	{ ARMV7M_PC,   0x38, 32 },		/* pc   */
	{ ARMV7M_XPSR, 0x3c, 32 },		/* xPSR */
};

static const struct stack_register_offset rtos_standard_cortex_m4f_stack_offsets[] = {
	{ ARMV7M_R0,   0x24, 32 },		/* r0   */
	{ ARMV7M_R1,   0x28, 32 },		/* r1   */
	{ ARMV7M_R2,   0x2c, 32 },		/* r2   */
	{ ARMV7M_R3,   0x30, 32 },		/* r3   */
	{ ARMV7M_R4,   0x00, 32 },		/* r4   */
	{ ARMV7M_R5,   0x04, 32 },		/* r5   */
	{ ARMV7M_R6,   0x08, 32 },		/* r6   */
	{ ARMV7M_R7,   0x0c, 32 },		/* r7   */
	{ ARMV7M_R8,   0x10, 32 },		/* r8   */
	{ ARMV7M_R9,   0x14, 32 },		/* r9   */
	{ ARMV7M_R10,  0x18, 32 },		/* r10  */
	{ ARMV7M_R11,  0x1c, 32 },		/* r11  */
	{ ARMV7M_R12,  0x34, 32 },		/* r12  */
	{ ARMV7M_R13,  -2,   32 },		/* sp   */
	{ ARMV7M_R14,  0x38, 32 },		/* lr   */
	{ ARMV7M_PC,   0x3c, 32 },		/* pc   */
	{ ARMV7M_XPSR, 0x40, 32 },		/* xPSR */
};

static const struct stack_register_offset rtos_standard_cortex_m4f_fpu_stack_offsets[] = {
	{ ARMV7M_R0,   0x64, 32 },		/* r0   */
	{ ARMV7M_R1,   0x68, 32 },		/* r1   */
	{ ARMV7M_R2,   0x6c, 32 },		/* r2   */
	{ ARMV7M_R3,   0x70, 32 },		/* r3   */
	{ ARMV7M_R4,   0x00, 32 },		/* r4   */
	{ ARMV7M_R5,   0x04, 32 },		/* r5   */
	{ ARMV7M_R6,   0x08, 32 },		/* r6   */
	{ ARMV7M_R7,   0x0c, 32 },		/* r7   */
	{ ARMV7M_R8,   0x10, 32 },		/* r8   */
	{ ARMV7M_R9,   0x14, 32 },		/* r9   */
	{ ARMV7M_R10,  0x18, 32 },		/* r10  */
	{ ARMV7M_R11,  0x1c, 32 },		/* r11  */
	{ ARMV7M_R12,  0x74, 32 },		/* r12  */
	{ ARMV7M_R13,  -2,   32 },		/* sp   */
	{ ARMV7M_R14,  0x78, 32 },		/* lr   */
	{ ARMV7M_PC,   0x7c, 32 },		/* pc   */
	{ ARMV7M_XPSR, 0x80, 32 },		/* xPSR */
};


static const struct stack_register_offset rtos_standard_cortex_r4_stack_offsets[] = {
	{ 0,  0x08, 32 },		/* r0  (a1)   */
	{ 1,  0x0c, 32 },		/* r1  (a2)  */
	{ 2,  0x10, 32 },		/* r2  (a3)  */
	{ 3,  0x14, 32 },		/* r3  (a4)  */
	{ 4,  0x18, 32 },		/* r4  (v1)  */
	{ 5,  0x1c, 32 },		/* r5  (v2)  */
	{ 6,  0x20, 32 },		/* r6  (v3)  */
	{ 7,  0x24, 32 },		/* r7  (v4)  */
	{ 8,  0x28, 32 },		/* r8  (a1)  */
	{ 10, 0x2c, 32 },		/* r9  (sb)  */
	{ 11, 0x30, 32 },		/* r10 (sl) */
	{ 12, 0x34, 32 },		/* r11 (fp) */
	{ 13, 0x38, 32 },		/* r12 (ip) */
	{ 14, -2,   32 },		/* sp   */
	{ 15, 0x3c, 32 },		/* lr   */
	{ 16, 0x40, 32 },		/* pc   */
	{ 17, -1,   96 },		/* FPA1 */
	{ 18, -1,   96 },		/* FPA2 */
	{ 19, -1,   96 },		/* FPA3 */
	{ 20, -1,   96 },		/* FPA4 */
	{ 21, -1,   96 },		/* FPA5 */
	{ 22, -1,   96 },		/* FPA6 */
	{ 23, -1,   96 },		/* FPA7 */
	{ 24, -1,   96 },		/* FPA8 */
	{ 25, -1,   32 },		/* FPS  */
	{ 26, 0x04, 32 },		/* CSPR */
};

static const struct stack_register_offset rtos_standard_nds32_n1068_stack_offsets[] = {
	{ 0,  0x88, 32 },		/* R0  */
	{ 1,  0x8C, 32 },		/* R1 */
	{ 2,  0x14, 32 },		/* R2 */
	{ 3,  0x18, 32 },		/* R3 */
	{ 4,  0x1C, 32 },		/* R4 */
	{ 5,  0x20, 32 },		/* R5 */
	{ 6,  0x24, 32 },		/* R6 */
	{ 7,  0x28, 32 },		/* R7 */
	{ 8,  0x2C, 32 },		/* R8 */
	{ 9,  0x30, 32 },		/* R9 */
	{ 10, 0x34, 32 },		/* R10 */
	{ 11, 0x38, 32 },		/* R11 */
	{ 12, 0x3C, 32 },		/* R12 */
	{ 13, 0x40, 32 },		/* R13 */
	{ 14, 0x44, 32 },		/* R14 */
	{ 15, 0x48, 32 },		/* R15 */
	{ 16, 0x4C, 32 },		/* R16 */
	{ 17, 0x50, 32 },		/* R17 */
	{ 18, 0x54, 32 },		/* R18 */
	{ 19, 0x58, 32 },		/* R19 */
	{ 20, 0x5C, 32 },		/* R20 */
	{ 21, 0x60, 32 },		/* R21 */
	{ 22, 0x64, 32 },		/* R22 */
	{ 23, 0x68, 32 },		/* R23 */
	{ 24, 0x6C, 32 },		/* R24 */
	{ 25, 0x70, 32 },		/* R25 */
	{ 26, 0x74, 32 },		/* R26 */
	{ 27, 0x78, 32 },		/* R27 */
	{ 28, 0x7C, 32 },		/* R28 */
	{ 29, 0x80, 32 },		/* R29 */
	{ 30, 0x84, 32 },		/* R30 (LP) */
	{ 31, 0x00, 32 },		/* R31 (SP) */
	{ 32, 0x04, 32 },		/* PSW */
	{ 33, 0x08, 32 },		/* IPC */
	{ 34, 0x0C, 32 },		/* IPSW */
	{ 35, 0x10, 32 },		/* IFC_LP */
};

static target_addr_t rtos_generic_stack_align(struct target *target,
	const uint8_t *stack_data, const struct rtos_register_stacking *stacking,
	target_addr_t stack_ptr, int align)
{
	target_addr_t new_stack_ptr;
	target_addr_t aligned_stack_ptr;
	new_stack_ptr = stack_ptr - stacking->stack_growth_direction *
		stacking->stack_registers_size;
	aligned_stack_ptr = new_stack_ptr & ~((target_addr_t)align - 1);
	if (aligned_stack_ptr != new_stack_ptr &&
		stacking->stack_growth_direction == -1) {
		/* If we have a downward growing stack, the simple alignment code
		 * above results in a wrong result (since it rounds down to nearest
		 * alignment).  We want to round up so add an extra align.
		 */
		aligned_stack_ptr += (target_addr_t)align;
	}
	return aligned_stack_ptr;
}

target_addr_t rtos_generic_stack_align8(struct target *target,
	const uint8_t *stack_data, const struct rtos_register_stacking *stacking,
	target_addr_t stack_ptr)
{
	return rtos_generic_stack_align(target, stack_data,
			stacking, stack_ptr, 8);
}

/* The Cortex-M3 will indicate that an alignment adjustment
 * has been done on the stack by setting bit 9 of the stacked xPSR
 * register.  In this case, we can just add an extra 4 bytes to get
 * to the program stack.  Note that some places in the ARM documentation
 * make this a little unclear but the padding takes place before the
 * normal exception stacking - so xPSR is always available at a fixed
 * location.
 *
 * Relevant documentation:
 *    Cortex-M series processors -> Cortex-M3 -> Revision: xxx ->
 *        Cortex-M3 Devices Generic User Guide -> The Cortex-M3 Processor ->
 *        Exception Model -> Exception entry and return -> Exception entry
 *    Cortex-M series processors -> Cortex-M3 -> Revision: xxx ->
 *        Cortex-M3 Devices Generic User Guide -> Cortex-M3 Peripherals ->
 *        System control block -> Configuration and Control Register (STKALIGN)
 *
 * This is just a helper function for use in the calculate_process_stack
 * function for a given architecture/rtos.
 */
target_addr_t rtos_cortex_m_stack_align(struct target *target,
	const uint8_t *stack_data, const struct rtos_register_stacking *stacking,
	target_addr_t stack_ptr, size_t xpsr_offset)
{
	const uint32_t ALIGN_NEEDED = (1 << 9);
	uint32_t xpsr;
	target_addr_t new_stack_ptr;

	new_stack_ptr = stack_ptr - stacking->stack_growth_direction *
		stacking->stack_registers_size;
	xpsr = (target->endianness == TARGET_LITTLE_ENDIAN) ?
			le_to_h_u32(&stack_data[xpsr_offset]) :
			be_to_h_u32(&stack_data[xpsr_offset]);
	if ((xpsr & ALIGN_NEEDED) != 0) {
		LOG_DEBUG("XPSR(0x%08" PRIx32 ") indicated stack alignment was necessary\r\n",
			xpsr);
		new_stack_ptr -= (stacking->stack_growth_direction * 4);
	}
	return new_stack_ptr;
}

static target_addr_t rtos_standard_cortex_m3_stack_align(struct target *target,
	const uint8_t *stack_data, const struct rtos_register_stacking *stacking,
	target_addr_t stack_ptr)
{
	const int XPSR_OFFSET = 0x3c;
	return rtos_cortex_m_stack_align(target, stack_data, stacking,
		stack_ptr, XPSR_OFFSET);
}

static target_addr_t rtos_standard_cortex_m4f_stack_align(struct target *target,
	const uint8_t *stack_data, const struct rtos_register_stacking *stacking,
	target_addr_t stack_ptr)
{
	const int XPSR_OFFSET = 0x40;
	return rtos_cortex_m_stack_align(target, stack_data, stacking,
		stack_ptr, XPSR_OFFSET);
}

static target_addr_t rtos_standard_cortex_m4f_fpu_stack_align(struct target *target,
	const uint8_t *stack_data, const struct rtos_register_stacking *stacking,
	target_addr_t stack_ptr)
{
	const int XPSR_OFFSET = 0x80;
	return rtos_cortex_m_stack_align(target, stack_data, stacking,
		stack_ptr, XPSR_OFFSET);
}


const struct rtos_register_stacking rtos_standard_cortex_m3_stacking = {
	.stack_registers_size = 0x40,
	.stack_growth_direction = -1,
	.num_output_registers = ARMV7M_NUM_CORE_REGS,
	.calculate_process_stack = rtos_standard_cortex_m3_stack_align,
	.register_offsets = rtos_standard_cortex_m3_stack_offsets
};

const struct rtos_register_stacking rtos_standard_cortex_m4f_stacking = {
	.stack_registers_size = 0x44,
	.stack_growth_direction = -1,
	.num_output_registers = ARMV7M_NUM_CORE_REGS,
	.calculate_process_stack = rtos_standard_cortex_m4f_stack_align,
	.register_offsets = rtos_standard_cortex_m4f_stack_offsets
};

const struct rtos_register_stacking rtos_standard_cortex_m4f_fpu_stacking = {
	.stack_registers_size = 0xcc,
	.stack_growth_direction = -1,
	.num_output_registers = ARMV7M_NUM_CORE_REGS,
	.calculate_process_stack = rtos_standard_cortex_m4f_fpu_stack_align,
	.register_offsets = rtos_standard_cortex_m4f_fpu_stack_offsets
};

const struct rtos_register_stacking rtos_standard_cortex_r4_stacking = {
	.stack_registers_size = 0x48,
	.stack_growth_direction = -1,
	.num_output_registers = 26,
	.calculate_process_stack = rtos_generic_stack_align8,
	.register_offsets = rtos_standard_cortex_r4_stack_offsets
};

const struct rtos_register_stacking rtos_standard_nds32_n1068_stacking = {
	.stack_registers_size = 0x90,
	.stack_growth_direction = -1,
	.num_output_registers = 32,
	.calculate_process_stack = rtos_generic_stack_align8,
	.register_offsets = rtos_standard_nds32_n1068_stack_offsets
};

static const struct stack_register_offset rtos_standard_ppc476fp_stack_offsets[] = {
	{ 0x00, 0x24, 32 },		/* R0 */
	{ 0x01, 0x00, 32 },		/* R1 (SP) */
	{ 0x02, 0x28, 32 },		/* R2 */
	{ 0x03, 0x2c, 32 },		/* R3 */
	{ 0x04, 0x30, 32 },		/* R4 */
	{ 0x05, 0x34, 32 },		/* R5 */
	{ 0x06, 0x38, 32 },		/* R6 */
	{ 0x07, 0x3c, 32 },		/* R7 */
	{ 0x08, 0x40, 32 },		/* R8 */
	{ 0x09, 0x44, 32 },		/* R9 */
	{ 0x0a, 0x48, 32 },		/* R10 */
	{ 0x0b, 0x4c, 32 },		/* R11 */
	{ 0x0c, 0x50, 32 },		/* R12 */
	{ 0x0d, 0x54, 32 },		/* R13 */
	{ 0x0e, 0x58, 32 },		/* R14 */
	{ 0x0f, 0x5c, 32 },		/* R15 */
	{ 0x10, 0x60, 32 },		/* R16 */
	{ 0x11, 0x64, 32 },		/* R17 */
	{ 0x12, 0x68, 32 },		/* R18 */
	{ 0x13, 0x6c, 32 },		/* R19 */
	{ 0x14, 0x70, 32 },		/* R20 */
	{ 0x15, 0x74, 32 },		/* R21 */
	{ 0x16, 0x78, 32 },		/* R22 */
	{ 0x17, 0x7c, 32 },		/* R23 */
	{ 0x18, 0x80, 32 },		/* R24 */
	{ 0x19, 0x84, 32 },		/* R25 */
	{ 0x1a, 0x88, 32 },		/* R26 */
	{ 0x1b, 0x8c, 32 },		/* R27 */
	{ 0x1c, 0x90, 32 },		/* R28 */
	{ 0x1d, 0x94, 32 },		/* R29 */
	{ 0x1e, 0x98, 32 },		/* R30 */
	{ 0x1f, 0x9c, 32 },		/* R31 */

	{ 0x20, -1, 32 },		/* F0 */
	{ 0x21, -1, 32 },		/* F1 */
	{ 0x22, -1, 32 },		/* F2 */
	{ 0x23, -1, 32 },		/* F3 */
	{ 0x24, -1, 32 },		/* F4 */
	{ 0x25, -1, 32 },		/* F5 */
	{ 0x26, -1, 32 },		/* F6 */
	{ 0x27, -1, 32 },		/* F7 */
	{ 0x28, -1, 32 },		/* F8 */
	{ 0x29, -1, 32 },		/* F9 */
	{ 0x2a, -1, 32 },		/* F10 */
	{ 0x2b, -1, 32 },		/* F11 */
	{ 0x2c, -1, 32 },		/* F12 */
	{ 0x2d, -1, 32 },		/* F13 */
	{ 0x2e, -1, 32 },		/* F14 */
	{ 0x2f, -1, 32 },		/* F15 */
	{ 0x30, -1, 32 },		/* F16 */
	{ 0x31, -1, 32 },		/* F17 */
	{ 0x32, -1, 32 },		/* F18 */
	{ 0x33, -1, 32 },		/* F19 */
	{ 0x34, -1, 32 },		/* F20 */
	{ 0x35, -1, 32 },		/* F21 */
	{ 0x36, -1, 32 },		/* F22 */
	{ 0x37, -1, 32 },		/* F23 */
	{ 0x38, -1, 32 },		/* F24 */
	{ 0x39, -1, 32 },		/* F25 */
	{ 0x3a, -1, 32 },		/* F26 */
	{ 0x3b, -1, 32 },		/* F27 */
	{ 0x3c, -1, 32 },		/* F28 */
	{ 0x3d, -1, 32 },		/* F29 */
	{ 0x3e, -1, 32 },		/* F30 */
	{ 0x3f, -1, 32 },		/* F31 */

	{ 0x40, 0x0c, 32 },		/* PC */
	{ 0x41, 0x08, 32 },		/* MSR */
	{ 0x42, 0x1c, 32 },		/* CR */
	{ 0x43, 0x10, 32 },		/* LR */
	{ 0x44, 0x14, 32 },		/* CTR */
	{ 0x45, 0x18, 32 },		/* XER */
};

const struct rtos_register_stacking rtos_standart_ppc476fp_stacking = {
    .stack_registers_size = 0xa0,
	.stack_growth_direction = -1,
	.num_output_registers = 38,
	.register_offsets = rtos_standard_ppc476fp_stack_offsets
};
