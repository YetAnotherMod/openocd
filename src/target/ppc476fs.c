#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/jtag.h>
#include <target/target.h>
#include <target/target_type.h>
#include <target/register.h>
#include <target/breakpoints.h>
#include <helper/log.h>

// jtag instruction codes without core ids
#define JTAG_INSTR_WRITE_JDCR_READ_JDSR 0x28 /* 0b0101000 */
#define JTAG_INSTR_WRITE_JISB_READ_JDSR 0x38 /* 0b0111000 */
#define JTAG_INSTR_WRITE_READ_DBDR 0x58 /* 0b1011000 */

#define JDSR_PSP_MASK (1 << (31 - 31))

#define JDCR_STO_MASK (1 << (31 - 0))
#define JDCR_SS_MASK (1 << (31 - 2))
#define JDCR_RESET_MASK (3 << (31 - 4)) // system reset
#define JDCR_RSDBSR_MASK (1 << (31 - 8))

#define SPR_REG_NUM_LR 8 
#define SPR_REG_NUM_CTR 9
#define SPR_REG_NUM_XER 1
#define SPR_REG_NUM_DBCR0 308
#define SPR_REG_NUM_DBCR1 309
#define SPR_REG_NUM_DBCR2 310
#define SPR_REG_NUM_DBSR 304
#define SPR_REG_NUM_IAC_BASE 312 /* IAC1..IAC4 */

#define DBCR0_EDM_MASK (1 << (63 - 32))
#define DBCR0_IAC1_MASK (1 << (63 - 40))
#define DBCR0_IACX_MASK (0xF << (63 - 43))
#define DBCR0_FT_MASK (1 << (63 - 63))

#define DBSR_IAC1_MASK (1 << (63 - 40))
#define DBSR_IAC2_MASK (1 << (63 - 41))
#define DBSR_IAC3_MASK (1 << (63 - 42))
#define DBSR_IAC4_MASK (1 << (63 - 43))
#define DBSR_DAC1R_MASK (1 << (63 - 44))
#define DBSR_DAC1W_MASK (1 << (63 - 45))
#define DBSR_DAC2R_MASK (1 << (63 - 46))
#define DBSR_DAC2W_MASK (1 << (63 - 47))
#define DBSR_IAC_ALL_MASK (DBSR_IAC1_MASK | DBSR_IAC2_MASK | DBSR_IAC3_MASK | DBSR_IAC4_MASK)
#define DBSR_DAC_ALL_MASK (DBSR_DAC1R_MASK | DBSR_DAC1W_MASK | DBSR_DAC2R_MASK | DBSR_DAC2W_MASK)

#define MSR_FP_MASK (1 << (63 - 50))

#define ALL_REG_COUNT 71
#define GDB_REG_COUNT 71 /* at start of all register array */
#define GEN_CACHE_REG_COUNT 38 /* R0-R31, PC, MSR, CR, LR, CTR, XER */
#define FPU_CACHE_REG_COUNT 33 /* F0-F31, FPSCR */
#define GPR_REG_COUNT 32
#define FPR_REG_COUNT 32

#define MAGIC_RANDOM_VALUE_1 0x396F965C
#define MAGIC_RANDOM_VALUE_2 0x44692D7E

struct ppc476fs_common {
	struct reg *all_regs[ALL_REG_COUNT];
	struct reg *gpr_regs[GPR_REG_COUNT];
	struct reg *fpr_regs[FPR_REG_COUNT];
	struct reg *PC_reg;
	struct reg *MSR_reg;
	struct reg *CR_reg;
	struct reg *LR_reg;
	struct reg *CTR_reg;
	struct reg *XER_reg;
	struct reg *FPSCR_reg;
	uint32_t DBCR0_value;
	uint32_t saved_R1; // ???
	uint32_t saved_R2; // ???
	uint32_t saved_R31; // ???
	uint32_t saved_LR; // ???
	uint64_t saved_F0; // ???
};

static int ppc476fs_get_gen_reg(struct reg *reg);
static int ppc476fs_set_gen_reg(struct reg *reg, uint8_t *buf);

static const struct reg_arch_type ppc476fs_gen_reg_type = {
	.get = ppc476fs_get_gen_reg,
	.set = ppc476fs_set_gen_reg
};

static int ppc476fs_get_fpu_reg(struct reg *reg);
static int ppc476fs_set_fpu_reg(struct reg *reg, uint8_t *buf);

static const struct reg_arch_type ppc476fs_fpu_reg_type = {
	.get = ppc476fs_get_fpu_reg,
	.set = ppc476fs_set_fpu_reg
};

static const uint32_t coreid_mask[4] = {
	0x4, 0x6
};

static inline struct ppc476fs_common *target_to_ppc476fs(struct target *target)
{
	return target->arch_info;
}

static inline uint32_t get_reg_value_32(struct reg *reg) {
	return *((uint32_t*)reg->value);
}

static inline void set_reg_value_32(struct reg *reg, uint32_t value) {
	*((uint32_t*)reg->value) = value;
}

static int jtag_read_write_register(struct target *target, uint32_t instr_without_coreid, uint32_t valid_bit, uint32_t write_data, uint32_t *read_data)
{
	struct scan_field field;
	struct scan_field fields[2];
	uint8_t instr_buffer[4];
	uint8_t data_out_buffer[4];
	uint8_t data_in_buffer[4];
	uint8_t valid_buffer[4];
	int ret;

	buf_set_u32(instr_buffer, 0, target->tap->ir_length, instr_without_coreid | coreid_mask[target->coreid]);
	field.num_bits = target->tap->ir_length;
	field.out_value = instr_buffer;
	field.in_value = NULL;
	jtag_add_ir_scan(target->tap, &field, TAP_IDLE);

	buf_set_u32(data_out_buffer, 0, 32, write_data);
	fields[0].num_bits = 32;
	fields[0].out_value = data_out_buffer;
	fields[0].in_value = data_in_buffer;

	buf_set_u32(valid_buffer, 0, 1, valid_bit);
	fields[1].num_bits = 1;
	fields[1].out_value = valid_buffer;
	fields[1].in_value = NULL;

	jtag_add_dr_scan(target->tap, 2, fields, TAP_IDLE);
	ret = jtag_execute_queue();
	if (ret != ERROR_OK)
		return ret;

	if (read_data != NULL)
		*read_data = buf_get_u32(data_in_buffer, 0, 32);

	return ERROR_OK;
}

static int read_JDSR(struct target *target, uint32_t *data)
{
	return jtag_read_write_register(target, JTAG_INSTR_WRITE_JDCR_READ_JDSR, 0, 0, data);
}

static int write_JDCR(struct target *target, uint32_t data)
{
	int ret;

	ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_JDCR_READ_JDSR, 1, data, NULL);
	if (ret != ERROR_OK)
		return ret;

	// !!! IMPORTANT
	// make additional write_JDCR/read_JDSR request with valid bit == 0
	// to correct a JTAG communication BUG
	return jtag_read_write_register(target, JTAG_INSTR_WRITE_JDCR_READ_JDSR, 0, 0, NULL);
}

static int stuff_code(struct target *target, uint32_t code)
{
	int ret;

	ret =  jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR, 1, code, NULL);
	if (ret != ERROR_OK)
		return ret;

	// !!! IMPORTANT
	// make additional write_JISB/read_JDSR request with valid bit == 0
	// to correct a JTAG communication BUG
	return jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR, 0, 0, NULL);
}

static int read_DBDR(struct target *target, uint32_t *data)
{
	return jtag_read_write_register(target, JTAG_INSTR_WRITE_READ_DBDR, 0, 0, data);
}

static int write_DBDR(struct target *target, uint32_t data)
{
	int ret;

	ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_READ_DBDR, 1, data, NULL);
	if (ret != ERROR_OK)
		return ret;

	// !!! IMPORTANT
	// make additional write_DBDR/read_DBDR request with valid bit == 0
	// to correct a JTAG communication BUG
	return jtag_read_write_register(target, JTAG_INSTR_WRITE_READ_DBDR, 0, 0, NULL);
}

static int read_gpr_reg(struct target *target, int reg_num, uint32_t *data)
{
	uint32_t code = 0x7C13FBA6 | (reg_num << 21); // mtdbdr Rx
	int ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	
	return read_DBDR(target, data);
}

static int write_gpr_reg(struct target *target, int reg_num, uint32_t data)
{
	uint32_t code;
	int ret = write_DBDR(target, data);
	if (ret != ERROR_OK)
		return ret;

	code = 0x7C13FAA6 | (reg_num << 21); // mfdbdr Rx
	return stuff_code(target, code);
}

// the function uses R31 register and does not restore one
static int read_spr_reg(struct target *target, int spr_num, uint32_t *data)
{
	uint32_t code = 0x7FE002A6 | ((spr_num & 0x1F) << 16) | ((spr_num & 0x3E0) << (11 - 5)); // mfspr R31, spr
	int ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	return read_gpr_reg(target, 31, data);
}

// the function uses R31 register and does not restore one
static int write_spr_reg(struct target *target, int spr_num, uint32_t data)
{
	uint32_t code;
	int ret = write_gpr_reg(target, 31, data);
	if (ret != ERROR_OK)
		return ret;

	code = 0x7FE003A6 | ((spr_num & 0x1F) << 16) | ((spr_num & 0x3E0) << (11 - 5)); // mtspr spr, R31
	return stuff_code(target, code);
}

static int test_memory_at_stack(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	uint32_t value_1;
	uint32_t value_2;
	int ret;

	if ((ppc476fs->saved_R1 < 8) || ((ppc476fs->saved_R1 & 0x3) != 0)) // check the stack pointer
		return ERROR_FAIL;

	// set magic values to memory
	ret = write_gpr_reg(target, 2, MAGIC_RANDOM_VALUE_1);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x9041FFF8); // stw R2, -8(R1)
	if (ret != ERROR_OK)
		return ret;
	ret = write_gpr_reg(target, 2, MAGIC_RANDOM_VALUE_2);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x9041FFFC); // stw R2, -4(R1)
	if (ret != ERROR_OK)
		return ret;

	// read back the magic values
	ret = stuff_code(target, 0x8041FFF8); // lwz R2, -8(R1)
	if (ret != ERROR_OK)
		return ret;
	ret  = read_gpr_reg(target, 2, &value_1);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x8041FFFC); // lwz R2, -4(R1)
	if (ret != ERROR_OK)
		return ret;
	ret  = read_gpr_reg(target, 2, &value_2);
	if (ret != ERROR_OK)
		return ret;

	// restore R2 // ??? change to R31
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	// check the magic values
	if ((value_1 != MAGIC_RANDOM_VALUE_1) && (value_2 != MAGIC_RANDOM_VALUE_2))
		return ERROR_FAIL;

	return ERROR_OK;
}

static int read_required_gen_regs(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct reg *reg;
	int i;
	bool R31_used = false;
	bool LR_used = false;
	uint32_t value;
	int ret;

	for (i = 0; i < GPR_REG_COUNT; ++i)
	{
		reg = ppc476fs->gpr_regs[i];
		if (!reg->valid) {
			ret = read_gpr_reg(target, i, reg->value);
			if (ret != ERROR_OK)
				return ret;
			reg->valid = true;
			reg->dirty = false;
			if (i == 1) // ???
				ppc476fs->saved_R1 = get_reg_value_32(reg);
			else if (i == 2)
				ppc476fs->saved_R2 = get_reg_value_32(reg);
			else if (i == 31)
				ppc476fs->saved_R31 = get_reg_value_32(reg);
		}
	}

	if (!ppc476fs->LR_reg->valid) {
		R31_used = true;
		ret = read_spr_reg(target, SPR_REG_NUM_LR, ppc476fs->LR_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->LR_reg->valid = true;
		ppc476fs->LR_reg->dirty = false;
		ppc476fs->saved_LR = get_reg_value_32(ppc476fs->LR_reg);
	}

	if (!ppc476fs->CTR_reg->valid) {
		R31_used = true;
		ret = read_spr_reg(target, SPR_REG_NUM_CTR, ppc476fs->CTR_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->CTR_reg->valid = true;
		ppc476fs->CTR_reg->dirty = false;
	}

	if (!ppc476fs->XER_reg->valid) {
		R31_used = true;
		ret = read_spr_reg(target, SPR_REG_NUM_XER, ppc476fs->XER_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->XER_reg->valid = true;
		ppc476fs->XER_reg->dirty = false;
	}

	if (!ppc476fs->MSR_reg->valid) {
		R31_used = true;
		ret = stuff_code(target, 0x7FE000A6); // mfmsr R31
		if (ret != ERROR_OK)
			return ret;
		ret = read_gpr_reg(target, 31, ppc476fs->MSR_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->MSR_reg->valid = true;
		ppc476fs->MSR_reg->dirty = false;
	}

	if (!ppc476fs->CR_reg->valid) {
		R31_used = true;
		ret = stuff_code(target, 0x7FE00026); // mfcr R31
		if (ret != ERROR_OK)
			return ret;
		ret = read_gpr_reg(target, 31, ppc476fs->CR_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->CR_reg->valid = true;
		ppc476fs->CR_reg->dirty = false;
	}

	if (!ppc476fs->PC_reg->valid) {
		R31_used = true;
		LR_used = true;
		ret = stuff_code(target, 0x48000001); // bl $+0
		if (ret != ERROR_OK)
			return ret;
		ret = read_spr_reg(target, SPR_REG_NUM_LR, &value);
		set_reg_value_32(ppc476fs->PC_reg, value - 4);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->PC_reg->valid = true;
		ppc476fs->PC_reg->dirty = false;
	}

	// restore LR
	if (LR_used) {
		R31_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_LR, ppc476fs->saved_LR);
		if (ret != ERROR_OK)
			return ret;
	}

	// restore R31
	if (R31_used) {
		ret = write_gpr_reg(target, 31, ppc476fs->saved_R31);
		if (ret != ERROR_OK)
			return ret;
	}

	return ERROR_OK;
}

static int read_required_fpu_regs(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct reg *reg;
	int i;
	uint32_t value_1;
	uint32_t value_2;
	uint32_t code;
	bool F0_used = false;
	bool read_need;
	int ret;

	read_need = false;
	for (i = 0; i < FPR_REG_COUNT; ++i) {
		if (!ppc476fs->fpr_regs[i]->valid) {
			read_need = true;
			break;
		}
	}
	read_need = read_need || !ppc476fs->FPSCR_reg->valid;
	if (!read_need)
		return ERROR_OK;

	if ((get_reg_value_32(ppc476fs->MSR_reg) & MSR_FP_MASK) == 0) {
		// FPU is disabled, so set all non-valid FPU register to zeros
		for (i = 0; i < FPR_REG_COUNT; ++i) {
			reg = ppc476fs->fpr_regs[i];
			if (!reg->valid) {
				memset(reg->value, 0, 8);
				reg->valid = true;
				reg->dirty = false;
			}
		}
		if (!ppc476fs->FPSCR_reg->valid) {
			set_reg_value_32(ppc476fs->FPSCR_reg, 0);
			ppc476fs->FPSCR_reg->valid = true;
			ppc476fs->FPSCR_reg->dirty = false;
		}
		return ERROR_OK;
	}

	ret = test_memory_at_stack(target);
	if (ret != ERROR_OK)
		return ret;

	for (i = 0; i < FPR_REG_COUNT; ++i) {
		reg = ppc476fs->fpr_regs[i];
		if (!reg->valid) {
			code = 0xD801FFF8 | (i << 21); // stfd Fx, -8(r1)
			ret = stuff_code(target, code);
			if (ret != ERROR_OK)
				return ret;
			ret = stuff_code(target, 0x8041FFF8); // lwz R2, -8(R1)
			if (ret != ERROR_OK)
				return ret;
			ret  = read_gpr_reg(target, 2, &value_1);
			if (ret != ERROR_OK)
				return ret;
			ret = stuff_code(target, 0x8041FFFC); // lwz R2, -4(R1)
			if (ret != ERROR_OK)
				return ret;
			ret  = read_gpr_reg(target, 2, &value_2);
			if (ret != ERROR_OK)
				return ret;
			memcpy(reg->value, &value_1, 4);
			memcpy(reg->value + 4, &value_2, 4);
			reg->valid = true;
			reg->dirty = false;
			if (i == 0)
				ppc476fs->saved_F0 = *((uint64_t*)reg->value); // ???
		}
	}

	if (!ppc476fs->FPSCR_reg->valid) {
		F0_used = true;
		ret = stuff_code(target, 0xFC00048E); // mffs F0
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0xD801FFF8); // stfd F0, -8(r1)
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x8041FFFC); // lwz R2, -4(R1)
		if (ret != ERROR_OK)
			return ret;
		ret  = read_gpr_reg(target, 2, &value_1);
		if (ret != ERROR_OK)
			return ret;
		set_reg_value_32(ppc476fs->FPSCR_reg, value_1);
		ppc476fs->FPSCR_reg->valid = true;
		ppc476fs->FPSCR_reg->dirty = false;
	}

	// restore F0 ??? ->func
	if (F0_used) {
		memcpy(&value_1, (uint8_t*)&ppc476fs->saved_F0 + 0, 4); // ??
		memcpy(&value_2, (uint8_t*)&ppc476fs->saved_F0 + 4, 4);
		ret = write_gpr_reg(target, 2, value_1);
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x9041FFF8); // stw R2, -8(R1)
		if (ret != ERROR_OK)
			return ret;
		ret = write_gpr_reg(target, 2, value_2);
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x9041FFFC); // stw R2, -4(R1)
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0xC801FFF8); // lfd F0, -8(R1)
		if (ret != ERROR_OK)
			return ret;
	}

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

int write_dirty_gen_regs(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct reg *reg;
	bool R31_used = false;
	bool LR_used = false;
	int i;
	int ret;

	if (ppc476fs->PC_reg->dirty) {
		R31_used = true;
		LR_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_LR, get_reg_value_32(ppc476fs->PC_reg));
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x4E800020); // blr
		if (ret != ERROR_OK)
			return ret;
	 	ppc476fs->PC_reg->dirty = false;
	}

	if (ppc476fs->CR_reg->dirty) {
		R31_used = true;
		ret = write_gpr_reg(target, 31, get_reg_value_32(ppc476fs->CR_reg));
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x7FEFF120); // mtcr R31
		if (ret != ERROR_OK)
			return ret;
	 	ppc476fs->CR_reg->dirty = false;
	}

	if (ppc476fs->MSR_reg->dirty) {
		R31_used = true;
		ret = write_gpr_reg(target, 31, get_reg_value_32(ppc476fs->MSR_reg));
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x7FE00124); // mtmsr R31
		if (ret != ERROR_OK)
			return ret;
	 	ppc476fs->MSR_reg->dirty = false;
	}

	if (ppc476fs->XER_reg->dirty) {
		R31_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_XER, get_reg_value_32(ppc476fs->XER_reg));
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->XER_reg->dirty = false;
	}

	if (ppc476fs->CTR_reg->dirty) {
		R31_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_CTR, get_reg_value_32(ppc476fs->CTR_reg));
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->CTR_reg->dirty = false;
	}

	if (ppc476fs->LR_reg->dirty) {
		R31_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_LR, get_reg_value_32(ppc476fs->LR_reg));
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->LR_reg->dirty = false;
		ppc476fs->saved_LR = get_reg_value_32(ppc476fs->LR_reg);
		LR_used = false;
	}

	if (LR_used) {
		R31_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_LR, ppc476fs->saved_LR);
		if (ret != ERROR_OK)
			return ret;
	}

	for (i = 0; i < GPR_REG_COUNT; ++i)
	{
		reg = ppc476fs->gpr_regs[i];
		if (reg->dirty) {
			ret = write_gpr_reg(target, i, get_reg_value_32(reg));
			if (ret != ERROR_OK)
				return ret;
			reg->dirty = false;
			if (i == 1) // ???
				ppc476fs->saved_R1 = get_reg_value_32(reg);
			else if (i == 2)
				ppc476fs->saved_R2 = get_reg_value_32(reg);
			else if (i == 31) {
				ppc476fs->saved_R31 = get_reg_value_32(reg);
				R31_used = false;
			}
		}
	}

	if (R31_used) {
		ret = write_gpr_reg(target, i, ppc476fs->saved_R31);
		if (ret != ERROR_OK)
			return ret;
	}

	return ERROR_OK;
}

int write_dirty_fpu_regs(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct reg *reg;
	uint32_t value_1;
	uint32_t value_2;
	uint32_t code;
	bool write_need = false;
	bool F0_used = false;
	int i;
	int ret;

	for (i = 0; i < FPR_REG_COUNT; ++i) {
		if (ppc476fs->fpr_regs[i]->dirty) {
			write_need = true;
			break;
		}
	}
	write_need = write_need || ppc476fs->FPSCR_reg->dirty;
	if (!write_need)
		return ERROR_OK;

	assert((get_reg_value_32(ppc476fs->MSR_reg) & MSR_FP_MASK) != 0); // ???

	ret = test_memory_at_stack(target);
	if (ret != ERROR_OK)
		return ret;

	if (ppc476fs->FPSCR_reg->dirty) {
		F0_used = true;
		/* ??? if (!ppc476fs->fpr_regs[0]->valid) {
			// read F0 if it has not read yet
			ret = stuff_code(target, 0xD801FFF8); // stfd F0, -8(r1)
			if (ret != ERROR_OK)
				return ret;
			ret = stuff_code(target, 0x8041FFF8); // lwz R2, -8(R1)
			if (ret != ERROR_OK)
				return ret;
			ret  = read_gpr_reg(target, 2, &value_1);
			if (ret != ERROR_OK)
				return ret;
			ret = stuff_code(target, 0x8041FFFC); // lwz R2, -4(R1)
			if (ret != ERROR_OK)
				return ret;
			ret  = read_gpr_reg(target, 2, &value_2);
			if (ret != ERROR_OK)
				return ret;
			memcpy(ppc476fs->fpr_regs[0]->value, &value_1, 4);
			memcpy(ppc476fs->fpr_regs[0]->value + 4, &value_2, 4);
			ppc476fs->fpr_regs[0]->valid = true;
		}*/
		// ??? ppc476fs->fpr_regs[0]->dirty = true; // F0 will be restored by original value late
		ret = write_gpr_reg(target, 2, get_reg_value_32(ppc476fs->FPSCR_reg));
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x9041FFFC); // stw R2, -4(R1)
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0xC801FFF8); // lfd F0, -8(R1)
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0xFDFE058E); // mtfsf 255, F0
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->FPSCR_reg->dirty = false;
	}

	for (i = 0; i < FPR_REG_COUNT; ++i) {
		reg = ppc476fs->fpr_regs[i];
		if (reg->dirty) {
			memcpy(&value_1, reg->value, 4);
			memcpy(&value_2, reg->value + 4, 4);
			ret = write_gpr_reg(target, 2, value_1);
			if (ret != ERROR_OK)
				return ret;
			ret = stuff_code(target, 0x9041FFF8); // stw R2, -8(R1)
			if (ret != ERROR_OK)
				return ret;
			ret = write_gpr_reg(target, 2, value_2);
			if (ret != ERROR_OK)
				return ret;
			ret = stuff_code(target, 0x9041FFFC); // stw R2, -4(R1)
			if (ret != ERROR_OK)
				return ret;
			code = 0xC801FFF8 | (i << 21); // lfd Fx, -8(R1)
			ret = stuff_code(target, code);
			if (ret != ERROR_OK)
				return ret;
			reg->dirty = false;
			if (i == 0) {
				ppc476fs->saved_F0 = *((uint64_t*)reg->value); // ???
				F0_used = false;
			}
		}
	}

	// restore F0 ??? ->func
	if (F0_used) {
		memcpy(&value_1, (uint8_t*)&ppc476fs->saved_F0 + 0, 4); // ???
		memcpy(&value_2, (uint8_t*)&ppc476fs->saved_F0 + 4, 4);
		ret = write_gpr_reg(target, 2, value_1);
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x9041FFF8); // stw R2, -8(R1)
		if (ret != ERROR_OK)
			return ret;
		ret = write_gpr_reg(target, 2, value_2);
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x9041FFFC); // stw R2, -4(R1)
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0xC801FFF8); // lfd F0, -8(R1)
		if (ret != ERROR_OK)
			return ret;
	}

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static void regs_status_invalidate(struct target *target)
{
	struct reg_cache *cache = target->reg_cache;

	while (cache != NULL) {
		register_cache_invalidate(cache);
		cache = cache->next;
	}
}

// the function uses R31 register and does not restore one
static int write_DBCR0(struct target *target, uint32_t data)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;

	ret = write_spr_reg(target, SPR_REG_NUM_DBCR0, data);
	if (ret != ERROR_OK)
		return ret;

	ppc476fs->DBCR0_value = data;

	return ERROR_OK;
}

static int clear_DBSR(struct target *target)
{
	return write_JDCR(target, JDCR_STO_MASK | JDCR_RSDBSR_MASK);
}

static int ppc476fs_get_gen_reg(struct reg *reg)
{
	struct target *target = reg->arch_info;

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	reg->valid = false;
	reg->dirty = false;

	return read_required_gen_regs(target);
}

static int ppc476fs_set_gen_reg(struct reg *reg, uint8_t *buf)
{
	struct target *target = reg->arch_info;
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	uint32_t MSR_prev_value = get_reg_value_32(ppc476fs->MSR_reg);
	uint32_t MSR_new_value;
	size_t i;
	int ret;	

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (reg == ppc476fs->MSR_reg) {
		MSR_new_value = buf_get_u32(buf, 0, 31);
		if (((MSR_prev_value ^ MSR_new_value) & MSR_FP_MASK) != 0) {
			ret = write_dirty_fpu_regs(target);
			if (ret != ERROR_OK)
				return ret;
			// write MSR to the CPU
			ret = write_gpr_reg(target, 31, MSR_new_value);
			if (ret != ERROR_OK)
				return ret;
			ret = stuff_code(target, 0x7FE00124); // mtmsr R31
			if (ret != ERROR_OK)
				return ret;
			ret = write_gpr_reg(target, 31, ppc476fs->saved_R31); // restore R31
			if (ret != ERROR_OK)
				return ret;
			// invalidate FPU registers
			for (i = 0; i < FPR_REG_COUNT; ++i) {
				ppc476fs->fpr_regs[i]->valid = false;
				ppc476fs->fpr_regs[i]->dirty = false;
			}
			ppc476fs->FPSCR_reg->valid = false;
			ppc476fs->FPSCR_reg->dirty = false;
			// set MSR register status
			buf_cpy(buf, reg->value, reg->size);
			reg->valid = true;
			reg->dirty = false;
			return ERROR_OK;
		}
	}

	buf_cpy(buf, reg->value, reg->size);
	reg->valid = true;
	reg->dirty = true;

	return ERROR_OK;
}

static int ppc476fs_get_fpu_reg(struct reg *reg)
{
	struct target *target = reg->arch_info;

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	reg->valid = false;
	reg->dirty = false;

	return read_required_fpu_regs(target);
}

static int ppc476fs_set_fpu_reg(struct reg *reg, uint8_t *buf)
{
	struct target *target = reg->arch_info;
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if ((get_reg_value_32(ppc476fs->MSR_reg) & MSR_FP_MASK) == 0)
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	buf_cpy(buf, reg->value, reg->size);
	reg->dirty = true;
	reg->valid = true;

	return ERROR_OK;
}

static struct reg *fill_reg(
	struct target *target,
	int all_index,
	struct reg *reg,
	const char *reg_name,
	enum reg_type reg_type,
	int bit_size,
	const struct reg_arch_type *arch_type,
	const char *feature_name)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	size_t storage_size;

	ppc476fs->all_regs[all_index] = reg;

	reg->name = reg_name;
	reg->number = all_index;
	reg->feature = calloc(1, sizeof(struct reg_feature));
	reg->feature->name = feature_name;
	reg->caller_save = true; // gdb defaults to true
	reg->exist = true;
	storage_size = DIV_ROUND_UP(bit_size, 8);
	if (storage_size < 4)
		storage_size = 4;
	reg->value = calloc(1, storage_size);
	reg->size = bit_size;
	reg->reg_data_type = calloc(1, sizeof(struct reg_data_type));
	reg->reg_data_type->type = reg_type;
	reg->arch_info = target;
	reg->type = arch_type;

	return reg;
}

static void build_reg_caches(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct reg_cache *gen_cache = calloc(1, sizeof(struct reg_cache));
	struct reg_cache *fpu_cache = calloc(1, sizeof(struct reg_cache));
	int all_index = 0;
	struct reg *gen_regs;
	struct reg *fpu_regs;
	char reg_name[64];
	int i;

	gen_cache->name = "PowerPC General Purpose Registers";
	gen_cache->num_regs = GEN_CACHE_REG_COUNT;
	gen_cache->reg_list = calloc(GEN_CACHE_REG_COUNT, sizeof(struct reg));
	gen_cache->next = fpu_cache;

	fpu_cache->name = "PowerPC Float Point Purpose Registers";
	fpu_cache->num_regs = FPU_CACHE_REG_COUNT;
	fpu_cache->reg_list = calloc(FPU_CACHE_REG_COUNT, sizeof(struct reg));
	assert(fpu_cache->next == NULL);

	gen_regs = gen_cache->reg_list;
	fpu_regs = fpu_cache->reg_list;

	for (i = 0; i < GPR_REG_COUNT; ++i) {
		sprintf(reg_name, "R%i", i);
		ppc476fs->gpr_regs[i] = fill_reg(target, all_index++, gen_regs++, strdup(reg_name), REG_TYPE_UINT32, 32, &ppc476fs_gen_reg_type, "org.gnu.gdb.power.core"); // R0-R31
	}

	for (i = 0; i < FPR_REG_COUNT; ++i) {
		sprintf(reg_name, "F%i", i);
		ppc476fs->fpr_regs[i] = fill_reg(target, all_index++, fpu_regs++, strdup(reg_name), REG_TYPE_IEEE_DOUBLE, 64, &ppc476fs_fpu_reg_type, "org.gnu.gdb.power.fpu"); // F0-R31
	}

	ppc476fs->PC_reg = fill_reg(target, all_index++, gen_regs++, "PC", REG_TYPE_CODE_PTR, 32, &ppc476fs_gen_reg_type, "org.gnu.gdb.power.core");
	ppc476fs->MSR_reg = fill_reg(target, all_index++, gen_regs++, "MSR", REG_TYPE_UINT32, 32, &ppc476fs_gen_reg_type, "org.gnu.gdb.power.core");
	ppc476fs->CR_reg = fill_reg(target, all_index++, gen_regs++, "CR", REG_TYPE_UINT32, 32, &ppc476fs_gen_reg_type, "org.gnu.gdb.power.core");
	ppc476fs->LR_reg = fill_reg(target, all_index++, gen_regs++, "LR", REG_TYPE_CODE_PTR, 32, &ppc476fs_gen_reg_type, "org.gnu.gdb.power.core");
	ppc476fs->CTR_reg = fill_reg(target, all_index++, gen_regs++, "CTR", REG_TYPE_UINT32, 32, &ppc476fs_gen_reg_type, "org.gnu.gdb.power.core");
	ppc476fs->XER_reg = fill_reg(target, all_index++, gen_regs++, "XER", REG_TYPE_UINT32, 32, &ppc476fs_gen_reg_type, "org.gnu.gdb.power.core");
	ppc476fs->FPSCR_reg = fill_reg(target, all_index++, fpu_regs++, "FPSCR", REG_TYPE_UINT32, 32, &ppc476fs_fpu_reg_type, "org.gnu.gdb.power.fpu");

	assert(all_index == ALL_REG_COUNT);
	assert(gen_regs - gen_cache->reg_list == GEN_CACHE_REG_COUNT);
	assert(fpu_regs - fpu_cache->reg_list == FPU_CACHE_REG_COUNT);

	target->reg_cache = gen_cache;
}

static int unset_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;
	uint32_t iac_mask;

	assert(breakpoint->set != 0);

	iac_mask = (DBCR0_IAC1_MASK >> breakpoint->linked_BRP);
	ret = write_DBCR0(target, ppc476fs->DBCR0_value & ~iac_mask);
	if (ret != ERROR_OK)
		return ret;

	// restore R31
	ret = write_gpr_reg(target, 31, ppc476fs->saved_R31);
	if (ret != ERROR_OK)
		return ret;

	breakpoint->set = 0;

	return ERROR_OK;
}

// the function uses R31 register and does not restore one
static int set_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;
	int iac_index = 0;
	uint32_t iac_mask;

	assert(breakpoint->set == 0);

	while (true) {
		iac_mask = (DBCR0_IAC1_MASK >> iac_index);
		if ((ppc476fs->DBCR0_value & iac_mask) == 0)
			break;
		++iac_index;
	}
	assert(iac_index < 4);

	breakpoint->linked_BRP = iac_index;

	ret = write_spr_reg(target, SPR_REG_NUM_IAC_BASE + iac_index, (uint32_t)breakpoint->address);
	if (ret != ERROR_OK)
		return ret;	
	ret = write_DBCR0(target, ppc476fs->DBCR0_value | iac_mask);
	if (ret != ERROR_OK)
		return ret;

	breakpoint->set = 1;

	return ERROR_OK;
}

static int enable_breakpoints(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct breakpoint *bp = target->breakpoints;
	int ret;

	while (bp != NULL) {
		if (bp->set == 0) {
			ret = set_breakpoint(target, bp);
			if (ret != ERROR_OK)
				return ret;
		}
		bp = bp->next;
	}

	// restore R31
	ret = write_gpr_reg(target, 31, ppc476fs->saved_R31);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static void break_points_invalidate(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct breakpoint *bp = target->breakpoints;

	ppc476fs->DBCR0_value &= ~DBCR0_IACX_MASK;

	while (bp != NULL) {
		bp->set = 0;
		bp = bp->next;
	}
}

static int save_state(struct target *target)
{
	int ret;

	regs_status_invalidate(target);

	ret = read_required_gen_regs(target);
	if (ret != ERROR_OK)
		return ret;

	ret = read_required_fpu_regs(target);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int restore_state(struct target *target)
{
	int ret = write_dirty_fpu_regs(target);
	if (ret != ERROR_OK)
		return ret;

	ret = write_dirty_gen_regs(target);
	if (ret != ERROR_OK)
		return ret;

	ret = enable_breakpoints(target);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

// ??? optimize
static int restore_state_before_run(struct target *target, int current, target_addr_t address, enum target_debug_reason  debug_reason)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	// current = 1: continue on current pc, otherwise continue at <address>
	if (!current) {
		set_reg_value_32(ppc476fs->PC_reg, (uint32_t)address);
		ppc476fs->PC_reg->valid = true;
		ppc476fs->PC_reg->dirty = true;
	}

	ret = restore_state(target);
	if (ret != ERROR_OK)
		return ret;

	target->debug_reason = debug_reason;

	regs_status_invalidate(target);

	return ERROR_OK;
}

// ???
static int ppc476fs_poll(struct target *target);
static int ppc476fs_halt(struct target *target);

// ??? 
static int to_halt_state(struct target *target)
{
	int ret = ppc476fs_poll(target);
	if (ret != ERROR_OK)
		return ret;

	if (target->state == TARGET_HALTED)
		return ERROR_OK;

	ret = ppc476fs_halt(target);
	if (ret != ERROR_OK)
		return ret;

	ret = ppc476fs_poll(target);
	if (ret != ERROR_OK)
		return ret;
	
	if (target->state != TARGET_HALTED)
		return ERROR_FAIL;

	return ERROR_OK;
}

static int examine_internal(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	uint32_t JDSR_value;
	bool is_running;
	int ret;

	ret = read_JDSR(target, &JDSR_value); // supposedly can return a wrong result
	if (ret != ERROR_OK)
		return ret;
	ret = read_JDSR(target, &JDSR_value); // repeat reading
	if (ret != ERROR_OK)
		return ret;

	is_running = ((JDSR_value & JDSR_PSP_MASK) == 0);

	// stop the target if it is running
	if (is_running) {
		ret = write_JDCR(target, JDCR_STO_MASK);
		if (ret != ERROR_OK)
			return ret;
	}

	ret = save_state(target);
	if (ret != ERROR_OK)
		return ret;

	ret = write_DBCR0(target, DBCR0_EDM_MASK | DBCR0_FT_MASK);
	if (ret != ERROR_OK)
		return ret;
	break_points_invalidate(target);

	ret = write_spr_reg(target, SPR_REG_NUM_DBCR1, 0);
	if (ret != ERROR_OK)
		return ret;
	ret = write_spr_reg(target, SPR_REG_NUM_DBCR2, 0);
	if (ret != ERROR_OK)
		return ret;

	// restore R31
	ret = write_gpr_reg(target, 31, ppc476fs->saved_R31);
	if (ret != ERROR_OK)
		return ret;

	ret = clear_DBSR(target);
	if (ret != ERROR_OK)
		return ret;

	// run the target if it was ranning before
	if (is_running) {
		ret = write_JDCR(target, 0);
		if (ret != ERROR_OK)
			return ret;
	}

	return ERROR_OK;
}

static int ppc476fs_poll(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	enum target_state prev_state = target->state;
	uint32_t JDSR_value, DBSR_value;
	int ret;

	ret = read_JDSR(target, &JDSR_value);
	if (ret != ERROR_OK) {
		target->state = TARGET_UNKNOWN;
		return ret;
	}

	if ((JDSR_value & JDSR_PSP_MASK) != 0)
		target->state = TARGET_HALTED;
	else
		target->state = TARGET_RUNNING;

	if ((prev_state != TARGET_HALTED) && (target->state == TARGET_HALTED)) {
		ret = save_state(target);
		if (ret != ERROR_OK)
			return ret;

		ret = read_spr_reg(target, SPR_REG_NUM_DBSR, &DBSR_value);
		if (ret != ERROR_OK)
			return ret;

		// restore R31
		if (!ppc476fs->gpr_regs[31]->dirty) {
			ret = write_gpr_reg(target, 31, get_reg_value_32(ppc476fs->gpr_regs[31]));
			if (ret != ERROR_OK)
				return ret;
		}

		if (DBSR_value != 0) {
			if ((DBSR_value & DBSR_IAC_ALL_MASK) != 0)
				target->debug_reason = DBG_REASON_BREAKPOINT;
			else if ((DBSR_value & DBSR_DAC_ALL_MASK) != 0)
				target->debug_reason = DBG_REASON_WATCHPOINT;
			ret = clear_DBSR(target);
			if (ret != ERROR_OK)
				return ret;
		}

		if (prev_state == TARGET_DEBUG_RUNNING)
			target_call_event_callbacks(target, TARGET_EVENT_DEBUG_HALTED);
		else
			target_call_event_callbacks(target, TARGET_EVENT_HALTED);
	}

	return ERROR_OK;
}

// call only then the target is halted
int ppc476fs_arch_state(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);

	LOG_USER("target halted due to %s, CoreID: %i, PC: 0x%08X",
		debug_reason_name(target),
		target->coreid,
		get_reg_value_32(ppc476fs->PC_reg));

	return ERROR_OK;
}

static int ppc476fs_halt(struct target *target)
{
	int ret;

	if (target->state == TARGET_HALTED) {
		LOG_WARNING("target was already halted");
		return ERROR_TARGET_NOT_RUNNING;
	}

	if (target->state == TARGET_UNKNOWN)
		LOG_WARNING("target was in unknown state when halt was requested");

	ret = write_JDCR(target, JDCR_STO_MASK);
	if (ret != ERROR_OK)
		return ret;

	target->debug_reason = DBG_REASON_DBGRQ;

	return ERROR_OK;
}

static int ppc476fs_resume(struct target *target, int current, target_addr_t address, int handle_breakpoints, int debug_execution)
{
	int ret = restore_state_before_run(target, current, address, DBG_REASON_NOTHALTED);
	if (ret != ERROR_OK)
		return ret;

	ret = write_JDCR(target, 0);
	if (ret != ERROR_OK)
		return ret;

	if (debug_execution) {
		target->state = TARGET_DEBUG_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
	}
	else {
		target->state = TARGET_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
	}

	return ERROR_OK;
}

static int ppc476fs_step(struct target *target, int current, target_addr_t address, int handle_breakpoints)
{
	int ret = restore_state_before_run(target, current, address, DBG_REASON_SINGLESTEP);
	if (ret != ERROR_OK)
		return ret;

	ret = write_JDCR(target, JDCR_STO_MASK | JDCR_SS_MASK);
	if (ret != ERROR_OK)
		return ret;

	target->state = TARGET_RUNNING;
   	target_call_event_callbacks(target, TARGET_EVENT_RESUMED);

	return ERROR_OK;
}

static int ppc476fs_assert_reset(struct target *target)
{
	if (target->reset_halt) {
		LOG_ERROR("Device does not support 'reset halt' command");
		return ERROR_FAIL;
	}

	return ERROR_OK;
}

static int ppc476fs_deassert_reset(struct target *target)
{
	int ret;

	target->state = TARGET_RESET;
	regs_status_invalidate(target);
	break_points_invalidate(target);

	ret = write_JDCR(target, JDCR_RESET_MASK);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int ppc476fs_soft_reset_halt(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	uint32_t value_JDSR;
	int i;
	int ret;
	
	target->state = TARGET_RESET;
	regs_status_invalidate(target);
	break_points_invalidate(target);

	ret = write_JDCR(target, JDCR_RESET_MASK);
	if (ret != ERROR_OK)
		return ret;

	for (i = 0; i < 100; ++i) {
		ret = write_JDCR(target, JDCR_STO_MASK);
		if (ret != ERROR_OK)
			return ret;

		ret = read_JDSR(target, &value_JDSR);
		if (ret != ERROR_OK)
			return ret;

		if ((value_JDSR & JDSR_PSP_MASK) != 0)
			break;
	}

	if ((value_JDSR & JDSR_PSP_MASK) == 0)
		return ERROR_FAIL;

	ret = save_state(target);
	if (ret != ERROR_OK)
		return ret;

	// restore a register state after the reset
	set_reg_value_32(ppc476fs->PC_reg, 0xFFFFFFC);
	ppc476fs->PC_reg->dirty = true;
	set_reg_value_32(ppc476fs->MSR_reg, 0);
	ppc476fs->MSR_reg->dirty = true;
	// [***] other register must be restored - otherwise the soft reset does not work

	ret = write_DBCR0(target, DBCR0_EDM_MASK | DBCR0_FT_MASK);
	if (ret != ERROR_OK)
		return ret;
	ret = write_spr_reg(target, SPR_REG_NUM_DBCR1, 0);
	if (ret != ERROR_OK)
		return ret;
	ret = write_spr_reg(target, SPR_REG_NUM_DBCR2, 0);
	if (ret != ERROR_OK)
		return ret;

	// restore R31
	ret = write_gpr_reg(target, 31, ppc476fs->saved_R31);
	if (ret != ERROR_OK)
		return ret;

	ret = clear_DBSR(target);
	if (ret != ERROR_OK)
		return ret;

	ret = restore_state(target);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int ppc476fs_get_gdb_reg_list(struct target *target, struct reg **reg_list[], int *reg_list_size, enum target_register_class reg_class)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target); 

	*reg_list_size = GDB_REG_COUNT;
	*reg_list = malloc(sizeof(struct reg *) * GDB_REG_COUNT);
	memcpy(*reg_list, ppc476fs->all_regs, sizeof(struct reg *) * GDB_REG_COUNT);

	return ERROR_OK;
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG communication BUG
static int ppc476fs_read_memory(struct target *target, target_addr_t address, uint32_t size, uint32_t count, uint8_t *buffer)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	uint32_t code;
	uint32_t shift;
	uint32_t i;
	uint32_t j;
	uint32_t value;
	int ret;

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3)) || ((size == 2) && (address & 0x1)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	memset(buffer, 0, size * count); // clear result buffer

	switch (size)
	{
	case 1:
		code = 0x88010000; // lbz %R0, 0(%R1)
		shift = 24;
		break;
	case 2:
		code = 0xA0010000; // lhz %R0, 0(%R1)
		shift = 16;
		break;
	case 4:
		code = 0x80010000; // lwz %R0, 0(%R1)
		shift = 0;
		break;
	default:
		assert(false);
	}

	for (i = 0; i < count; ++i) {
		ret = write_gpr_reg(target, 1, (uint32_t)address);
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			return ret;
		ret = read_gpr_reg(target, 0, &value);
		if (ret != ERROR_OK)
			return ret;
		value <<= shift;
		for (j = 0; j < size; ++j)
		{
			*(buffer++) = (value >> 24);
			value <<= 8;
		}
		address += size;
	}

	// restore R1 ???? !!!!
	if (!ppc476fs->gpr_regs[1]->dirty) {
		ret = write_gpr_reg(target, 1, get_reg_value_32(ppc476fs->gpr_regs[1]));
		if (ret != ERROR_OK)
			return ret;
	}

	// restore R0 ???? !!!!
	if (!ppc476fs->gpr_regs[0]->dirty) {
		ret = write_gpr_reg(target, 0, get_reg_value_32(ppc476fs->gpr_regs[0]));
		if (ret != ERROR_OK)
			return ret;
	}

	return ERROR_OK;
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG communication BUG
static int ppc476fs_write_memory(struct target *target, target_addr_t address, uint32_t size, uint32_t count, const uint8_t *buffer)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	uint32_t code;
	uint32_t i;
	uint32_t j;
	uint32_t value;
	int ret;

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	switch (size)
	{
	case 1:
		code = 0x98010000; // stb %R0, 0(%R1)
		break;
	case 2:
		code = 0xB0010000; // sth %R0, 0(%R1)
		break;
	case 4:
		code = 0x90010000; // stw %R0, 0(%R1)
		break;
	default:
		assert(false);
	}

	for (i = 0; i < count; ++i) {
		ret = write_gpr_reg(target, 1, (uint32_t)address);
		if (ret != ERROR_OK)
			return ret;
		value = 0;
		for (j = 0; j < size; ++j)
		{
			value <<= 8;
			value |= (uint32_t)*(buffer++);
		}
		ret = write_gpr_reg(target, 0, value);
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			return ret;
		address += size;
	}

	// restore R1 ???? !!!!
	if (!ppc476fs->gpr_regs[1]->dirty) {
		ret = write_gpr_reg(target, 1, get_reg_value_32(ppc476fs->gpr_regs[1]));
		if (ret != ERROR_OK)
			return ret;
	}

	// restore R0 ???? !!!!
	if (!ppc476fs->gpr_regs[0]->dirty) {
		ret = write_gpr_reg(target, 0, get_reg_value_32(ppc476fs->gpr_regs[0]));
		if (ret != ERROR_OK)
			return ret;
	}

	return ERROR_OK;	
}

static int ppc476fs_add_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct breakpoint *bp;
	int ret, bp_count;

	if (breakpoint->type != BKPT_HARD)
		return ERROR_TARGET_FAILURE; // only hardware points	
	if (breakpoint->length != 4)
		return ERROR_TARGET_UNALIGNED_ACCESS;

	bp = target->breakpoints;
	bp_count = 0;
	while (bp != NULL) {
		++bp_count;
		bp = bp->next;
	}
	if (bp_count == 4)
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	ret = to_halt_state(target); // ??? may be wrong code
	if (ret != ERROR_OK)
		return ret;

	breakpoint->set = 0;

	return ERROR_OK;
}

static int ppc476fs_remove_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	int ret;

	if (breakpoint->set == 0)
		return ERROR_OK;

	ret = to_halt_state(target); // ??? may be wrong code
	if (ret != ERROR_OK)
		return ret;

	return unset_breakpoint(target, breakpoint);
}

static int ppc476fs_add_watchpoint(struct target *target, struct watchpoint *watchpoint)
{
	return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
}

static int ppc476fs_remove_watchpoint(struct target *target, struct watchpoint *watchpoint)
{
	assert(false);

	return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
}

static int ppc476fs_target_create(struct target *target, Jim_Interp *interp)
{
	struct ppc476fs_common *ppc476fs = calloc(1, sizeof(struct ppc476fs_common));
	target->arch_info = ppc476fs;

	if ((target->coreid < 0) || (target->coreid > 1)) {
		LOG_ERROR("CoreID=%i is not allowed. It must be 0 or 1. It has been set to 0.", target->coreid);
		target->coreid = 0;
	}

	return ERROR_OK;
}

static int ppc476fs_init_target(struct command_context *cmd_ctx, struct target *target)
{
	build_reg_caches(target);

	return ERROR_OK;
}

static int ppc476fs_examine(struct target *target)
{
	int ret = examine_internal(target);
	if (ret != ERROR_OK) {
		LOG_ERROR("Device has not been examined (error code = %i)", ret);
		return ret;
	}

   	target_set_examined(target);

	return ERROR_OK;
}

COMMAND_HANDLER(ppc476fs_handle_status_command)
{
	struct target *target = get_current_target(CMD_CTX);
	uint32_t JDSR_value;
	int ret;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	ret = read_JDSR(target, &JDSR_value);
	if (ret != ERROR_OK) {
		command_print(CMD, "cannot read JDSR register");
		return ret;
	}

	command_print(CMD, "PowerPC JTAG status:");
	command_print(CMD, "  JDSR = 0x%08X", JDSR_value);

	return ERROR_OK;
}

COMMAND_HANDLER(ppc476fs_handle_jtag_speed_command)
{
	struct target *target = get_current_target(CMD_CTX);
	time_t current_time = time(NULL);
	uint32_t count = 0;
	uint32_t dummy_data;
	int ret;

	while (time(NULL) == current_time) ; // wait new second
	current_time = time(NULL);

	while (time(NULL) == current_time) {
		ret = read_DBDR(target, &dummy_data);
		if (ret != ERROR_OK) {
			command_print(CMD, "JTAG communication error");
			return ret;
		}
		++count;
	}

	command_print(CMD, "JTAG speed = %u (transaction per second)", count);

	return ERROR_OK;
}

static const struct command_registration ppc476fs_exec_command_handlers[] = {
	{
		.name = "status",
		.handler = ppc476fs_handle_status_command,
		.mode = COMMAND_EXEC,
		.usage = "status",
		.help = "display status"
	},
	{
		.name = "jtag_speed",
		.handler = ppc476fs_handle_jtag_speed_command,
		.mode = COMMAND_EXEC,
		.usage = "jtag_speed",
		.help = "display jtag speed (transaction per second)"
	},
	COMMAND_REGISTRATION_DONE
};

const struct command_registration ppc476fs_command_handlers[] = {
	{
		.name = "ppc476fs",
		.mode = COMMAND_ANY,
		.help = "ppc476fs command group",
		.usage = "",
		.chain = ppc476fs_exec_command_handlers
	},
	COMMAND_REGISTRATION_DONE
};

struct target_type ppc476fs_target = {
	.name = "ppc476fs",

	.poll = ppc476fs_poll,
	.arch_state = ppc476fs_arch_state,

	.halt = ppc476fs_halt,
	.resume = ppc476fs_resume,
	.step = ppc476fs_step,

	.assert_reset = ppc476fs_assert_reset,
	.deassert_reset = ppc476fs_deassert_reset,
	.soft_reset_halt = ppc476fs_soft_reset_halt,

	.get_gdb_reg_list = ppc476fs_get_gdb_reg_list,

	.read_memory = ppc476fs_read_memory,
	.write_memory = ppc476fs_write_memory,

	.add_breakpoint = ppc476fs_add_breakpoint,
	.remove_breakpoint = ppc476fs_remove_breakpoint,
	.add_watchpoint = ppc476fs_add_watchpoint,
	.remove_watchpoint = ppc476fs_remove_watchpoint,

	.commands = ppc476fs_command_handlers,
	.target_create = ppc476fs_target_create,
	.init_target = ppc476fs_init_target,
	.examine = ppc476fs_examine,
};
