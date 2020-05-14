#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/jtag.h>
#include <target/target.h>
#include <target/target_type.h>
#include <target/register.h>
#include <target/breakpoints.h>
#include <helper/log.h>
#include <helper/time_support.h>

// uncomment the lines below to see the debug messages without turning on a debug mode
/* #undef LOG_DEBUG
#define LOG_DEBUG(expr ...) \
	do { \
		printf("D:%i:%s: ", __LINE__, __func__); \
		printf(expr); \
		printf("\n"); \
	} while (0)*/

// jtag instruction codes without core ids
#define JTAG_INSTR_WRITE_JDCR_READ_JDSR 0x28 /* 0b0101000 */
#define JTAG_INSTR_WRITE_JISB_READ_JDSR 0x38 /* 0b0111000 */
#define JTAG_INSTR_WRITE_READ_DBDR 0x58 /* 0b1011000 */
#define JTAG_INSTR_CORE_RELOAD 0x78 /* 0b1111000, is used for preventing a JTAG bug with the core swintching */

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
#define SPR_REG_NUM_MMUCR 946

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

#define MMUCR_STID_MASK (0xFFFF << 0)

#define ALL_REG_COUNT 71
#define GDB_REG_COUNT 71 /* at start of all register array */
#define GEN_CACHE_REG_COUNT 38 /* R0-R31, PC, MSR, CR, LR, CTR, XER */
#define FPU_CACHE_REG_COUNT 33 /* F0-F31, FPSCR */
#define GPR_REG_COUNT 32
#define FPR_REG_COUNT 32

#define MAGIC_RANDOM_VALUE_1 0x396F965C
#define MAGIC_RANDOM_VALUE_2 0x44692D7E

#define ERROR_MEMORY_AT_STACK (-99)

#define TLB_NUMBER 1024

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
	uint32_t saved_R1;
	uint32_t saved_R2;
	uint32_t saved_LR;
	uint64_t saved_F0;
};

struct ppc476fs_tap_ext {
	int last_coreid; // -1 if the last core id is unknown
};

struct tlb_record {
	int index;
	int way;
	unsigned tid;
	uint32_t epn;
	int v;
	int ts;
	unsigned dsiz; // bit mask
	bool bolted;
	uint32_t erpn;
	uint32_t rpn;
	unsigned wimg;
	int en; // 0 - BE, 1 - LE
	int il1i;
	int il1d;
	unsigned u;
	unsigned uxwr;
	unsigned sxwr;
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
	0x5, 0x6
};

static inline struct ppc476fs_common *target_to_ppc476fs(struct target *target)
{
	return target->arch_info;
}

static inline struct ppc476fs_tap_ext *target_to_ppc476fs_tap_ext(struct target *target)
{
	return target->tap->priv;
}

static inline uint32_t get_reg_value_32(struct reg *reg) {
	return *((uint32_t*)reg->value);
}

static inline void set_reg_value_32(struct reg *reg, uint32_t value) {
	*((uint32_t*)reg->value) = value;
}

static int jtag_read_write_register(struct target *target, uint32_t instr_without_coreid, uint32_t valid_bit, uint32_t write_data, uint32_t *read_data)
{
	struct ppc476fs_tap_ext *tap_ext = target_to_ppc476fs_tap_ext(target);
	struct scan_field field;
	struct scan_field fields[2];
	uint8_t instr_buffer[4];
	uint8_t data_out_buffer[4];
	uint8_t data_in_buffer[4];
	uint8_t valid_buffer[4];
	int ret;

	// !!! IMPORTANT
	// prevent the JTAG core switching bug
	if (tap_ext->last_coreid != target->coreid) {
		buf_set_u32(instr_buffer, 0, target->tap->ir_length, JTAG_INSTR_CORE_RELOAD | coreid_mask[target->coreid]);
		field.num_bits = target->tap->ir_length;
		field.out_value = instr_buffer;
		field.in_value = NULL;
		jtag_add_ir_scan(target->tap, &field, TAP_IDLE);
		tap_ext->last_coreid = target->coreid;
	}

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
	ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_JDCR_READ_JDSR, 0, 0, NULL);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
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
	ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR, 0, 0, NULL);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
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
	ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_READ_DBDR, 0, 0, NULL);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
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
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

// the function uses R2 register and does not restore one
static int read_spr_reg(struct target *target, int spr_num, uint32_t *data)
{
	uint32_t code = 0x7C4002A6 | ((spr_num & 0x1F) << 16) | ((spr_num & 0x3E0) << (11 - 5)); // mfspr R2, spr
	int ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	ret = read_gpr_reg(target, 2, data);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

// the function uses R2 register and does not restore one
static int write_spr_reg(struct target *target, int spr_num, uint32_t data)
{
	uint32_t code;
	int ret = write_gpr_reg(target, 2, data);
	if (ret != ERROR_OK)
		return ret;

	code = 0x7C4003A6 | ((spr_num & 0x1F) << 16) | ((spr_num & 0x3E0) << (11 - 5)); // mtspr spr, R2
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

// the function uses R2 register and does not restore one
static int read_fpr_reg(struct target *target, int reg_num, uint64_t *value)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	uint32_t value_1;
	uint32_t value_2;
	uint32_t code;
	int ret;

	assert((get_reg_value_32(ppc476fs->MSR_reg) & MSR_FP_MASK) != 0);

	code = 0xD801FFF8 | (reg_num << 21); // stfd Fx, -8(r1)
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

	memcpy(((uint32_t*)value + 0), &value_1, 4);
	memcpy(((uint32_t*)value + 1), &value_2, 4);

	return ERROR_OK;
}

// the function uses R2 register and does not restore one
static int write_fpr_reg(struct target *target, int reg_num, uint64_t value)
{
	uint32_t value_1 = (uint32_t)(value >> 0);
	uint32_t value_2 = (uint32_t)(value >> 32);
	uint32_t code;
	int ret;

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
	code = 0xC801FFF8 | (reg_num << 21); // lfd Fx, -8(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

// the function uses R2 register and does not restore one
static int test_memory_at_stack_internal(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	uint32_t value_1;
	uint32_t value_2;
	int ret;

	if ((ppc476fs->saved_R1 < 8) || ((ppc476fs->saved_R1 & 0x3) != 0)) // check the stack pointer
		return ERROR_MEMORY_AT_STACK;

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

	// check the magic values
	if ((value_1 != MAGIC_RANDOM_VALUE_1) && (value_2 != MAGIC_RANDOM_VALUE_2))
		return ERROR_MEMORY_AT_STACK;

	return ERROR_OK;
}

static int test_memory_at_stack(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret1;
	int ret2;

	ret1 = test_memory_at_stack_internal(target);

	// restore R2
	ret2 = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret2 != ERROR_OK)
		return ret2;

	return ret1;
}

static int read_required_gen_regs(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct reg *reg;
	int i;
	bool R2_used = false;
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
			if (i == 1)
				ppc476fs->saved_R1 = get_reg_value_32(reg);
			else if (i == 2)
				ppc476fs->saved_R2 = get_reg_value_32(reg);
		}
	}

	if (!ppc476fs->LR_reg->valid) {
		R2_used = true;
		ret = read_spr_reg(target, SPR_REG_NUM_LR, ppc476fs->LR_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->LR_reg->valid = true;
		ppc476fs->LR_reg->dirty = false;
		ppc476fs->saved_LR = get_reg_value_32(ppc476fs->LR_reg);
	}

	if (!ppc476fs->CTR_reg->valid) {
		R2_used = true;
		ret = read_spr_reg(target, SPR_REG_NUM_CTR, ppc476fs->CTR_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->CTR_reg->valid = true;
		ppc476fs->CTR_reg->dirty = false;
	}

	if (!ppc476fs->XER_reg->valid) {
		R2_used = true;
		ret = read_spr_reg(target, SPR_REG_NUM_XER, ppc476fs->XER_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->XER_reg->valid = true;
		ppc476fs->XER_reg->dirty = false;
	}

	if (!ppc476fs->MSR_reg->valid) {
		R2_used = true;
		ret = stuff_code(target, 0x7C4000A6); // mfmsr R2
		if (ret != ERROR_OK)
			return ret;
		ret = read_gpr_reg(target, 2, ppc476fs->MSR_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->MSR_reg->valid = true;
		ppc476fs->MSR_reg->dirty = false;
	}

	if (!ppc476fs->CR_reg->valid) {
		R2_used = true;
		ret = stuff_code(target, 0x7C400026); // mfcr R2
		if (ret != ERROR_OK)
			return ret;
		ret = read_gpr_reg(target, 2, ppc476fs->CR_reg->value);
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->CR_reg->valid = true;
		ppc476fs->CR_reg->dirty = false;
	}

	if (!ppc476fs->PC_reg->valid) {
		R2_used = true;
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

	// restore LR if it is needed
	if (LR_used) {
		R2_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_LR, ppc476fs->saved_LR);
		if (ret != ERROR_OK)
			return ret;
	}

	// restore R2 if it is needed
	if (R2_used) {
		ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
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
	bool F0_used = false;
	bool read_need;
	uint64_t value;
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
	if (ret == ERROR_MEMORY_AT_STACK) {
		LOG_WARNING("cannot read FPU registers because of the stark pointer, CoreID: %i", target->coreid);
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
	if (ret != ERROR_OK)
		return ret;

	for (i = 0; i < FPR_REG_COUNT; ++i) {
		reg = ppc476fs->fpr_regs[i];
		if (!reg->valid) {
			ret = read_fpr_reg(target, i, (uint64_t*)reg->value);
			if (ret != ERROR_OK)
				return ret;
			reg->valid = true;
			reg->dirty = false;
			if (i == 0)
				ppc476fs->saved_F0 = *((uint64_t*)reg->value);
		}
	}

	if (!ppc476fs->FPSCR_reg->valid) {
		F0_used = true;
		ret = stuff_code(target, 0xFC00048E); // mffs F0
		if (ret != ERROR_OK)
			return ret;
		ret = read_fpr_reg(target, 0, &value);
		set_reg_value_32(ppc476fs->FPSCR_reg, (uint32_t)(value >> 32));
		ppc476fs->FPSCR_reg->valid = true;
		ppc476fs->FPSCR_reg->dirty = false;
	}

	// restore F0 if it is needed
	if (F0_used) {
		ret = write_fpr_reg(target, 0, ppc476fs->saved_F0);
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
	bool R2_used = false;
	bool LR_used = false;
	int i;
	int ret;

	if (ppc476fs->PC_reg->dirty) {
		R2_used = true;
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
		R2_used = true;
		ret = write_gpr_reg(target, 2, get_reg_value_32(ppc476fs->CR_reg));
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x7C4FF120); // mtcr R2
		if (ret != ERROR_OK)
			return ret;
	 	ppc476fs->CR_reg->dirty = false;
	}

	if (ppc476fs->MSR_reg->dirty) {
		R2_used = true;
		ret = write_gpr_reg(target, 2, get_reg_value_32(ppc476fs->MSR_reg));
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, 0x7C400124); // mtmsr R2
		if (ret != ERROR_OK)
			return ret;
	 	ppc476fs->MSR_reg->dirty = false;
	}

	if (ppc476fs->XER_reg->dirty) {
		R2_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_XER, get_reg_value_32(ppc476fs->XER_reg));
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->XER_reg->dirty = false;
	}

	if (ppc476fs->CTR_reg->dirty) {
		R2_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_CTR, get_reg_value_32(ppc476fs->CTR_reg));
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->CTR_reg->dirty = false;
	}

	if (ppc476fs->LR_reg->dirty) {
		R2_used = true;
		ret = write_spr_reg(target, SPR_REG_NUM_LR, get_reg_value_32(ppc476fs->LR_reg));
		if (ret != ERROR_OK)
			return ret;
		ppc476fs->LR_reg->dirty = false;
		ppc476fs->saved_LR = get_reg_value_32(ppc476fs->LR_reg);
		LR_used = false;
	}

	// restore LR if it is needed
	if (LR_used) {
		R2_used = true;
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
			if (i == 1)
				ppc476fs->saved_R1 = get_reg_value_32(reg);
			else if (i == 2) {
				ppc476fs->saved_R2 = get_reg_value_32(reg);
				R2_used = false;
			}
		}
	}

	// restore R2 if it is needed
	if (R2_used) {
		ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
		if (ret != ERROR_OK)
			return ret;
	}

	return ERROR_OK;
}

int write_dirty_fpu_regs(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct reg *reg;
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

	assert((get_reg_value_32(ppc476fs->MSR_reg) & MSR_FP_MASK) != 0);

	ret = test_memory_at_stack(target);
	if (ret == ERROR_MEMORY_AT_STACK) {
		LOG_WARNING("cannot write FPU registers because of the stark pointer, CoreID: %i", target->coreid);
		for (i = 0; i < FPR_REG_COUNT; ++i) {
			reg = ppc476fs->fpr_regs[i];
			reg->dirty = false;
		}
		ppc476fs->FPSCR_reg->dirty = false;
		return ERROR_OK;
	}
	if (ret != ERROR_OK)
		return ret;

	if (ppc476fs->FPSCR_reg->dirty) {
		F0_used = true;
		ret = write_fpr_reg(target, 0, (uint64_t)get_reg_value_32(ppc476fs->FPSCR_reg) << 32);
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
			ret = write_fpr_reg(target, i, *((uint64_t*)reg->value));
			if (ret != ERROR_OK)
				return ret;
			reg->dirty = false;
			if (i == 0) {
				ppc476fs->saved_F0 = *((uint64_t*)reg->value);
				F0_used = false;
			}
		}
	}

	// restore F0 if it is needed
	if (F0_used) {
		ret = write_fpr_reg(target, 0, ppc476fs->saved_F0);
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

// the function uses R2 register and does not restore one
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
			ret = write_gpr_reg(target, 2, MSR_new_value);
			if (ret != ERROR_OK)
				return ret;
			ret = stuff_code(target, 0x7C400124); // mtmsr R2
			if (ret != ERROR_OK)
				return ret;
			ret = write_gpr_reg(target, 2, ppc476fs->saved_R2); // restore R2
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

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	breakpoint->set = 0;

	return ERROR_OK;
}

// the function uses R2 register and does not restore one
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

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static void break_points_invalidate(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct breakpoint *bp = target->breakpoints;

	assert((ppc476fs->DBCR0_value & DBCR0_IACX_MASK) == 0);

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

	regs_status_invalidate(target);

	return ERROR_OK;
}

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

	target->debug_reason = debug_reason;

	ret = restore_state(target);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int save_state_and_init_debug(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;

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

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	ret = clear_DBSR(target);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int reset_and_halt(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	uint32_t value_JDSR;
	int i;
	int ret;
	
	target->state = TARGET_RESET;
	regs_status_invalidate(target); // if an error occurs
	ppc476fs->DBCR0_value = 0;
	break_points_invalidate(target); // if an error occurs

	ret = write_JDCR(target, JDCR_RESET_MASK);
	if (ret != ERROR_OK)
		return ret;

	// stop the processor
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

	ret = save_state_and_init_debug(target);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int examine_internal(struct target *target)
{
	struct ppc476fs_tap_ext *tap_ext = target_to_ppc476fs_tap_ext(target);
	uint32_t JDSR_value;
	bool is_running;
	int ret;

	tap_ext->last_coreid = -1;

	ret = read_JDSR(target, &JDSR_value);
	if (ret != ERROR_OK)
		return ret;

	is_running = ((JDSR_value & JDSR_PSP_MASK) == 0);

	// stop the target if it is running
	if (is_running) {
		ret = write_JDCR(target, JDCR_STO_MASK);
		if (ret != ERROR_OK)
			return ret;
	}

	ret = save_state_and_init_debug(target);
	if (ret != ERROR_OK)
		return ret;

	// run the target if it was ranning before
	if (is_running) {
		ret = restore_state(target);
		if (ret != ERROR_OK)
			return ret;
		ret = write_JDCR(target, 0);
		if (ret != ERROR_OK)
			return ret;
	}

	return ERROR_OK;
}

// the target must be halted
// all UTLB are read without any sort
static int load_all_tlb(struct target *target, struct tlb_record records[TLB_NUMBER])
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int64_t start_time = timeval_ms();
	int64_t current_time;
	int i;
	int index;
	int way;
	uint32_t mmucr_saved;
	uint32_t mmucr_value;
	uint32_t r1_value;
	uint32_t r2_value;
	int ret;

	assert(target->state == TARGET_HALTED);

	// save MMUCR
	ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, &mmucr_saved);
	if (ret != ERROR_OK)
		return ret;

	for (i = 0; i < TLB_NUMBER; ++i) {
		current_time = timeval_ms();
		if (current_time - start_time > 500) {
			keep_alive();
			start_time = current_time;
		}

		index = i >> 2;
		way = i & 0x3;
		records[i].index = index;
		records[i].way = way;

		r2_value = (index << 16) | (way << 29);
		ret = write_gpr_reg(target, 2, r2_value);
		if (ret != ERROR_OK)
			return ret;

		ret = stuff_code(target, 0x7C220764); // tlbre R1, R2, 0
		if (ret != ERROR_OK)
			return ret;
		ret = read_gpr_reg(target, 1, &r1_value);
		if (ret != ERROR_OK)
			return ret;
		records[i].epn = (r1_value >> 12) & 0xFFFFF; // [12:31]
		records[i].v = (r1_value >> 11) & 0x1; // [11]
		records[i].ts = (r1_value >> 10) & 0x1; // [10]
		records[i].dsiz = (r1_value >> 4) & 0x3F; // [4:9]
		records[i].bolted = (r1_value >> 3) & 0x1; // [3]

		ret = stuff_code(target, 0x7C220F64); // tlbre R1, R2, 1
		if (ret != ERROR_OK)
			return ret;
		ret = read_gpr_reg(target, 1, &r1_value);
		if (ret != ERROR_OK)
			return ret;
		records[i].rpn = (r1_value >> 12) & 0xFFFFF; // [12:31]
		records[i].erpn = (r1_value >> 0) & 0x3FF; // [0:9]

		ret = stuff_code(target, 0x7C221764); // tlbre R1, R2, 2
		if (ret != ERROR_OK)
			return ret;
		ret = read_gpr_reg(target, 1, &r1_value);
		if (ret != ERROR_OK)
			return ret;
		records[i].il1i = (r1_value >> 17) & 0x1; // [17]
		records[i].il1d = (r1_value >> 16) & 0x1; // [16]
		records[i].u = (r1_value >> 12) & 0xF; // [12:15]
		records[i].wimg = (r1_value >> 8) & 0xF; // [8:11]
		records[i].en = (r1_value >> 7) & 0x1; // [7]
		records[i].uxwr = (r1_value >> 3) & 0x7; // [3:5]
		records[i].sxwr = (r1_value >> 0) & 0x7; // [0:2]

		ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, &mmucr_value);
		if (ret != ERROR_OK)
			return ret;
		records[i].tid = mmucr_value & MMUCR_STID_MASK;
	}

	// restore MMUCR
	ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, mmucr_saved);
	if (ret != ERROR_OK)
		return ret;

	// restore R1
	ret = write_gpr_reg(target, 1, ppc476fs->saved_R1);
	if (ret != ERROR_OK)
		return ret;

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int tlr_record_compar(const void *p1, const void *p2)
{
	const struct tlb_record *r1 = p1;
	const struct tlb_record *r2 = p2;

	if (r1->tid < r2->tid)
		return -1;
	if (r1->tid > r2->tid)
		return 1;

	if (r1->ts < r2->ts)
		return -1;
	if (r1->ts > r2->ts)
		return 1;

	if (r1->epn < r2->epn)
		return -1;
	if (r1->epn > r2->epn)
		return 1;

	return 0;
}

static const char *dsiz_to_string(unsigned dsiz)
{
	switch (dsiz) {
		case 0x00:
			return "4k";
		case 0x01:
			return "16k";
		case 0x03:
			return "64k";
		case 0x07:
			return "1m";
		case 0x0F:
			return "16m";
		case 0x1F:
			return "256m";
		case 0x3F:
			return "1g";
	}

	return "?";
}

static int ppc476fs_poll(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	enum target_state prev_state = target->state;
	uint32_t JDSR_value, DBSR_value;
	int ret;

	// LOG_DEBUG("CoreID: %i, cores %i %i", target->coreid, target->gdb_service->core[0], target->gdb_service->core[1]);

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

		// restore R2
		ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
		if (ret != ERROR_OK)
			return ret;

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

	LOG_DEBUG("CoreID: %i", target->coreid);

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
	LOG_DEBUG("CoreID: %i", target->coreid);

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
	LOG_DEBUG("CoreID: %i", target->coreid);

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
	LOG_DEBUG("CoreID: %i", target->coreid);

	if (target->reset_halt) {
		LOG_ERROR("Device does not support 'reset halt' command");
		return ERROR_FAIL;
	}

	return ERROR_OK;
}

static int ppc476fs_deassert_reset(struct target *target)
{
	int ret;

	LOG_DEBUG("CoreID: %i", target->coreid);

	ret = reset_and_halt(target);
	if (ret != ERROR_OK)
		return ret;

	// restore state with breakpoints
	ret = restore_state(target);
	if (ret != ERROR_OK)
		return ret;

	// contunue executing
	ret = write_JDCR(target, 0);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int ppc476fs_soft_reset_halt(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;
	
	LOG_DEBUG("CoreID: %i", target->coreid);

	ret = reset_and_halt(target);
	if (ret != ERROR_OK)
		return ret;

	// restore a register state after the reset
	set_reg_value_32(ppc476fs->PC_reg, 0xFFFFFFC);
	ppc476fs->PC_reg->dirty = true;
	set_reg_value_32(ppc476fs->MSR_reg, 0);
	ppc476fs->MSR_reg->dirty = true;
	// [***] other register must be restored - otherwise the soft reset does not work

	// restore state with breakpoints
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

	LOG_DEBUG("CoreID: %i, address: 0x%lX, size: %u, count: 0x%X", target->coreid, address, size, count);

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
		code = 0x88410000; // lbz %R2, 0(%R1)
		shift = 24;
		break;
	case 2:
		code = 0xA0410000; // lhz %R2, 0(%R1)
		shift = 16;
		break;
	case 4:
		code = 0x80410000; // lwz %R2, 0(%R1)
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
		ret = read_gpr_reg(target, 2, &value);
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

	// restore R1
	ret = write_gpr_reg(target, 1, ppc476fs->saved_R1);
	if (ret != ERROR_OK)
		return ret;

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

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

	LOG_DEBUG("CoreID: %i, address: 0x%016lX, size: %u, count: 0x%08X", target->coreid, address, size, count);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	switch (size)
	{
	case 1:
		code = 0x98410000; // stb %R2, 0(%R1)
		break;
	case 2:
		code = 0xB0410000; // sth %R2, 0(%R1)
		break;
	case 4:
		code = 0x90410000; // stw %R2, 0(%R1)
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
		ret = write_gpr_reg(target, 2, value);
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			return ret;
		address += size;
	}

	// restore R1
	ret = write_gpr_reg(target, 1, ppc476fs->saved_R1);
	if (ret != ERROR_OK)
		return ret;

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;	
}

static int ppc476fs_add_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct breakpoint *bp;
	int bp_count;

	LOG_DEBUG("CoreID: %i", target->coreid);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (breakpoint->type != BKPT_HARD)
		return ERROR_TARGET_FAILURE; // only hardware points	
	if (breakpoint->length != 4)
		return ERROR_TARGET_UNALIGNED_ACCESS;

	bp = target->breakpoints;
	bp_count = 0;
	while (bp != NULL) {
		if (bp != breakpoint) // do not count the added breakpoint, it may be in the list
			++bp_count;
		bp = bp->next;
	}
	if (bp_count == 4)
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	breakpoint->set = 0;

	return ERROR_OK;
}

static int ppc476fs_remove_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	int ret;

	LOG_DEBUG("CoreID: %i", target->coreid);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (breakpoint->set == 0)
		return ERROR_OK;

	ret = unset_breakpoint(target, breakpoint);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
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

	LOG_DEBUG("CoreID: %i", target->coreid);

	if ((target->coreid < 0) || (target->coreid > 1)) {
		LOG_ERROR("CoreID=%i is not allowed. It must be 0 or 1. It has been set to 0.", target->coreid);
		target->coreid = 0;
	}

	return ERROR_OK;
}

static int ppc476fs_init_target(struct command_context *cmd_ctx, struct target *target)
{
	LOG_DEBUG("CoreID: %i", target->coreid);

	build_reg_caches(target);

	if (target->tap->priv == NULL) {
		struct ppc476fs_tap_ext *tap_ext = malloc(sizeof(struct ppc476fs_tap_ext));
		tap_ext->last_coreid = -1;
		target->tap->priv = tap_ext;
		LOG_DEBUG("The TAP extera struct has been created, CoreID: %i", target->coreid);
	}
	else {
		LOG_DEBUG("The TAP extra struct has already been created, CoreID: %i", target->coreid);
	}

	return ERROR_OK;
}

static int ppc476fs_examine(struct target *target)
{
	int ret;

	LOG_DEBUG("CoreID: %i", target->coreid);

	ret = examine_internal(target);
	if (ret != ERROR_OK) {
		LOG_ERROR("Device has not been examined (error code = %i)", ret);
		return ret;
	}

	target_set_examined(target);

	return ERROR_OK;
}

COMMAND_HANDLER(ppc476fs_handle_tlb_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct tlb_record records[TLB_NUMBER];
	char buffer[256];
	int i;
	int record_count;
	int ret;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	ret = load_all_tlb(target, records);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot read UTLB: %i", ret);
		return ret;
	}

	keep_alive();

	// process only valid records
	record_count = 0;
	for (i = 0; i < TLB_NUMBER; ++i) {
		if (records[i].v)
			records[record_count++] = records[i];
	}

	qsort(records, record_count, sizeof(struct tlb_record), tlr_record_compar);

	command_print(CMD, "TID  TS   EPN   V  DSIZ ERPN  RPN  WIMG EN IL1I IL1D U UXWR SXWR  IW");
	for (i = 0; i < record_count; ++i) {
		sprintf(buffer, "%04X  %i %1s%05X  %i  %4s  %03X %05X   %X  %2s  %i    %i   %X   %X    %X  %02X%i",
			records[i].tid,
			records[i].ts,
			records[i].bolted ? "*" : "",
			records[i].epn,
			records[i].v,
			dsiz_to_string(records[i].dsiz),
			records[i].erpn,
			records[i].rpn,
			records[i].wimg,
			records[i].en == 0 ? "BE" : "LE",
			records[i].il1i,
			records[i].il1d,
			records[i].u,
			records[i].uxwr,
			records[i].sxwr,
			records[i].index,
			records[i].way);
		command_print(CMD, "%s", buffer);
	}

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
		.name = "tlb",
		.handler = ppc476fs_handle_tlb_command,
		.mode = COMMAND_EXEC,
		.usage = "tlb",
		.help = "dump all valid UTLB records"
	},
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
