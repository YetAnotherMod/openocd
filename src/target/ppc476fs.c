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
#include <helper/bits.h>

// uncomment the lines below to see the debug messages without turning on a debug mode
/*
#undef LOG_DEBUG
#define LOG_DEBUG(expr ...) \
	do { \
		printf("D:%i:%s: ", __LINE__, __func__); \
		printf(expr); \
		printf("\n"); \
	} while (0)
*/

// jtag instruction codes without core ids
#define JTAG_INSTR_WRITE_JDCR_READ_JDSR 0x28 /* 0b0101000 */
#define JTAG_INSTR_WRITE_JISB_READ_JDSR 0x38 /* 0b0111000 */
#define JTAG_INSTR_WRITE_READ_DBDR 0x58 /* 0b1011000 */
#define JTAG_INSTR_CORE_RELOAD 0x78 /* 0b1111000, is used for preventing a JTAG bug with the core swintching */

#define JDSR_PSP_MASK BIT(31 - 31)

#define JDCR_STO_MASK BIT(31 - 0)
#define JDCR_SS_MASK BIT(31 - 2)
#define JDCR_RESET_MASK (3 << (31 - 4)) /* system reset */
#define JDCR_RSDBSR_MASK BIT(31 - 8)

#define SPR_REG_NUM_LR 8 
#define SPR_REG_NUM_CTR 9
#define SPR_REG_NUM_XER 1
#define SPR_REG_NUM_PID 48
#define SPR_REG_NUM_DBCR0 308
#define SPR_REG_NUM_DBCR1 309
#define SPR_REG_NUM_DBCR2 310
#define SPR_REG_NUM_DBSR 304
#define SPR_REG_NUM_IAC_BASE 312 /* IAC1..IAC4 */
#define SPR_REG_NUM_DAC_BASE 316 /* DAC1..DAC2 */
#define SPR_REG_NUM_SSPCR 830
#define SPR_REG_NUM_USPCR 831
#define SPR_REG_NUM_MMUCR 946

#define DBCR0_EDM_MASK BIT(63 - 32)
#define DBCR0_TRAP_MASK BIT(63 - 39)
#define DBCR0_IAC1_MASK BIT(63 - 40)
#define DBCR0_IACX_MASK (0xF << (63 - 43))
#define DBCR0_DAC1R_MASK BIT(63 - 44)
#define DBCR0_DAC1W_MASK BIT(63 - 45)
#define DBCR0_DACX_MASK (0xF << (63 - 47))
#define DBCR0_FT_MASK BIT(63 - 63)

#define DBSR_IAC1_MASK BIT(63 - 40)
#define DBSR_IAC2_MASK BIT(63 - 41)
#define DBSR_IAC3_MASK BIT(63 - 42)
#define DBSR_IAC4_MASK BIT(63 - 43)
#define DBSR_DAC1R_MASK BIT(63 - 44)
#define DBSR_DAC1W_MASK BIT(63 - 45)
#define DBSR_DAC2R_MASK BIT(63 - 46)
#define DBSR_DAC2W_MASK BIT(63 - 47)
#define DBSR_IAC_ALL_MASK (DBSR_IAC1_MASK | DBSR_IAC2_MASK | DBSR_IAC3_MASK | DBSR_IAC4_MASK)
#define DBSR_DAC_ALL_MASK (DBSR_DAC1R_MASK | DBSR_DAC1W_MASK | DBSR_DAC2R_MASK | DBSR_DAC2W_MASK)

#define MSR_PR_MASK BIT(63 - 49)
#define MSR_FP_MASK BIT(63 - 50)
#define MSR_DS_MASK BIT(63 - 59)

#define MMUCR_STID_MASK (0xFFFF << 0)

#define ALL_REG_COUNT 71
#define GDB_REG_COUNT 71 /* at start of all register array */
#define GEN_CACHE_REG_COUNT 38 /* R0-R31, PC, MSR, CR, LR, CTR, XER */
#define FPU_CACHE_REG_COUNT 33 /* F0-F31, FPSCR */
#define GPR_REG_COUNT 32
#define FPR_REG_COUNT 32

#define MAGIC_RANDOM_VALUE_1 0x396F965C
#define MAGIC_RANDOM_VALUE_2 0x44692D7E

#define PHYS_MEM_MAGIC_PID 0xEFCD
#define PHYS_MEM_BASE_ADDR 0x00000000
#define PHYS_MEM_TLB_INDEX (PHYS_MEM_MAGIC_PID & 0xFF) /* if PHYS_MEM_BASE_ADDR == 0x00000000 */
#define PHYS_MEM_TLB_WAY 2
#define PHYS_MEM_TLB_INDEX_WAY ((PHYS_MEM_TLB_INDEX << 2) | PHYS_MEM_TLB_WAY)

#define ERROR_MEMORY_AT_STACK (-99)

#define HW_BP_NUMBER 4
#define WP_NUMBER 2
#define TLB_NUMBER 1024

#define TLB_0_EPN_BIT_POS 12
#define TLB_0_EPN_BIT_LEN 20
#define TLB_0_V_MASK BIT(11)
#define TLB_0_TS_MASK BIT(10)
#define TLB_0_DSIZ_BIT_POS 4
#define TLB_0_DSIZ_BIT_LEN 6
#define TLB_0_BLTD_MASK BIT(3)

#define TLB_1_RPN_BIT_POS 12
#define TLB_1_RPN_BIT_LEN 20
#define TLB_1_ERPN_BIT_POS 0
#define TLB_1_ERPN_BIT_LEN 10

#define TLB_2_IL1I_MASK BIT(17)
#define TLB_2_IL1D_MASK BIT(16)
#define TLB_2_U_BIT_POS 12
#define TLB_2_U_BIT_LEN 4
#define TLB_2_WIMG_BIT_POS 8
#define TLB_2_WIMG_BIT_LEN 4
#define TLB_2_EN_MASK BIT(7)
#define TLB_2_UXWR_BIT_POS 3
#define TLB_2_UXWR_BIT_LEN 3
#define TLB_2_SXWR_BIT_POS 0
#define TLB_2_SXWR_BIT_LEN 3

#define DSIZ_4K 0x00
#define DSIZ_16K 0x01
#define DSIZ_64K 0x03
#define DSIZ_1M 0x07
#define DSIZ_16M 0x0F
#define DSIZ_256M 0x1F
#define DSIZ_1G 0x3F

#define TLB_PARAMS_MASK_EPN BIT(0)
#define TLB_PARAMS_MASK_RPN BIT(1)
#define TLB_PARAMS_MASK_ERPN BIT(2)
#define TLB_PARAMS_MASK_TID BIT(3)
#define TLB_PARAMS_MASK_TS BIT(4)
#define TLB_PARAMS_MASK_DSIZ BIT(5)
#define TLB_PARAMS_MASK_WAY BIT(6)
#define TLB_PARAMS_MASK_IL1I BIT(7)
#define TLB_PARAMS_MASK_IL1D BIT(8)
#define TLB_PARAMS_MASK_U BIT(9)
#define TLB_PARAMS_MASK_WIMG BIT(10)
#define TLB_PARAMS_MASK_EN BIT(11)
#define TLB_PARAMS_MASK_UXWR BIT(12)
#define TLB_PARAMS_MASK_SXWR BIT(13)

#define TRAP_INSTRUCTION_CODE 0x7FE00008

struct tlb_hw_record {
	uint32_t data[3]; // if the 'valid' bit is zero, all other data are undefined
	uint32_t tid; // if the 'valid' bit is zero, the field is undefined
};

struct tlb_cached_record {
	bool loaded;
	struct tlb_hw_record hw;
};

struct tlb_sort_record {
	int index_way;
	struct tlb_hw_record hw;
};

struct tlb_command_params
{
	unsigned mask; // TLB_PARAMS_MASK*
	uint32_t epn;
	uint32_t rpn;
	uint32_t erpn;
	uint32_t tid;
	uint32_t ts;
	uint32_t dsiz; // DSIZ*
	int way; // -1 for 'auto'
	uint32_t il1i;
	uint32_t il1d;
	uint32_t u;
	uint32_t wimg;
	uint32_t en; // 0-BE, 1-LE
	uint32_t uxwr;
	uint32_t sxwr;
};

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
	uint32_t IAC_value[HW_BP_NUMBER];
	uint32_t DAC_value[WP_NUMBER];
	uint32_t saved_R1;
	uint32_t saved_R2;
	uint32_t saved_LR;
	uint64_t saved_F0;
	struct tlb_cached_record tlb_cache[TLB_NUMBER];
};

struct ppc476fs_tap_ext {
	int last_coreid; // -1 if the last core id is unknown
};

// used for save/restore/setup pysh memory access
struct phys_mem_state
{
	uint32_t saved_MSR;
	uint32_t saved_MMUCR;
	uint32_t saved_PID;
	uint32_t saved_USPCR;
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

static inline uint32_t get_bits_32(uint32_t value, unsigned pos, unsigned len)
{
	return (value >> pos) & ((1U << len) - 1);
}

static inline void set_bits_32(uint32_t value, unsigned pos, unsigned len, uint32_t *dest)
{
	*dest &= ~(((1U << len) - 1U) << pos);
	*dest |= value << pos;
}

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

// the function only add the request into the JTAG queue, the jtag_execute_queue function is not called
// read_data can be null
static void add_jtag_read_write_register(struct target *target, uint32_t instr_without_coreid, uint32_t valid_bit, uint32_t write_data, uint8_t read_data[8])
{
	struct ppc476fs_tap_ext *tap_ext = target_to_ppc476fs_tap_ext(target);
	struct scan_field instr_field;
	uint8_t instr_buffer[4];
	struct scan_field data_fields[1];
	uint8_t data_out_buffer[8];
	uint64_t zeros = 0;

	// !!! IMPORTANT
	// prevent the JTAG core switching bug
	if (tap_ext->last_coreid != target->coreid) {
		buf_set_u32(instr_buffer, 0, target->tap->ir_length, JTAG_INSTR_CORE_RELOAD | coreid_mask[target->coreid]);
		instr_field.num_bits = target->tap->ir_length;
		instr_field.out_value = instr_buffer;
		instr_field.in_value = NULL;
		jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);
		tap_ext->last_coreid = target->coreid;
	}

	buf_set_u32(instr_buffer, 0, target->tap->ir_length, instr_without_coreid | coreid_mask[target->coreid]);
	instr_field.num_bits = target->tap->ir_length;
	instr_field.out_value = instr_buffer;
	instr_field.in_value = NULL;
	jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);

	buf_set_u32(data_out_buffer, 0, 32, write_data);
	buf_set_u32(data_out_buffer, 32, 1, valid_bit);
	data_fields[0].num_bits = 33;
	data_fields[0].out_value = data_out_buffer;
	data_fields[0].in_value = read_data;
	jtag_add_dr_scan(target->tap, 1, data_fields, TAP_IDLE);

	// !!! IMPORTANT
	// make additional request with valid bit == 0
	// to correct a JTAG communication BUG
	if (valid_bit != 0) {
		jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);
		data_fields[0].out_value = (uint8_t*)zeros;
		data_fields[0].in_value = NULL;
		jtag_add_dr_scan(target->tap, 1, data_fields, TAP_IDLE);
	}
}

static int jtag_read_write_register(struct target *target, uint32_t instr_without_coreid, uint32_t valid_bit, uint32_t write_data, uint32_t *read_data)
{
	uint8_t data_in_buffer[8];
	int ret;

	add_jtag_read_write_register(target, instr_without_coreid, valid_bit, write_data, read_data == NULL ? NULL : data_in_buffer);

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

	return ERROR_OK;
}

static int stuff_code(struct target *target, uint32_t code)
{
	int ret;

	ret =  jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR, 1, code, NULL);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int read_DBDR(struct target *target, uint32_t *data)
{
	return jtag_read_write_register(target, JTAG_INSTR_WRITE_READ_DBDR, 0, 0, data);
}

static int read_gpr_reg(struct target *target, int reg_num, uint32_t *data)
{
	uint32_t code = 0x7C13FBA6 | (reg_num << 21); // mtdbdr Rx
	int ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	
	return read_DBDR(target, data);
}

// the function only add the request into the JTAG queue, the jtag_execute_queue function is not called
static void add_write_gpr_reg(struct target *target, int reg_num, uint32_t data)
{
	uint32_t code = 0x7C13FAA6 | (reg_num << 21); // mfdbdr Rx

	add_jtag_read_write_register(target, JTAG_INSTR_WRITE_READ_DBDR, 1, data, NULL);
	add_jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR, 1, code, NULL);
}

static int write_gpr_reg(struct target *target, int reg_num, uint32_t data)
{
	int ret;

	add_write_gpr_reg(target, reg_num, data);

	ret = jtag_execute_queue();
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

// the function uses R2 register and does not restore one
static int read_MSR(struct target *target, uint32_t *value)
{
	int ret;

	ret = stuff_code(target, 0x7C4000A6); // mfmsr R2
	if (ret != ERROR_OK)
		return ret;
	ret = read_gpr_reg(target, 2, value);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

// the function uses R2 register and does not restore one
static int write_MSR(struct target *target, uint32_t value)
{
	int ret;

	ret = write_gpr_reg(target, 2, value);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x7C400124); // mtmsr R2
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
		ret = read_MSR(target, ppc476fs->MSR_reg->value);
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
		LOG_WARNING("cannot read FPU registers because of the stark pointer, coreid=%i", target->coreid);
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
		ret = write_MSR(target, get_reg_value_32(ppc476fs->MSR_reg));
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
		LOG_WARNING("cannot write FPU registers because of the stark pointer, coreid=%i", target->coreid);
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

static void invalidate_regs_status(struct target *target)
{
	struct reg_cache *cache = target->reg_cache;

	while (cache != NULL) {
		register_cache_invalidate(cache);
		cache = cache->next;
	}
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
			ret = write_MSR(target, MSR_new_value);
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

// the function uses R2 register and does not restore one
static int unset_hw_breakpoint(struct target *target, struct breakpoint *bp)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int iac_index = 0;
	uint32_t iac_mask;
	int ret;

	assert(bp->set != 0);

	while (true) {
		iac_mask = (DBCR0_IAC1_MASK >> iac_index);
		if ((ppc476fs->DBCR0_value & iac_mask) != 0)
		{
			if (ppc476fs->IAC_value[iac_index] == (uint32_t)bp->address)
				break;
		}
		++iac_index;
		assert(iac_index < HW_BP_NUMBER);
	}

	ret = write_DBCR0(target, ppc476fs->DBCR0_value & ~iac_mask);
	if (ret != ERROR_OK)
		return ret;

	bp->set = 0;

	return ERROR_OK;
}

// the function uses R1 and R2 registers and does not restore them
static int unset_soft_breakpoint(struct target *target, struct breakpoint *bp)
{
	uint32_t instr_saved;
	uint32_t test_value;
	int ret;

	assert(bp->set != 0);

	memcpy(&instr_saved, bp->orig_instr, 4);

	ret = write_gpr_reg(target, 1, (uint32_t)bp->address);
	if (ret != ERROR_OK)
		return ret;
	ret = write_gpr_reg(target, 2, instr_saved);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x90410000); // stw %R2, 0(%R1)
	if (ret != ERROR_OK)
		return ret;

	// test
	ret = stuff_code(target, 0x80410000); // lwz %R2, 0(%R1)
	if (ret != ERROR_OK)
		return ret;
	ret = read_gpr_reg(target, 2, &test_value);
	if (ret != ERROR_OK)
		return ret;

	if (test_value == instr_saved)
		bp->set = 0;
	else
		LOG_WARNING("soft breakpoint cannot be removed at address 0x%08X", (uint32_t)bp->address);

	return ERROR_OK;
}

static int unset_all_soft_breakpoints(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct breakpoint *bp;
	int ret;

	bp = target->breakpoints;
	while (bp != NULL) {
		if (bp->type == BKPT_SOFT) {
			ret = unset_soft_breakpoint(target, bp);
			if (ret != ERROR_OK)
				return ret;
		}
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

// the function uses R2 register and does not restore one
static int set_hw_breakpoint(struct target *target, struct breakpoint *bp)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int iac_index = 0;
	uint32_t iac_mask;
	int ret;

	assert(bp->set == 0);

	while (true) {
		iac_mask = (DBCR0_IAC1_MASK >> iac_index);
		if ((ppc476fs->DBCR0_value & iac_mask) == 0)
			break;
		++iac_index;
		assert(iac_index < HW_BP_NUMBER);
	}

	ret = write_spr_reg(target, SPR_REG_NUM_IAC_BASE + iac_index, (uint32_t)bp->address);
	if (ret != ERROR_OK)
		return ret;
	ppc476fs->IAC_value[iac_index] = (uint32_t)bp->address;

	ret = write_DBCR0(target, ppc476fs->DBCR0_value | iac_mask);
	if (ret != ERROR_OK)
		return ret;

	bp->set = 1;

	return ERROR_OK;
}

// the function uses R1 and R2 registers and does not restore them
static int set_soft_breakpoint(struct target *target, struct breakpoint *bp)
{
	int ret;
	uint32_t instr_saved;
	uint32_t test_value;

	ret = write_gpr_reg(target, 1, (uint32_t)bp->address);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x80410000); // lwz %R2, 0(%R1)
	if (ret != ERROR_OK)
		return ret;
	ret = read_gpr_reg(target, 2, &instr_saved);
	if (ret != ERROR_OK)
		return ret;

	memcpy(bp->orig_instr, &instr_saved, 4);

	ret = write_gpr_reg(target, 2, TRAP_INSTRUCTION_CODE);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x90410000); // stw %R2, 0(%R1)
	if (ret != ERROR_OK)
		return ret;

	// test
	ret = stuff_code(target, 0x80410000); // lwz %R2, 0(%R1)
	if (ret != ERROR_OK)
		return ret;
	ret = read_gpr_reg(target, 2, &test_value);
	if (ret != ERROR_OK)
		return ret;

	if (test_value == TRAP_INSTRUCTION_CODE)
		bp->set = 1;
	else
		LOG_WARNING("soft breakpoint cannot be set at address 0x%08X", (uint32_t)bp->address);

	return ERROR_OK;
}

static int enable_breakpoints(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct breakpoint *bp = target->breakpoints;
	bool R1_used = false;
	bool R2_used = false;
	int ret;

	while (bp != NULL) {
		if (bp->set == 0) {
			if (bp->type == BKPT_HARD) {
				R2_used = true;
				ret = set_hw_breakpoint(target, bp);
			} else {
				R1_used = true;
				R2_used = true;
				ret = set_soft_breakpoint(target, bp);
			}
			if (ret != ERROR_OK)
				return ret;
		}
		bp = bp->next;
	}

	// restore R1 if it is needed
	if (R1_used) {
		ret = write_gpr_reg(target, 1, ppc476fs->saved_R1);
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

// the DAC fields in DBCR0 register must be cleared before the function call
static void invalidate_hw_breakpoints(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct breakpoint *bp = target->breakpoints;

	assert((ppc476fs->DBCR0_value & DBCR0_IACX_MASK) == 0);

	while (bp != NULL) {
		if (bp->type == BKPT_HARD)
			bp->set = 0;
		bp = bp->next;
	}
}

static int add_hw_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct breakpoint *bp;
	int bp_count;

	bp = target->breakpoints;
	bp_count = 0;
	while (bp != NULL) {
		if (bp->type != BKPT_HARD)
			continue;
		if (bp != breakpoint) // do not count the added breakpoint, it may be in the list
			++bp_count;
		bp = bp->next;
	}
	if (bp_count == HW_BP_NUMBER)
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	return ERROR_OK;
}

static int unset_watchpoint(struct target *target, struct watchpoint *wp)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int dac_index = 0;
	uint32_t dacr_mask;
	uint32_t dacw_mask;
	int ret;

	assert(wp->set != 0);

	while (true) {
		dacr_mask = (DBCR0_DAC1R_MASK >> (dac_index * 2));
		dacw_mask = (DBCR0_DAC1W_MASK >> (dac_index * 2));
		if ((ppc476fs->DBCR0_value & (dacr_mask | dacw_mask)) != 0)
		{
			if (ppc476fs->DAC_value[dac_index] == (uint32_t)wp->address)
				break;
		}
		++dac_index;
		assert(dac_index < WP_NUMBER);
	}

	ret = write_DBCR0(target, ppc476fs->DBCR0_value & ~(dacr_mask | dacw_mask));
	if (ret != ERROR_OK)
		return ret;

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	wp->set = 0;

	return ERROR_OK;
}

// the function uses R2 register and does not restore one
static int set_watchpoint(struct target *target, struct watchpoint *wp)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;
	int dac_index = 0;
	uint32_t dacr_mask;
	uint32_t dacw_mask;
	uint32_t dac_mask;

	assert(wp->set == 0);

	while (true) {
		dacr_mask = (DBCR0_DAC1R_MASK >> (dac_index * 2));
		dacw_mask = (DBCR0_DAC1W_MASK >> (dac_index * 2));
		if ((ppc476fs->DBCR0_value & (dacr_mask | dacw_mask)) == 0)
			break;
		++dac_index;
		assert(dac_index < WP_NUMBER);
	}

	ret = write_spr_reg(target, SPR_REG_NUM_DAC_BASE + dac_index, (uint32_t)wp->address);
	if (ret != ERROR_OK)
		return ret;
	ppc476fs->DAC_value[dac_index] = (uint32_t)wp->address;

	switch (wp->rw)
	{
		case WPT_READ:
			dac_mask = dacr_mask;
			break;
		case WPT_WRITE:
			dac_mask = dacw_mask;
			break;
		case WPT_ACCESS:
			dac_mask = dacr_mask | dacw_mask;
			break;
		default:
			assert(false);
	}

	ret = write_DBCR0(target, ppc476fs->DBCR0_value | dac_mask);
	if (ret != ERROR_OK)
		return ret;

	wp->set = 1;

	return ERROR_OK;
}

static int enable_watchpoints(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct watchpoint *wp = target->watchpoints;
	bool R2_used = false;
	int ret;

	while (wp != NULL) {
		if (wp->set == 0) {
			R2_used = true;
			ret = set_watchpoint(target, wp);
			if (ret != ERROR_OK)
				return ret;
		}
		wp = wp->next;
	}

	// restore R2 if it is needed
	if (R2_used) {
		ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
		if (ret != ERROR_OK)
			return ret;
	}

	return ERROR_OK;
}

static void invalidate_watchpoints(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct watchpoint *wp = target->watchpoints;

	assert((ppc476fs->DBCR0_value & DBCR0_DACX_MASK) == 0);

	while (wp != NULL) {
		wp->set = 0;
		wp = wp->next;
	}
}

static void invalidate_tlb_cache(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int i;

	for (i = 0; i < TLB_NUMBER; ++i)
		ppc476fs->tlb_cache[i].loaded = false;
}

static int save_state(struct target *target)
{
	int ret;

	invalidate_regs_status(target);
	invalidate_tlb_cache(target);

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

	ret = enable_watchpoints(target);
	if (ret != ERROR_OK)
		return ret;

	invalidate_regs_status(target);
	invalidate_tlb_cache(target);

	return ERROR_OK;
}

static int restore_state_before_run(struct target *target, int current, target_addr_t address, enum target_debug_reason  debug_reason)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("target not halted");
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

	ret = write_DBCR0(target, DBCR0_EDM_MASK | DBCR0_TRAP_MASK | DBCR0_FT_MASK);
	if (ret != ERROR_OK)
		return ret;
	invalidate_hw_breakpoints(target);
	invalidate_watchpoints(target);

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

	unset_all_soft_breakpoints(target); // ignore return value
	
	target->state = TARGET_RESET;
	invalidate_regs_status(target); // if an error occurs
	ppc476fs->DBCR0_value = 0;
	invalidate_hw_breakpoints(target); // if an error occurs
	invalidate_watchpoints(target); // if an error occurs

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
// the function uses R1, R2 registers and does not restore them
static int read_virt_mem(struct target *target, uint32_t address, uint32_t size, uint8_t *buffer)
{
	uint32_t code;
	uint32_t shift;
	uint32_t value;
	uint32_t i;
	int ret;

	assert(target->state == TARGET_HALTED);

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

	ret = write_gpr_reg(target, 1, address);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	ret = read_gpr_reg(target, 2, &value);
	if (ret != ERROR_OK)
		return ret;

	value <<= shift;
	for (i = 0; i < size; ++i)
	{
		*(buffer++) = (value >> 24);
		value <<= 8;
	}

	return ERROR_OK;
}

// the target must be halted
// the function uses R1, R2 registers and does not restore them
// the function only add the request into the JTAG queue, the jtag_execute_queue function is not called
static void add_write_virt_mem(struct target *target, uint32_t address, uint32_t size, const uint8_t *buffer)
{
	uint32_t code;
	uint32_t value;
	uint32_t i;

	assert(target->state == TARGET_HALTED);

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

	add_write_gpr_reg(target, 1, address);

	value = 0;
	for (i = 0; i < size; ++i)
	{
		value <<= 8;
		value |= (uint32_t)*(buffer++);
	}

	add_write_gpr_reg(target, 2, value);
	add_jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR, 1, code, NULL);
}

// the target must be halted
// the function uses R1, R2, MMUCR registers and does not restore them
static int load_tlb(struct target *target, int index_way, struct tlb_hw_record *hw)
{
	int index;
	int way;
	uint32_t r2_value;
	uint32_t mmucr_value;
	int ret;

	assert(target->state == TARGET_HALTED);

	hw->data[0] = 0;
	hw->data[1] = 0;
	hw->data[2] = 0;
	hw->tid = 0;

	index = index_way >> 2;
	way = index_way & 0x3;

	r2_value = (index << 16) | (way << 29);
	ret = write_gpr_reg(target, 2, r2_value);
	if (ret != ERROR_OK)
		return ret;

	ret = stuff_code(target, 0x7C220764); // tlbre R1, R2, 0
	if (ret != ERROR_OK)
		return ret;
	ret = read_gpr_reg(target, 1, &hw->data[0]);
	if (ret != ERROR_OK)
		return ret;

	// otimization for non-valid UTLB records
	if ((hw->data[0] & TLB_0_V_MASK) == 0)
		return ERROR_OK;

	ret = stuff_code(target, 0x7C220F64); // tlbre R1, R2, 1
	if (ret != ERROR_OK)
		return ret;
	ret = read_gpr_reg(target, 1, &hw->data[1]);
	if (ret != ERROR_OK)
		return ret;

	ret = stuff_code(target, 0x7C221764); // tlbre R1, R2, 2
	if (ret != ERROR_OK)
		return ret;
	ret = read_gpr_reg(target, 1, &hw->data[2]);
	if (ret != ERROR_OK)
		return ret;

	ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, &mmucr_value);
	if (ret != ERROR_OK)
		return ret;
	hw->tid = mmucr_value & MMUCR_STID_MASK;

	return ERROR_OK;
}

// the target must be halted
// the function deletes the UTLB record at the specified index_way if the 'valid' bit is 0
// the function uses R1, R2, MMUCR registers and does not restore them
// the function cannot write a bolted UTLB record
// the function does not call 'isync'
static int write_tlb(struct target *target, int index_way, struct tlb_hw_record *hw)
{
	int way;
	uint32_t tid;
	uint32_t data0;
	uint32_t r2_value;
	int ret;

	assert(target->state == TARGET_HALTED);
	assert((hw->data[0] & TLB_0_BLTD_MASK) == 0);

	// correction for non-valid UTLB record
	tid = hw->tid;
	data0 = hw->data[0];
	if ((data0 & TLB_0_V_MASK) == 0) {
		tid = index_way >> 2; // make the correct UTLB index
		data0 = 0;
	}

	ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, tid);
	if (ret != ERROR_OK)
		return ret;

	way = index_way & 0x3;
	r2_value = (way << 29) | 0x80000000; // the way is set manually
	ret = write_gpr_reg(target, 2, r2_value);
	if (ret != ERROR_OK)
		return ret;

	ret = write_gpr_reg(target, 1, data0);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x7C2207A4); // tlbwe R1, R2, 0
	if (ret != ERROR_OK)
		return ret;

	// otimization for non-valid UTLB records
	if ((data0 & TLB_0_V_MASK) == 0)
		return ERROR_OK;

	ret = write_gpr_reg(target, 1, hw->data[1]);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x7C220FA4); // tlbwe R1, R2, 1
	if (ret != ERROR_OK)
		return ret;

	ret = write_gpr_reg(target, 1, hw->data[2]);
	if (ret != ERROR_OK)
		return ret;
	ret = stuff_code(target, 0x7C2217A4); // tlbwe R1, R2, 2
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int load_uncached_tlb(struct target *target, int index_way)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;

	if (ppc476fs->tlb_cache[index_way].loaded)
		return ERROR_OK;

	ret = load_tlb(target, index_way, &ppc476fs->tlb_cache[index_way].hw);
	if (ret != ERROR_OK)
		return ret;

	ppc476fs->tlb_cache[index_way].loaded = true;

	return ERROR_OK;
}

static int compare_tlb_record(const void *p1, const void *p2)
{
	const struct tlb_sort_record *r1 = p1;
	const struct tlb_sort_record *r2 = p2;
	uint32_t v1;
	uint32_t v2;

	if (r1->hw.tid < r2->hw.tid)
		return -1;
	if (r1->hw.tid > r2->hw.tid)
		return 1;

	v1 = r1->hw.data[0] & TLB_0_TS_MASK;
	v2 = r2->hw.data[0] & TLB_0_TS_MASK;
	if (v1 < v2)
		return -1;
	if (v1 > v2)
		return 1;

	v1 = get_bits_32(r1->hw.data[0], TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN);
	v2 = get_bits_32(r2->hw.data[0], TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN);
	if (v1 < v2)
		return -1;
	if (v1 > v2)
		return 1;

	return 0;
}

static const char *dsiz_to_string(unsigned dsiz)
{
	switch (dsiz) {
		case DSIZ_4K:
			return "4k";
		case DSIZ_16K:
			return "16k";
		case DSIZ_64K:
			return "64k";
		case DSIZ_1M:
			return "1m";
		case DSIZ_16M:
			return "16m";
		case DSIZ_256M:
			return "256m";
		case DSIZ_1G:
			return "1g";
	}

	return "?";
}

static void print_tlb_table_header(struct command_invocation *cmd) {
	command_print(CMD, "TID  TS   EPN   V  DSIZ ERPN  RPN  WIMG EN IL1I IL1D U UXWR SXWR  IW");
}

static void print_tlb_table_record(struct command_invocation *cmd, int index_way, struct tlb_hw_record *hw) {
	char buffer[256];

	sprintf(buffer, "%04X  %i %1s%05X  %i  %4s  %03X %05X   %X  %2s  %i    %i   %X   %X    %X  %02X%i",
		hw->tid,
		(int)((hw->data[0] & TLB_0_TS_MASK) != 0),
		(hw->data[0] & TLB_0_BLTD_MASK) != 0 ? "*" : "",
		get_bits_32(hw->data[0], TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN),
		(int)((hw->data[0] & TLB_0_V_MASK) != 0),
		dsiz_to_string(get_bits_32(hw->data[0], TLB_0_DSIZ_BIT_POS, TLB_0_DSIZ_BIT_LEN)),
		get_bits_32(hw->data[1], TLB_1_ERPN_BIT_POS, TLB_1_ERPN_BIT_LEN),
		get_bits_32(hw->data[1], TLB_1_RPN_BIT_POS, TLB_1_RPN_BIT_LEN),
		get_bits_32(hw->data[2], TLB_2_WIMG_BIT_POS, TLB_2_WIMG_BIT_LEN),
		(hw->data[2] & TLB_2_EN_MASK) == 0 ? "BE" : "LE",
		(int)((hw->data[2] & TLB_2_IL1I_MASK) != 0),
		(int)((hw->data[2] & TLB_2_IL1D_MASK) != 0),
		get_bits_32(hw->data[2], TLB_2_U_BIT_POS, TLB_2_U_BIT_LEN),
		get_bits_32(hw->data[2], TLB_2_UXWR_BIT_POS, TLB_2_UXWR_BIT_LEN),
		get_bits_32(hw->data[2], TLB_2_SXWR_BIT_POS, TLB_2_SXWR_BIT_LEN),
		index_way >> 2,
		index_way & 0x3);
	command_print(CMD, "%s", buffer);
}

static int init_phys_mem(struct target *target, struct phys_mem_state *state)
{
	int ret;

	ret = read_MSR(target, &state->saved_MSR);
	if (ret != ERROR_OK)
		return ret;

	ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, &state->saved_MMUCR);
	if (ret != ERROR_OK)
		return ret;

	ret = read_spr_reg(target, SPR_REG_NUM_PID, &state->saved_PID);
	if (ret != ERROR_OK)
		return ret;

	ret = read_spr_reg(target, SPR_REG_NUM_USPCR, &state->saved_USPCR);
	if (ret != ERROR_OK)
		return ret;

	// set MSR
	ret = write_MSR(target, state->saved_MSR | MSR_PR_MASK | MSR_DS_MASK); // problem mode and TS=1
	if (ret != ERROR_OK)
		return ret;

	// load TLB record
	ret = load_uncached_tlb(target, PHYS_MEM_TLB_INDEX_WAY);
	if (ret != ERROR_OK)
		return ret;

	// set PID
	ret = write_spr_reg(target, SPR_REG_NUM_PID, PHYS_MEM_MAGIC_PID);
	if (ret != ERROR_OK)
		return ret;

	// set USPCR
	ret = write_spr_reg(target, SPR_REG_NUM_USPCR, 0x70000000); // only 1Gb page with PID
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int restore_phys_mem(struct target *target, struct phys_mem_state *state)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;

	// restore TLB record
	ret = write_tlb(target, PHYS_MEM_TLB_INDEX_WAY, &ppc476fs->tlb_cache[PHYS_MEM_TLB_INDEX_WAY].hw);
	if (ret != ERROR_OK)
		return ret;

	// retsore USPCR
	ret = write_spr_reg(target, SPR_REG_NUM_USPCR, state->saved_USPCR);
	if (ret != ERROR_OK)
		return ret;

	// retsore PID
	ret = write_spr_reg(target, SPR_REG_NUM_PID, state->saved_PID);
	if (ret != ERROR_OK)
		return ret;

	// restore MMUCR
	ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, state->saved_MMUCR);
	if (ret != ERROR_OK)
		return ret;

	// restore MSR
	ret = write_MSR(target, state->saved_MSR);
	if (ret != ERROR_OK)
		return ret;

	// syncing
	ret = stuff_code(target, 0x4C00012C); // isync
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

static int access_phys_mem(struct target *target, uint32_t new_ERPN_RPN)
{
	struct tlb_hw_record hw;
	int ret;

	hw.data[0] = TLB_0_V_MASK | TLB_0_TS_MASK; // TS=1
	set_bits_32(PHYS_MEM_BASE_ADDR >> 12, TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN, &hw.data[0]);
	set_bits_32(DSIZ_1G, TLB_0_DSIZ_BIT_POS, TLB_0_DSIZ_BIT_LEN, &hw.data[0]);

	hw.data[1] = 0;
	set_bits_32(new_ERPN_RPN >> 20, TLB_1_ERPN_BIT_POS, TLB_1_ERPN_BIT_LEN, &hw.data[1]);
	set_bits_32(new_ERPN_RPN & 0xFFFFF, TLB_1_RPN_BIT_POS, TLB_1_RPN_BIT_LEN, &hw.data[1]);

	hw.data[2] = TLB_2_IL1I_MASK | TLB_2_IL1D_MASK;
	set_bits_32(0x7, TLB_2_WIMG_BIT_POS, TLB_2_WIMG_BIT_LEN, &hw.data[2]);
	set_bits_32(0x3, TLB_2_UXWR_BIT_POS, TLB_2_UXWR_BIT_LEN, &hw.data[2]);

	hw.tid = PHYS_MEM_MAGIC_PID;

	ret = write_tlb(target, PHYS_MEM_TLB_INDEX_WAY, &hw);
	if (ret != ERROR_OK)
		return ret;

	// syncing
	ret = stuff_code(target, 0x4C00012C); // isync
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static inline int parse_uint32_params(unsigned param_mask, uint32_t max_value, const char *param, unsigned *current_mask, uint32_t *dest)
{
	unsigned long value;
	int ret;

	if ((*current_mask & param_mask) != 0)
		return ERROR_COMMAND_ARGUMENT_INVALID;
	*current_mask |= param_mask;

	ret = parse_ulong(param, &value);
	if (ret != ERROR_OK)
		return ERROR_COMMAND_ARGUMENT_INVALID; // not ret

	if (value > max_value)
		return ERROR_COMMAND_ARGUMENT_INVALID;

	*dest = (uint32_t)value;

	return ERROR_OK;
}

static inline int parse_dsiz_params(unsigned param_mask, const char *param, unsigned *current_mask, uint32_t *dest)
{
	if ((*current_mask & param_mask) != 0)
		return ERROR_COMMAND_ARGUMENT_INVALID;
	*current_mask |= param_mask;

	if (strcmp(param, "4k") == 0)
		*dest = DSIZ_4K;
	else if (strcmp(param, "16k") == 0)
		*dest = DSIZ_16K;
	else if (strcmp(param, "64k") == 0)
		*dest = DSIZ_64K;
	else if (strcmp(param, "1m") == 0)
		*dest = DSIZ_1M;
	else if (strcmp(param, "16m") == 0)
		*dest = DSIZ_16M;
	else if (strcmp(param, "256m") == 0)
		*dest = DSIZ_256M;
	else if (strcmp(param, "1g") == 0)
		*dest = DSIZ_1G;
	else
		return ERROR_COMMAND_ARGUMENT_INVALID;

	return ERROR_OK;
}

static int parse_tlb_command_params(unsigned argc, const char *argv[], struct tlb_command_params *params)
{
	unsigned arg_index;
	const char* arg;
	const char* p;
	char cmd[64];
	int ret;

	memset(params, 0, sizeof *params);
	params->dsiz = DSIZ_4K;
	params->way = -1;

	for (arg_index = 0; arg_index < argc; ++arg_index) {
		arg = argv[arg_index];

		p = strchr(arg, '=');
		if (p == NULL)
			return ERROR_COMMAND_ARGUMENT_INVALID;

		if ((size_t)(p - arg) >= sizeof cmd)
			return ERROR_COMMAND_ARGUMENT_INVALID;
		memset(cmd, 0, sizeof cmd);
		memcpy(cmd, arg, p - arg);
		++p;

		if (strcmp(cmd, "epn") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_EPN, 0xFFFFF, p, &params->mask, &params->epn);
		else if (strcmp(cmd, "rpn") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_RPN, 0xFFFFF, p, &params->mask, &params->rpn);
		else if (strcmp(cmd, "erpn") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_ERPN, 0x3FF, p, &params->mask, &params->erpn);
		else if (strcmp(cmd, "tid") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_TID, 0xFFFF, p, &params->mask, &params->tid);
		else if (strcmp(cmd, "ts") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_TS, 1, p, &params->mask, &params->ts);
		else if (strcmp(cmd, "il1i") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_IL1I, 1, p, &params->mask, &params->il1i);
		else if (strcmp(cmd, "il1d") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_IL1D, 1, p, &params->mask, &params->il1d);
		else if (strcmp(cmd, "u") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_U, 0xF, p, &params->mask, &params->u);
		else if (strcmp(cmd, "wimg") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_WIMG, 0xF, p, &params->mask, &params->wimg);
		else if (strcmp(cmd, "uxwr") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_UXWR, 0x7, p, &params->mask, &params->uxwr);
		else if (strcmp(cmd, "sxwr") == 0)
			ret = parse_uint32_params(TLB_PARAMS_MASK_SXWR, 0x7, p, &params->mask, &params->sxwr);
		else if (strcmp(cmd, "dsiz") == 0)
			ret = parse_dsiz_params(TLB_PARAMS_MASK_DSIZ, p, &params->mask, &params->dsiz);
		else if (strcmp(cmd, "en") == 0) {
			if ((params->mask & TLB_PARAMS_MASK_EN) != 0)
				ret = ERROR_COMMAND_ARGUMENT_INVALID;
			else {
				params->mask |= TLB_PARAMS_MASK_EN;
				if (strcmp(p, "LE") == 0) {
					params->en = 1;
					ret = ERROR_OK;
				} else
					ret = strcmp(p, "BE") == 0 ? ERROR_OK : ERROR_COMMAND_ARGUMENT_INVALID;
			}
		}
		else if (strcmp(cmd, "way") == 0) {
			if ((params->mask & TLB_PARAMS_MASK_WAY) != 0)
				ret = ERROR_COMMAND_ARGUMENT_INVALID;
			else {
				if (strcmp(p, "auto") == 0) {
					params->mask |= TLB_PARAMS_MASK_WAY;
					params->way = -1;
					ret = ERROR_OK;
				} else
					ret = parse_uint32_params(TLB_PARAMS_MASK_WAY, 0x3, p, &params->mask, (uint32_t*)&params->way);
			}
		}
		else
			ret = ERROR_COMMAND_ARGUMENT_INVALID;

		if (ret != ERROR_OK)
			return ret;		
	}

	return ERROR_OK;
}

static int handle_tlb_dump_command_internal(struct command_invocation *cmd, struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct tlb_sort_record records[TLB_NUMBER];
	uint32_t saved_MMUCR;
	uint32_t value_SSPCR;
	uint32_t value_USPCR;
	int i;
	int record_count;
	int ret;

	// save MMUCR
	ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, &saved_MMUCR);
	if (ret != ERROR_OK)
		return ret;

	// load all uncached TLBs
	for (i = 0; i < TLB_NUMBER; ++i) {
		keep_alive();
		ret = load_uncached_tlb(target, i);
		if (ret != ERROR_OK)
			return ret;
	}

	ret = read_spr_reg(target, SPR_REG_NUM_SSPCR, &value_SSPCR);
	if (ret != ERROR_OK)
		return ret;
	ret = read_spr_reg(target, SPR_REG_NUM_USPCR, &value_USPCR);
	if (ret != ERROR_OK)
		return ret;

	// restore MMUCR
	ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
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

	// process only valid records
	record_count = 0;
	for (i = 0; i < TLB_NUMBER; ++i) {
		if ((ppc476fs->tlb_cache[i].hw.data[0] & TLB_0_V_MASK) != 0) {
			records[record_count].index_way = i;
			records[record_count++].hw = ppc476fs->tlb_cache[i].hw;
		}
	}

	qsort(records, record_count, sizeof(struct tlb_sort_record), compare_tlb_record);

	print_tlb_table_header(CMD);
	for (i = 0; i < record_count; ++i) {
		print_tlb_table_record(CMD, records[i].index_way, &records[i].hw);
	}
	command_print(CMD, "SSPCR = 0x%08X, USPCR = 0x%08X", value_SSPCR, value_USPCR);

	return ERROR_OK;
}

static int handle_tlb_create_command_internal(struct command_invocation *cmd, struct target *target, struct tlb_command_params *params)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct tlb_hw_record hw;
	uint32_t saved_MMUCR;
	int index;
	int way;
	int index_way;
	int ret;

	// save MMUCR
	ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, &saved_MMUCR);
	if (ret != ERROR_OK)
		return ret;

	switch (params->dsiz)
	{
	case DSIZ_4K:
		index = (params->tid & 0xFF) ^ (params->epn & 0xFF) ^ ((params->epn >> 4) & 0xF0) ^ ((params->epn >> 12) & 0xFF);
		break;
	case DSIZ_16K:
		index = (params->tid & 0xFF) ^ ((params->epn >> 2) & 0xFF) ^ ((params->epn >> 4) & 0xC0) ^ ((params->epn >> 12) & 0xFF);
		break;
	case DSIZ_64K:
		index = (params->tid & 0xFF) ^ ((params->epn >> 4) & 0xFF) ^ ((params->epn >> 12) & 0xFF);
		break;
	case DSIZ_1M:
		index = (params->tid & 0xFF) ^ ((params->epn >> 8) & 0xFF) ^ ((params->epn >> 12) & 0xF0);
		break;
	case DSIZ_16M:
		index = (params->tid & 0xFF) ^ ((params->epn >> 12) & 0xFF);
		break;
	case DSIZ_256M:
		index = (params->tid & 0xFF) ^ ((params->epn >> 12) & 0xF0);
		break;
	case DSIZ_1G:
		index = (params->tid & 0xFF) ^ ((params->epn >> 12) & 0xC0);
		break;
	default:
		assert(false);
	}

	way = params->way;
	if (way == -1) {
		for (way = 0; way < 4; ++way) {
			index_way = (index << 2) | way;
			ret = load_uncached_tlb(target, index_way);
			if (ret != ERROR_OK)
				return ret;
			if ((ppc476fs->tlb_cache[index_way].hw.data[0] & TLB_0_V_MASK) == 0)
				break;
		}
		if (way > 3) {
			LOG_ERROR("there is no free way for the UTLB record");
			return ERROR_FAIL;
		}
	}

	index_way = (index << 2) | way;
	ret = load_uncached_tlb(target, index_way);
	if (ret != ERROR_OK)
		return ret;
	if ((ppc476fs->tlb_cache[index_way].hw.data[0] & TLB_0_V_MASK) != 0) {
			LOG_ERROR("the defined way is not free");
			return ERROR_FAIL;
	}

	hw.data[0] = TLB_0_V_MASK;
	set_bits_32(params->epn, TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN, &hw.data[0]);
	if (params->ts != 0)
		hw.data[0] |= TLB_0_TS_MASK;
	set_bits_32(params->dsiz, TLB_0_DSIZ_BIT_POS, TLB_0_DSIZ_BIT_LEN, &hw.data[0]);

	hw.data[1] = 0;
	set_bits_32(params->rpn, TLB_1_RPN_BIT_POS, TLB_1_RPN_BIT_LEN, &hw.data[1]);
	set_bits_32(params->erpn, TLB_1_ERPN_BIT_POS, TLB_1_ERPN_BIT_LEN, &hw.data[1]);

	hw.data[2] = 0;
	if (params->il1i != 0)
		hw.data[2] |= TLB_2_IL1I_MASK;
	if (params->il1d != 0)
		hw.data[2] |= TLB_2_IL1D_MASK;
	set_bits_32(params->u, TLB_2_U_BIT_POS, TLB_2_U_BIT_LEN, &hw.data[2]);
	set_bits_32(params->wimg, TLB_2_WIMG_BIT_POS, TLB_2_WIMG_BIT_LEN, &hw.data[2]);
	if (params->en != 0)
		hw.data[2] |= TLB_2_EN_MASK;
	set_bits_32(params->uxwr, TLB_2_UXWR_BIT_POS, TLB_2_UXWR_BIT_LEN, &hw.data[2]);
	set_bits_32(params->sxwr, TLB_2_SXWR_BIT_POS, TLB_2_SXWR_BIT_LEN, &hw.data[2]);

	hw.tid = params->tid;

	ret = write_tlb(target, index_way, &hw);
	if (ret != ERROR_OK)
		return ret;

	// syncing
	ret = stuff_code(target, 0x4C00012C); // isync
	if (ret != ERROR_OK)
		return ret;

	// invalidate and reload UTLB record
	ppc476fs->tlb_cache[index_way].loaded = false;
	ret = load_uncached_tlb(target, index_way);
	if (ret != ERROR_OK)
		return ret;

	print_tlb_table_header(CMD);
	print_tlb_table_record(CMD, index_way, &ppc476fs->tlb_cache[index_way].hw);

	// restore MMUCR
	ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
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

static int handle_tlb_drop_command_internal(struct command_invocation *cmd, struct target *target, struct tlb_command_params *params)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct tlb_hw_record hw;
	uint32_t saved_MMUCR;
	uint32_t ts;
	int index_way;
	int count = 0;
	int ret;

	// save MMUCR
	ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, &saved_MMUCR);
	if (ret != ERROR_OK)
		return ret;

	memset(&hw, 0, sizeof hw);

	for (index_way = 0; index_way < TLB_NUMBER; ++index_way) {
		keep_alive();
		ret = load_uncached_tlb(target, index_way);
		if (ret != ERROR_OK)
			return ret;

		if ((ppc476fs->tlb_cache[index_way].hw.data[0] & TLB_0_V_MASK) == 0)
			continue;
		if (ppc476fs->tlb_cache[index_way].hw.tid != params->tid)
			continue;
		if (get_bits_32(ppc476fs->tlb_cache[index_way].hw.data[0], TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN) != params->epn)
			continue;
		ts = ((ppc476fs->tlb_cache[index_way].hw.data[0] & TLB_0_TS_MASK) != 0);
		if (ts != params->ts)
			continue;

		ppc476fs->tlb_cache[index_way].loaded = false;
		ret = write_tlb(target, index_way, &hw);
		if (ret != ERROR_OK)
			return ret;

		// syncing
		ret = stuff_code(target, 0x4C00012C); // isync
		if (ret != ERROR_OK)
			return ret;

		if (count == 0)
			print_tlb_table_header(CMD);
		print_tlb_table_record(CMD, index_way, &ppc476fs->tlb_cache[index_way].hw);
		++count;
	}

	// restore MMUCR
	ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
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

	if (count == 0)
		command_print(CMD, "No UTLB records have been found");
	else
		command_print(CMD, "The UTLB records above have been deleted (%i)", count);

	return ERROR_OK;
}

static int handle_tlb_drop_all_command_internal(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	struct tlb_hw_record hw;
	uint32_t saved_MMUCR;
	int i;
	int ret;

	ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, &saved_MMUCR);
	if (ret != ERROR_OK)
		return ret;

	invalidate_tlb_cache(target);

	memset(&hw, 0, sizeof hw);

	for (i = 0; i < TLB_NUMBER; ++i) {
		keep_alive();
		ret = write_tlb(target, i, &hw);
		if (ret != ERROR_OK)
			return ret;
	}

	// syncing
	ret = stuff_code(target, 0x4C00012C); // isync
	if (ret != ERROR_OK)
		return ret;

	// restore MMUCR
	ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
	if (ret != ERROR_OK)
		return ret;

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	// restore R1
	ret = write_gpr_reg(target, 1, ppc476fs->saved_R1);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int ppc476fs_poll(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	enum target_state prev_state = target->state;
	uint32_t JDSR_value, DBSR_value;
	int ret;

	// LOG_DEBUG("coreid=%i, cores %i %i", target->coreid, target->gdb_service->core[0], target->gdb_service->core[1]);

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
			if (((DBSR_value & DBSR_IAC_ALL_MASK) != 0) && ((DBSR_value & DBSR_DAC_ALL_MASK) != 0))
				target->debug_reason = DBG_REASON_WPTANDBKPT; // watchpoints and breakpoints
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

	LOG_USER("target halted due to %s, coreid=%i, PC: 0x%08X",
		debug_reason_name(target),
		target->coreid,
		get_reg_value_32(ppc476fs->PC_reg));

	return ERROR_OK;
}

static int ppc476fs_halt(struct target *target)
{
	int ret;

	LOG_DEBUG("coreid=%i", target->coreid);

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
	LOG_DEBUG("coreid=%i", target->coreid);

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
	LOG_DEBUG("coreid=%i", target->coreid);

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
	LOG_DEBUG("coreid=%i", target->coreid);

	if (target->reset_halt) {
		LOG_ERROR("Device does not support 'reset halt' command");
		return ERROR_FAIL;
	}

	return ERROR_OK;
}

static int ppc476fs_deassert_reset(struct target *target)
{
	int ret;

	LOG_DEBUG("coreid=%i", target->coreid);

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
	
	LOG_DEBUG("coreid=%i", target->coreid);

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
	uint32_t i;
	int ret;

	LOG_DEBUG("coreid=%i, address: 0x%lX, size: %u, count: 0x%X", target->coreid, address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3)) || ((size == 2) && (address & 0x1))) {
		LOG_ERROR("unaligned access");
		return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	memset(buffer, 0, size * count); // clear result buffer

	for (i = 0; i < count; ++i) {
		keep_alive();
		ret = read_virt_mem(target, (uint32_t)address, size, buffer);
		if (ret != ERROR_OK)
			return ret;

		address += size;
		buffer += size;
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
	uint32_t i;
	int ret;

	LOG_DEBUG("coreid=%i, address=0x%lX, size=%u, count=0x%X", target->coreid, address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u))) {
		LOG_ERROR("unaligned access");
		return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	for (i = 0; i < count; ++i) {
		keep_alive();
		add_write_virt_mem(target, (uint32_t)address, size, buffer);
		address += size;
		buffer += size;
	}

	// the JTAG queue will be executed druring the registers restoing

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

static int ppc476fs_checksum_memory(struct target *target, target_addr_t address, uint32_t count, uint32_t *checksum)
{
	return ERROR_FAIL;
}

static int ppc476fs_add_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	int ret;

	LOG_DEBUG("coreid=%i, address=0x%lX, type=%i, length=0x%X", target->coreid, breakpoint->address, breakpoint->type, breakpoint->length);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (breakpoint->length != 4)
		return ERROR_TARGET_UNALIGNED_ACCESS;

	if ((breakpoint->address & 0x3) != 0)
		return ERROR_TARGET_UNALIGNED_ACCESS;

	breakpoint->set = 0;
	memset(breakpoint->orig_instr, 0, 4);

	if (breakpoint->type == BKPT_HARD) {
		ret = add_hw_breakpoint(target, breakpoint);
		if (ret != ERROR_OK)
			return ret;
	}

	return ERROR_OK;
}

static int ppc476fs_remove_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;

	LOG_DEBUG("coreid=%i, address=0x%lX, type=%i, length=0x%X", target->coreid, breakpoint->address, breakpoint->type, breakpoint->length);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (breakpoint->set == 0)
		return ERROR_OK;

	if (breakpoint->type == BKPT_HARD) {
		ret = unset_hw_breakpoint(target, breakpoint);
		if (ret != ERROR_OK)
			return ret;
	} else {
		ret = unset_soft_breakpoint(target, breakpoint);
		if (ret != ERROR_OK)
			return ret;
		// restore R1
		ret = write_gpr_reg(target, 1, ppc476fs->saved_R1);
		if (ret != ERROR_OK)
			return ret;
	}

	// restore R2
	ret = write_gpr_reg(target, 2, ppc476fs->saved_R2);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int ppc476fs_add_watchpoint(struct target *target, struct watchpoint *watchpoint)
{
	struct watchpoint *wp;
	int wp_count;

	LOG_DEBUG("coreid=%i, address=0x%08lX, rw=%i, length=%u, value=0x%08X, mask=0x%08X",
		target->coreid, watchpoint->address, watchpoint->rw, watchpoint->length, watchpoint->value, watchpoint->mask);

	watchpoint->set = 0;

	if ((watchpoint->length != 1) && (watchpoint->length != 2) && (watchpoint->length != 4))
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	if (watchpoint->mask != 0xFFFFFFFF)
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	wp = target->watchpoints;
	wp_count = 0;
	while (wp != NULL) {
		if (wp != watchpoint) // do not count the added watchpoint, it may be in the list
			++wp_count;
		wp = wp->next;
	}
	if (wp_count == WP_NUMBER)
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

	return ERROR_OK;
}

static int ppc476fs_remove_watchpoint(struct target *target, struct watchpoint *watchpoint)
{
	int ret;

	LOG_DEBUG("coreid=%i, address=0x%08lX, rw=%i, length=%u, value=0x%08X, mask=0x%08X",
		target->coreid, watchpoint->address, watchpoint->rw, watchpoint->length, watchpoint->value, watchpoint->mask);

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (watchpoint->set == 0)
		return ERROR_OK;

	ret = unset_watchpoint(target, watchpoint);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int ppc476fs_target_create(struct target *target, Jim_Interp *interp)
{
	struct ppc476fs_common *ppc476fs = calloc(1, sizeof(struct ppc476fs_common));
	target->arch_info = ppc476fs;

	LOG_DEBUG("coreid=%i", target->coreid);

	if ((target->coreid < 0) || (target->coreid > 1)) {
		LOG_ERROR("coreid=%i is not allowed. It must be 0 or 1. It has been set to 0.", target->coreid);
		target->coreid = 0;
	}

	return ERROR_OK;
}

static int ppc476fs_init_target(struct command_context *cmd_ctx, struct target *target)
{
	LOG_DEBUG("coreid=%i", target->coreid);

	build_reg_caches(target);

	if (target->tap->priv == NULL) {
		struct ppc476fs_tap_ext *tap_ext = malloc(sizeof(struct ppc476fs_tap_ext));
		tap_ext->last_coreid = -1;
		target->tap->priv = tap_ext;
		LOG_DEBUG("The TAP extera struct has been created, coreid=%i", target->coreid);
	}
	else {
		LOG_DEBUG("The TAP extra struct has already been created, coreid=%i", target->coreid);
	}

	return ERROR_OK;
}

static int ppc476fs_examine(struct target *target)
{
	int ret;

	LOG_DEBUG("coreid=%i", target->coreid);

	ret = examine_internal(target);
	if (ret != ERROR_OK) {
		LOG_ERROR("Device has not been examined (error code = %i)", ret);
		return ret;
	}

	target_set_examined(target);

	return ERROR_OK;
}

static int ppc476fs_virt2phys(struct target *target, target_addr_t address, target_addr_t *physical)
{
	LOG_DEBUG("coreid=%i", target->coreid);

	*physical = 0;

	return ERROR_TARGET_TRANSLATION_FAULT;
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG communication BUG
static int ppc476fs_read_phys_memory(struct target *target, target_addr_t address, uint32_t size, uint32_t count, uint8_t *buffer)
{
	struct phys_mem_state state;
	uint32_t last_ERPN_RPN = -1; // not setuped yet 
	uint32_t new_ERPN_RPN;
	uint32_t i;
	int ret;

	LOG_DEBUG("coreid=%i, address=0x%lX, size=%u, count=0x%X", target->coreid, address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3)) || ((size == 2) && (address & 0x1))) {
		LOG_ERROR("unaligned access");
		return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	memset(buffer, 0, size * count); // clear result buffer

	ret = init_phys_mem(target, &state);
	if (ret != ERROR_OK)
		return ret;

	for (i = 0; i < count; ++i) {
		keep_alive();

		new_ERPN_RPN = (address >> 12) & 0x3FFC0000;
		if (new_ERPN_RPN != last_ERPN_RPN) {
			ret = access_phys_mem(target, new_ERPN_RPN);
			if (ret != ERROR_OK)
				return ret;
			last_ERPN_RPN = new_ERPN_RPN;
		}

		ret = read_virt_mem(target, (uint32_t)(address & 0x3FFFFFFF) + PHYS_MEM_BASE_ADDR, size, buffer);
		if (ret != ERROR_OK)
			return ret;

		address += size;
		buffer += size;
	}

	// restore state
	ret = restore_phys_mem(target, &state);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG communication BUG
static int ppc476fs_write_phys_memory(struct target *target, target_addr_t address, uint32_t size, uint32_t count, const uint8_t *buffer)
{
	struct phys_mem_state state;
	uint32_t last_ERPN_RPN = -1; // not setuped yet 
	uint32_t new_ERPN_RPN;
	uint32_t i;
	int ret;

	LOG_DEBUG("coreid=%i, address=0x%lX, size=%u, count=0x%X", target->coreid, address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u))) {
		LOG_ERROR("unaligned access");
		return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	ret = init_phys_mem(target, &state);
	if (ret != ERROR_OK)
		return ret;

	for (i = 0; i < count; ++i) {
		new_ERPN_RPN = (address >> 12) & 0x3FFC0000;
		if (new_ERPN_RPN != last_ERPN_RPN) {
			ret = access_phys_mem(target, new_ERPN_RPN);
			if (ret != ERROR_OK)
				return ret;
			last_ERPN_RPN = new_ERPN_RPN;
		}

		keep_alive();
		add_write_virt_mem(target, (uint32_t)(address & 0x3FFFFFFF) + PHYS_MEM_BASE_ADDR, size, buffer);
		address += size;
		buffer += size;
	}

	// the JTAG queue will be executed during the state restoring

	// restore state
	ret = restore_phys_mem(target, &state);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int ppc476fs_mmu(struct target *target, int *enabled)
{
	*enabled = 1;
	return ERROR_OK;
}

COMMAND_HANDLER(ppc476fs_handle_tlb_dump_command)
{
	struct target *target = get_current_target(CMD_CTX);
	int ret;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	ret = handle_tlb_dump_command_internal(CMD, target);
	if (ret != ERROR_OK) {
		LOG_ERROR("error executing the command %i", ret);
		return ret;
	}

	return ERROR_OK;
}

COMMAND_HANDLER(ppc476fs_handle_tlb_create_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct tlb_command_params params;
	int ret;

	ret = parse_tlb_command_params(CMD_ARGC, CMD_ARGV, &params);
	if (ret != ERROR_OK) {
		LOG_ERROR("parameter parse error");
		return ret;
	}

	if ((params.mask & TLB_PARAMS_MASK_EPN) == 0) {
		LOG_ERROR("parameter 'epn' is not defined");
		return ERROR_COMMAND_ARGUMENT_INVALID;
	}

	if ((params.mask & TLB_PARAMS_MASK_RPN) == 0) {
		LOG_ERROR("parameter 'rpn' is not defined");
		return ERROR_COMMAND_ARGUMENT_INVALID;
	}

	ret = handle_tlb_create_command_internal(CMD, target, &params);
	if (ret != ERROR_OK) {
		LOG_ERROR("error executing the command %i", ret);
		return ret;
	}

	return ERROR_OK;
}

COMMAND_HANDLER(ppc476fs_handle_tlb_drop_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct tlb_command_params params;
	int ret;

	ret = parse_tlb_command_params(CMD_ARGC, CMD_ARGV, &params);
	if (ret != ERROR_OK) {
		LOG_ERROR("parameter parse error");
		return ret;
	}

	if ((params.mask & TLB_PARAMS_MASK_EPN) == 0) {
		LOG_ERROR("parameter 'epn' is not defined");
		return ERROR_COMMAND_ARGUMENT_INVALID;
	}

	if ((params.mask & ~(TLB_PARAMS_MASK_EPN | TLB_PARAMS_MASK_TID | TLB_PARAMS_MASK_TS)) != 0) {
		LOG_ERROR("only parameters 'epn', 'tid' and 'ts' can be defined");
		return ERROR_COMMAND_ARGUMENT_INVALID;
	}

	ret = handle_tlb_drop_command_internal(CMD, target, &params);
	if (ret != ERROR_OK) {
		LOG_ERROR("error executing the command %i", ret);
		return ret;
	}

	return ERROR_OK;
}

COMMAND_HANDLER(ppc476fs_handle_tlb_drop_all_command)
{
	struct target *target = get_current_target(CMD_CTX);
	int ret;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	ret = handle_tlb_drop_all_command_internal(target);
	if (ret != ERROR_OK) {
		LOG_ERROR("error executing the command %i", ret);
		return ret;
	}

	command_print(CMD, "All UTLB records have been deleted");

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
	int64_t start_time = timeval_ms();
	uint32_t count = 0;
	uint32_t dummy_data;
	int ret;

	while (timeval_ms() - start_time < 1000) {
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

static const struct command_registration ppc476fs_tlb_drop_command_handlers[] = {
	{
		.name = "all",
		.handler = ppc476fs_handle_tlb_drop_all_command,
		.mode = COMMAND_EXEC,
		.usage = "",
		.help = "delete all UTLB records"
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration ppc476fs_tlb_exec_command_handlers[] = {
	{
		.name = "dump",
		.handler = ppc476fs_handle_tlb_dump_command,
		.mode = COMMAND_EXEC,
		.usage = "",
		.help = "dump all valid UTLB records"
	},
	{
		.name = "create",
		.handler = ppc476fs_handle_tlb_create_command,
		.mode = COMMAND_EXEC,
		.usage = "epn=<xxx> rpn=<xxx> [erpn=0] [tid=0] [ts=0] [dsiz=4k] [way=auto] [bltd=0] [il1i=0] [il1d=0] [u=0] [wimg=0] [en=BE] [uxwr=0] [sxwr=0]",
		.help = "create new UTLB record"
	},
	{
		.name = "drop",
		.handler = ppc476fs_handle_tlb_drop_command,
		.mode = COMMAND_EXEC,
		.usage = "epn=<xxx> [tid=0] [ts=0]",
		.help = "delete UTLB record",
		.chain = ppc476fs_tlb_drop_command_handlers
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration ppc476fs_exec_command_handlers[] = {
	{
		.name = "tlb",
		.handler = ppc476fs_handle_tlb_dump_command,
		.mode = COMMAND_EXEC,
		.usage = "",
		.help = "ppc476fs tlb command group",
		.chain = ppc476fs_tlb_exec_command_handlers
	},
	{
		.name = "status",
		.handler = ppc476fs_handle_status_command,
		.mode = COMMAND_EXEC,
		.usage = "",
		.help = "display status"
	},
	{
		.name = "jtag_speed",
		.handler = ppc476fs_handle_jtag_speed_command,
		.mode = COMMAND_EXEC,
		.usage = "",
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

	.checksum_memory = ppc476fs_checksum_memory,

	.add_breakpoint = ppc476fs_add_breakpoint,
	.remove_breakpoint = ppc476fs_remove_breakpoint,
	.add_watchpoint = ppc476fs_add_watchpoint,
	.remove_watchpoint = ppc476fs_remove_watchpoint,

	.commands = ppc476fs_command_handlers,
	.target_create = ppc476fs_target_create,
	.init_target = ppc476fs_init_target,
	.examine = ppc476fs_examine,

	.virt2phys = ppc476fs_virt2phys,
	.read_phys_memory = ppc476fs_read_phys_memory,
	.write_phys_memory = ppc476fs_write_phys_memory,
	.mmu = ppc476fs_mmu
};
