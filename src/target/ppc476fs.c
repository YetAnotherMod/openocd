#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/jtag.h>
#include <target/target.h>
#include <target/target_type.h>
#include <target/register.h>
#include <target/breakpoints.h>
#include <helper/log.h>

#define JDSR_PSP_MASK (1 << (31 - 31))

#define JDCR_STO_MASK (1 << (31 - 0))
#define JDCR_SS_MASK (1 << (31 - 2))
#define JDCR_RSDBSR_MASK (1 << (31 - 8))

#define DBCR0_EDM_MASK (1 << (63 - 32))
#define DBCR0_IAC1_MASK (1 << (63 - 40))
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

struct ppc476fs_common {
	uint32_t DBCR0_value;
};

enum ppc476fs_reg_arch_type
{
	PPC476FS_REG_TYPE_GPR, // reg_arch_opcode - GPR register number
	PPC476FS_REG_TYPE_FPR, // reg_arch_opcode - FPU register number
	PPC476FS_REG_TYPE_SPR, // reg_arch_opcode - register code for mfspr/mtspr commmands
	PPC476FS_REG_TYPE_IAR, // reg_arch_opcode is not used
	PPC476FS_REG_TYPE_MSR, // reg_arch_opcode is not used
	PPC476FS_REG_TYPE_CR, // reg_arch_opcode is not used
	PPC476FS_REG_TYPE_FPSCR // reg_arch_opcode is not used
};

struct ppc476fs_reg_info
{
	char *name;
	size_t gdb_numb;
	enum reg_type type;
	int bit_size;
	enum ppc476fs_reg_arch_type reg_arch_type;
	uint32_t reg_arch_opcode;
	char *feature;
};

// index of the item equals DGB register number
static const struct ppc476fs_reg_info reg_info[] = {
	{ "R0", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 0, "org.gnu.gdb.power.core" },
	{ "R1", 1, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 1, "org.gnu.gdb.power.core" },
	{ "R2", 2, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 2, "org.gnu.gdb.power.core" },
	{ "R3", 3, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 3, "org.gnu.gdb.power.core" },
	{ "R4", 4, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 4, "org.gnu.gdb.power.core" },
	{ "R5", 5, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 5, "org.gnu.gdb.power.core" },
	{ "R6", 6, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 6, "org.gnu.gdb.power.core" },
	{ "R7", 7, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 7, "org.gnu.gdb.power.core" },
	{ "R8", 8, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 8, "org.gnu.gdb.power.core" },
	{ "R9", 9, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 9, "org.gnu.gdb.power.core" },
	{ "R10", 10, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 10, "org.gnu.gdb.power.core" },
	{ "R11", 11, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 11, "org.gnu.gdb.power.core" },
	{ "R12", 12, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 12, "org.gnu.gdb.power.core" },
	{ "R13", 13, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 13, "org.gnu.gdb.power.core" },
	{ "R14", 14, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 14, "org.gnu.gdb.power.core" },
	{ "R15", 15, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 15, "org.gnu.gdb.power.core" },
	{ "R16", 16, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 16, "org.gnu.gdb.power.core" },
	{ "R17", 17, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 17, "org.gnu.gdb.power.core" },
	{ "R18", 18, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 18, "org.gnu.gdb.power.core" },
	{ "R19", 19, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 19, "org.gnu.gdb.power.core" },
	{ "R20", 20, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 20, "org.gnu.gdb.power.core" },
	{ "R21", 21, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 21, "org.gnu.gdb.power.core" },
	{ "R22", 22, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 22, "org.gnu.gdb.power.core" },
	{ "R23", 23, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 23, "org.gnu.gdb.power.core" },
	{ "R24", 24, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 24, "org.gnu.gdb.power.core" },
	{ "R25", 25, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 25, "org.gnu.gdb.power.core" },
	{ "R26", 26, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 26, "org.gnu.gdb.power.core" },
	{ "R27", 27, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 27, "org.gnu.gdb.power.core" },
	{ "R28", 28, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 28, "org.gnu.gdb.power.core" },
	{ "R29", 29, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 29, "org.gnu.gdb.power.core" },
	{ "R30", 30, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 30, "org.gnu.gdb.power.core" },
	{ "R31", 31, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 31, "org.gnu.gdb.power.core" },
	{ "F0", 32, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 0, "org.gnu.gdb.power.fpu" },
	{ "F1", 33, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 1, "org.gnu.gdb.power.fpu"  },
	{ "F2", 34, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 2, "org.gnu.gdb.power.fpu"  },
	{ "F3", 35, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 3, "org.gnu.gdb.power.fpu"  },
	{ "F4", 36, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 4, "org.gnu.gdb.power.fpu"  },
	{ "F5", 37, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 5, "org.gnu.gdb.power.fpu"  },
	{ "F6", 38, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 6, "org.gnu.gdb.power.fpu"  },
	{ "F7", 39, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 7, "org.gnu.gdb.power.fpu"  },
	{ "F8", 40, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 8, "org.gnu.gdb.power.fpu"  },
	{ "F9", 41, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 9, "org.gnu.gdb.power.fpu"  },
	{ "F10", 42, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 10, "org.gnu.gdb.power.fpu"  },
	{ "F11", 43, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 11, "org.gnu.gdb.power.fpu"  },
	{ "F12", 44, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 12, "org.gnu.gdb.power.fpu"  },
	{ "F13", 45, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 13, "org.gnu.gdb.power.fpu"  },
	{ "F14", 46, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 14, "org.gnu.gdb.power.fpu"  },
	{ "F15", 47, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 15, "org.gnu.gdb.power.fpu"  },
	{ "F16", 48, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 16, "org.gnu.gdb.power.fpu"  },
	{ "F17", 49, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 17, "org.gnu.gdb.power.fpu"  },
	{ "F18", 50, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 18, "org.gnu.gdb.power.fpu"  },
	{ "F19", 51, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 19, "org.gnu.gdb.power.fpu"  },
	{ "F20", 52, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 20, "org.gnu.gdb.power.fpu"  },
	{ "F21", 53, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 21, "org.gnu.gdb.power.fpu"  },
	{ "F22", 54, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 22, "org.gnu.gdb.power.fpu"  },
	{ "F23", 55, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 23, "org.gnu.gdb.power.fpu"  },
	{ "F24", 56, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 24, "org.gnu.gdb.power.fpu"  },
	{ "F25", 57, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 25, "org.gnu.gdb.power.fpu"  },
	{ "F26", 58, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 26, "org.gnu.gdb.power.fpu"  },
	{ "F27", 59, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 27, "org.gnu.gdb.power.fpu"  },
	{ "F28", 60, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 28, "org.gnu.gdb.power.fpu"  },
	{ "F29", 61, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 29, "org.gnu.gdb.power.fpu"  },
	{ "F30", 62, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 30, "org.gnu.gdb.power.fpu"  },
	{ "F31", 63, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 31, "org.gnu.gdb.power.fpu"  },
	{ "PC", 64, REG_TYPE_CODE_PTR, 32, PPC476FS_REG_TYPE_IAR, 0, "org.gnu.gdb.power.core" },
	{ "MSR", 65, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_MSR, 0, "org.gnu.gdb.power.core" },
	{ "CR", 66, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_CR, 0, "org.gnu.gdb.power.core" },
	{ "LR", 67, REG_TYPE_CODE_PTR, 32, PPC476FS_REG_TYPE_SPR, 8, "org.gnu.gdb.power.core" },
	{ "CTR", 68, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 9, "org.gnu.gdb.power.core" },
	{ "XER", 69, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 1, "org.gnu.gdb.power.core" },
	{ "FPSCR", 70, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_FPSCR, 0, "org.gnu.gdb.power.fpu"  }
};

#define REG_INFO_COUNT (sizeof reg_info / sizeof reg_info[0])
#define REG_GDB_COUNT 70

// ???
static const struct ppc476fs_reg_info DBCR0_data = {
	"DBCR0", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 308, NULL
};
static const struct ppc476fs_reg_info DBCR1_data = {
	"DBCR1", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 309, NULL
};
static const struct ppc476fs_reg_info DBCR2_data = {
	"DBCR2", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 310, NULL
};
static const struct ppc476fs_reg_info DBSR_data = {
	"DBSR", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 304, NULL
};
static const struct ppc476fs_reg_info IACx_data[4] = {
	{ "IAC1", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 312, NULL },
	{ "IAC2", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 313, NULL },
	{ "IAC3", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 314, NULL },
	{ "IAC4", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 315, NULL },
};

static int ppc476fs_get_reg(struct reg *reg);
static int ppc476fs_set_reg(struct reg *reg, uint8_t *buf);
static int ppc476fs_get_dummy_reg(struct reg *reg);
static int ppc476fs_set_dummy_reg(struct reg *reg, uint8_t *buf);

static const struct reg_arch_type ppc476fs_reg_type = {
	.get = ppc476fs_get_reg,
	.set = ppc476fs_set_reg
};

static const struct reg_arch_type ppc476fs_dummy_reg_type = {
	.get = ppc476fs_get_dummy_reg,
	.set = ppc476fs_set_dummy_reg
};

static struct reg dummy_reg = {
	.type = &ppc476fs_dummy_reg_type
};

static inline struct ppc476fs_common *target_to_ppc476fs(struct target *target)
{
	return target->arch_info;
}





// ??? ===============================================================================

static int jtag_read_write_register(struct target *target, uint32_t instr, uint32_t valid_bit, uint32_t write_data, uint32_t *read_data)
{
	struct scan_field field;
	struct scan_field fields[2];
	uint8_t instr_buffer[4];
	uint8_t data_out_buffer[4];
	uint8_t data_in_buffer[4];
	uint8_t valid_buffer[4];
	int ret;

	buf_set_u32(instr_buffer, 0, target->tap->ir_length, instr);
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
	return jtag_read_write_register(target, 0x2C, 0, 0, data); // 0b0101100
}

static int write_JDCR(struct target *target, uint32_t data)
{
	int ret;

	ret = jtag_read_write_register(target, 0x2C, 1, data, NULL); // 0b0101100
	if (ret != ERROR_OK)
		return ret;

	// !!! IMPORTANT
	// make additional write_JDCR/read_JDSR request with valid bit == 0
	// to correct a JTAG communication BUG
	return jtag_read_write_register(target, 0x2C, 0, 0, NULL); // 0b0101100
}

static int stuff_code(struct target *target, uint32_t code)
{
	int ret;

	assert(target->state == TARGET_HALTED);

	ret =  jtag_read_write_register(target, 0x3C, 1, code, NULL); // 0b0111100
	if (ret != ERROR_OK)
		return ret;

	// !!! IMPORTANT
	// make additional write_JISB/read_JDSR request with valid bit == 0
	// to correct a JTAG communication BUG
	return jtag_read_write_register(target, 0x3C, 0, 0, NULL); // 0b0111100
}

static int read_DBDR(struct target *target, uint32_t *data)
{
	return jtag_read_write_register(target, 0x5C, 0, 0, data); // 0b1011100
}

static int write_DBDR(struct target *target, uint32_t data)
{
	int ret;

	assert(target->state == TARGET_HALTED);

	ret = jtag_read_write_register(target, 0x5C, 1, data, NULL); // 0b1011100
	if (ret != ERROR_OK)
		return ret;

	// !!! IMPORTANT
	// make additional write_DBDR/read_DBDR request with valid bit == 0
	// to correct a JTAG communication BUG
	return jtag_read_write_register(target, 0x5C, 0, 0, NULL); // 0b1011100
}


// ??? ===============================================================================







static struct reg *find_reg_by_name(struct target *target, const char *reg_name)
{
	struct reg_cache *cache = target->reg_cache;
	unsigned i;

	while (cache != NULL) {
		for (i = 0; i < cache->num_regs; ++i) {
			if (strcmp(cache->reg_list[i].name, reg_name) == 0)
				return &cache->reg_list[i];
		}
		cache = cache->next;
	}

	assert(false);

	return NULL;
}

// ??? inline
static int read_reg_by_code(struct target *target, uint32_t code, void *data) // ??? name
{
	int ret;

	assert(target->state == TARGET_HALTED);

	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	return read_DBDR(target, data);
}

// ??? inline
static int write_reg_by_code(struct target *target, uint32_t code, uint32_t data) // ??? name
{
	int ret;

	assert(target->state == TARGET_HALTED);

	ret = write_DBDR(target, data);
	if (ret != ERROR_OK)
		return ret;

	return stuff_code(target, code);
}

static int read_cpu_reg(struct target *target, const struct ppc476fs_reg_info *reg_data, void *data);
static int write_cpu_reg(struct target *target, const struct ppc476fs_reg_info *reg_data, const void *data);

// MSR, R1(SP), R2 are already saved, and R1(SP) is correct aligned // ???? about R1
static int read_fpu_reg(struct target *target, uint32_t msr_value, uint32_t reg_number, void *data)
{
	const struct ppc476fs_reg_info *temp_reg_data_2 = &reg_info[find_reg_by_name(target, "R2")->number]; // ??? name
	const struct ppc476fs_reg_info *temp_reg_data_3 = &reg_info[find_reg_by_name(target, "MSR")->number]; // ??? name
	uint32_t code, value, value_high, value_low;
	int ret;

	// ??? restore memory area

	ret = ERROR_OK; // ???

	// save magic numbers
	value = 0x83AFC410;
	ret = write_cpu_reg(target, temp_reg_data_2, &value); // ???
	if (ret != ERROR_OK)
		return ret;
	code = 0x9041FFF8; // stw R2, -8(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	value = 0x014CFA38;
	ret = write_cpu_reg(target, temp_reg_data_2, &value); // ???
	if (ret != ERROR_OK)
		return ret;
	code = 0x9041FFFC; // stw R2, -4(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	value = msr_value | MSR_FP_MASK; // ???
	ret = write_cpu_reg(target, temp_reg_data_3, &value); // ???
	if (ret != ERROR_OK)
		return ret;

	code = 0xD801FFF8 | (reg_number << 21); // stfd Fx, -8(r1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	code = 0x8041FFF8; // lwz R2, -8(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	ret  = read_cpu_reg(target, temp_reg_data_2, &value_high);
	if (ret != ERROR_OK)
		return ret;

	code = 0x8041FFFC; // lwz R2, -4(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	ret  = read_cpu_reg(target, temp_reg_data_2, &value_low);
	if (ret != ERROR_OK)
		return ret;

	if ((value_high == 0x83AFC410) && (value_low == 0x014CFA38)) // ??? const
		return ERROR_FAIL;

	memcpy(data, &value_high, 4);
	memcpy(data + 4, &value_low, 4);

	return ERROR_OK;
}

static int read_cpu_reg(struct target *target, const struct ppc476fs_reg_info *reg_data, void *data)
{
	int ret, main_ret;
	uint32_t code;
	uint32_t value; // ???
	uint32_t save_value, temp_value;
	uint32_t save_value_2; // ???
	uint32_t save_value_3; // ???
	uint64_t save_value_64; // ???
	uint64_t temp_value_64; // ???
	const struct ppc476fs_reg_info *temp_reg_data;
	const struct ppc476fs_reg_info *temp_reg_data_2;
	const struct ppc476fs_reg_info *temp_reg_data_3;

	assert(target->state == TARGET_HALTED);

	switch (reg_data->reg_arch_type) {
	case PPC476FS_REG_TYPE_GPR:
		code = 0x7C13FBA6 | (reg_data->reg_arch_opcode << 21); // mtdbdr Rx
		ret = read_reg_by_code(target, code, data);
		break;
	case PPC476FS_REG_TYPE_FPR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "R1")->number];
		temp_reg_data_2 = &reg_info[find_reg_by_name(target, "R2")->number];
		temp_reg_data_3 = &reg_info[find_reg_by_name(target, "MSR")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save R1 (stack)
		if (ret != ERROR_OK)
			break; // return all ???
		if ((save_value < 8) || ((save_value & 0x3) != 0)) // check stack pointer
			return ERROR_FAIL;
		ret = read_cpu_reg(target, temp_reg_data_2, &save_value_2); // save R2
		if (ret != ERROR_OK)
			break;
		ret = read_cpu_reg(target, temp_reg_data_3, &save_value_3); // save MSR
		if (ret != ERROR_OK)
		 	break;
		main_ret = read_fpu_reg(target, save_value_3, reg_data->reg_arch_opcode, data);
		ret = write_cpu_reg(target, temp_reg_data_3, &save_value_3); // restore MSR ??? optimize
		if (main_ret == ERROR_OK) // ???
		 	main_ret = ret;
		ret = write_cpu_reg(target, temp_reg_data_2, &save_value_2); // restore R2
		if (main_ret == ERROR_OK) // ???
			main_ret = ret;
		// ??? not need
		// ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore R1
		// if (main_ret == ERROR_OK) // ???
		// 	main_ret = ret;
		ret = main_ret;
		break;
	case PPC476FS_REG_TYPE_SPR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "R31")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save R31
		if (ret != ERROR_OK)
			break;
		code = 0x7FE002A6 | ((reg_data->reg_arch_opcode & 0x1F) << 16) | ((reg_data->reg_arch_opcode & 0x3E0) << (11 - 5)); // mfspr R31, spr
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = read_cpu_reg(target, temp_reg_data, data); // read R31
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore R31
		break;
	case PPC476FS_REG_TYPE_IAR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "LR")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save LR
		if (ret != ERROR_OK)
			break;
		code = 0x48000001; // bl $+0
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = read_cpu_reg(target, temp_reg_data, &temp_value); // read LR (it will contain the current IAR + 4)
		if (ret != ERROR_OK)
			break;
		temp_value -= 4; // correct the address
		buf_cpy(&temp_value, data, 32);
		ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore LR
		break;
	case PPC476FS_REG_TYPE_MSR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "R31")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save R31
		if (ret != ERROR_OK)
			break;
		code = 0x7FE000A6; // mfmsr R31
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = read_cpu_reg(target, temp_reg_data, data); // read R31
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore R31
		break;
	case PPC476FS_REG_TYPE_CR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "R31")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save R31
		if (ret != ERROR_OK)
			break;
		code = 0x7FE00026; // mfcr R31
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = read_cpu_reg(target, temp_reg_data, data); // read R31
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore R31
		break;
	case PPC476FS_REG_TYPE_FPSCR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "F0")->number];
		temp_reg_data_3 = &reg_info[find_reg_by_name(target, "MSR")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value_64); // save F0
		if (ret != ERROR_OK)
			return ret;
		ret = read_cpu_reg(target, temp_reg_data_3, &save_value_3); // save MSR
		if (ret != ERROR_OK)
			break;
		value = save_value_3 | MSR_FP_MASK; // ???
		ret = write_cpu_reg(target, temp_reg_data_3, &value); // ???
		if (ret != ERROR_OK)
			return ret;
		code = 0xFC00048E; // mffs F0
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = read_cpu_reg(target, temp_reg_data, &temp_value_64); // read F0
		if (ret != ERROR_OK)
			break;
		memcpy(data, ((void*)&temp_value_64) + 4, 4); // ???
		ret = write_cpu_reg(target, temp_reg_data_3, &save_value_3); // restore MSR ??? optimize
		if (ret != ERROR_OK) // ???
			return ret;
		ret = write_cpu_reg(target, temp_reg_data, &save_value_64); // restore R31
		break;
	default:
		assert(false);
	}

	return ret;
}

// MSR, R1(SP), R2 are already saved, and R1(SP) is correct aligned ??? about R1
static int write_fpu_reg(struct target *target, uint32_t msr_value, uint32_t reg_number, const void *data)
{
	const struct ppc476fs_reg_info *temp_reg_data_2 = &reg_info[find_reg_by_name(target, "R2")->number]; // ??? name
	const struct ppc476fs_reg_info *temp_reg_data_3 = &reg_info[find_reg_by_name(target, "MSR")->number]; // ??? name
	uint32_t code, value, value_high, value_low;
	int ret;

	// ??? restore memory area

	memcpy(&value_high, data, 4); // ???
	memcpy(&value_low, data + 4, 4); // ???*/

	value = value_high;
	ret = write_cpu_reg(target, temp_reg_data_2, &value); // ???
	if (ret != ERROR_OK)
		return ret;
	code = 0x9041FFF8; // stw R2, -8(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	code = 0x8041FFF8; // lfw R2, -8(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	ret  = read_cpu_reg(target, temp_reg_data_2, &value);
	if (ret != ERROR_OK)
		return ret;
	if (value != value_high)
		return ERROR_FAIL;


	value = value_low;
	ret = write_cpu_reg(target, temp_reg_data_2, &value); // ???
	if (ret != ERROR_OK)
		return ret;
	code = 0x9041FFFC; // stw R2, -4(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	code = 0x8041FFFC; // lfw R2, -4(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;
	ret  = read_cpu_reg(target, temp_reg_data_2, &value);
	if (ret != ERROR_OK)
		return ret;
	if (value != value_low)
		return ERROR_FAIL;

	value = msr_value | MSR_FP_MASK; // ???
	ret = write_cpu_reg(target, temp_reg_data_3, &value); // ???
	if (ret != ERROR_OK)
		return ret;

	code = 0xC801FFF8 | (reg_number << 21); // lfd Fx, -8(R1)
	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	return ERROR_OK;
}

static int write_cpu_reg(struct target *target, const struct ppc476fs_reg_info *reg_data, const void *data)
{
	int ret, main_ret;
	uint32_t code;
	uint32_t save_value, save_value_2, save_value_3; // ????
	uint64_t save_value_64; // ???
	uint32_t value;
	uint64_t temp_value_64;
	const struct ppc476fs_reg_info *temp_reg_data;
	const struct ppc476fs_reg_info *temp_reg_data_2; // ???
	const struct ppc476fs_reg_info *temp_reg_data_3; // ???

	assert(target->state == TARGET_HALTED);

	// /?? printf("*** write %s 0x%08X\n", reg_data->name, *((uint32_t*)data)); // ???

	switch (reg_data->reg_arch_type) {
	case PPC476FS_REG_TYPE_GPR:
		code = 0x7C13FAA6 | (reg_data->reg_arch_opcode << 21); // mfdbdr Rx
		// ??? ret = write_reg_by_code(target, code, data);
		ret = write_reg_by_code(target, code, *((uint32_t*)data)); // ???
		break;
	case PPC476FS_REG_TYPE_FPR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "R1")->number];
		temp_reg_data_2 = &reg_info[find_reg_by_name(target, "R2")->number];
		temp_reg_data_3 = &reg_info[find_reg_by_name(target, "MSR")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save R1 (stack)
		if (ret != ERROR_OK)
			break; // return all ???
		if ((save_value < 8) || ((save_value & 0x3) != 0)) // check stack pointer
			return ERROR_FAIL;
		ret = read_cpu_reg(target, temp_reg_data_2, &save_value_2); // save R2
		if (ret != ERROR_OK)
			break;
		ret = read_cpu_reg(target, temp_reg_data_3, &save_value_3); // save MSR
		if (ret != ERROR_OK)
			break;
		main_ret = write_fpu_reg(target, save_value_3, reg_data->reg_arch_opcode, data); // ???
		ret = write_cpu_reg(target, temp_reg_data_3, &save_value_3); // restore MSR ??? optimize
		if (main_ret == ERROR_OK) // ???
		 	main_ret = ret;
		ret = write_cpu_reg(target, temp_reg_data_2, &save_value_2); // restore R2
		if (main_ret == ERROR_OK) // ???
			main_ret = ret;
		// ??? not need
		// ??? ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore R1
		// ??? if (main_ret == ERROR_OK) // ???
			// ??? main_ret = ret;
		ret = main_ret;
		break;
	case PPC476FS_REG_TYPE_SPR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "R31")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save R31
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, data); // write R31
		if (ret != ERROR_OK)
			break;
		code = 0x7FE003A6 | ((reg_data->reg_arch_opcode & 0x1F) << 16) | ((reg_data->reg_arch_opcode & 0x3E0) << (11 - 5)); // mtspr spr, R31
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore R31
		break;
	case PPC476FS_REG_TYPE_IAR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "LR")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save LR
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, data); // write LR
		if (ret != ERROR_OK)
			break;
		code = 0x4E800020; // blr
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore LR
		break;
	case PPC476FS_REG_TYPE_MSR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "R31")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save R31
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, data); // write R31
		if (ret != ERROR_OK)
			break;
		code = 0x7FE00124; // mtmsr R31
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore R31
		break;
	case PPC476FS_REG_TYPE_CR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "R31")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value); // save R31
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, data); // write R31
		if (ret != ERROR_OK)
			break;
		code = 0x7FEFF120; // mtcr R31
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore R31
		break;
	case PPC476FS_REG_TYPE_FPSCR:
		temp_reg_data = &reg_info[find_reg_by_name(target, "F0")->number];
		temp_reg_data_3 = &reg_info[find_reg_by_name(target, "MSR")->number];
		ret = read_cpu_reg(target, temp_reg_data, &save_value_64); // save F0
		if (ret != ERROR_OK)
			return ret;
		ret = read_cpu_reg(target, temp_reg_data_3, &save_value_3); // save MSR
		if (ret != ERROR_OK)
			break;
		value = save_value_3 | MSR_FP_MASK; // ???
		ret = write_cpu_reg(target, temp_reg_data_3, &value); // ???
		if (ret != ERROR_OK)
			return ret;
		temp_value_64 = 0;
		memcpy(((void*)&temp_value_64) + 4, data, 4); // ???
		ret = write_cpu_reg(target, temp_reg_data, &temp_value_64); // read F0
		if (ret != ERROR_OK)
			break;
		code = 0xFDFE058E; // mtfsf 255, F0		              
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			break;
		ret = write_cpu_reg(target, temp_reg_data_3, &save_value_3); // restore MSR ??? optimize
		if (ret != ERROR_OK) // ???
			return ret;
		ret = write_cpu_reg(target, temp_reg_data, &save_value_64); // restore R31
		break;
	default:
		assert(false);
	}

	return ret;
}

static int write_DBCR0(struct target *target, uint32_t data)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;

	ret = write_cpu_reg(target, &DBCR0_data, &data);
	if (ret != ERROR_OK)
		return ret;

	ppc476fs->DBCR0_value = data;

	return ERROR_OK;
}


// ??? optimize to read_cpu_reg
static int read_DBSR(struct target *target, uint32_t *data)
{
	/* ??? struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;
	uint32_t data;*/

	return read_cpu_reg(target, &DBSR_data, data);
	/* ????if (ret != ERROR_OK)
		return ret;

	ppc476fs->DBSR = data;

	return ERROR_OK;*/
}

static int clear_DBSR(struct target *target)
{
	assert(target->state == TARGET_HALTED);

	return write_JDCR(target, JDCR_STO_MASK | JDCR_RSDBSR_MASK);
}

static int ppc476fs_get_reg(struct reg *reg)
{
	struct target *target = reg->arch_info;
	const struct ppc476fs_reg_info *reg_data = &reg_info[reg->number];
	int ret;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted"); // ??? many dup
		return ERROR_TARGET_NOT_HALTED;
	}

	ret = read_cpu_reg(target, reg_data, reg->value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot read cpu register 1"); // ??? dup
		return ret;
	}

	reg->valid = true;
	reg->dirty = false;

	return ERROR_OK;
}

static int ppc476fs_set_reg(struct reg *reg, uint8_t *buf)
{
	struct target *target = reg->arch_info;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted"); // ??? many dup
		return ERROR_TARGET_NOT_HALTED;
	}

	buf_cpy(buf, reg->value, reg->size);
	reg->dirty = true;
	reg->valid = true;

	return ERROR_OK;
}

static int ppc476fs_get_dummy_reg(struct reg *reg)
{
	return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
}

static int ppc476fs_set_dummy_reg(struct reg *reg, uint8_t *buf)
{
	return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
}

static void build_reg_caches(struct target *target)
{
	struct reg_cache *cache = malloc(sizeof(struct reg_cache));
	size_t i;
	size_t storage_size;

	cache->name = "PowerPC General Purpose Registers";
	cache->next = NULL;
	cache->reg_list = calloc(REG_INFO_COUNT, sizeof(struct reg));
	cache->num_regs = REG_INFO_COUNT;

	for (i = 0; i < REG_INFO_COUNT; ++i) {
		const struct ppc476fs_reg_info *reg_data = &reg_info[i];
		struct reg *reg = &cache->reg_list[i];

		reg->name = reg_data->name;
		reg->number = i;
		reg->feature = calloc(1, sizeof(struct reg_feature));
		reg->feature->name = reg_data->feature;
		reg->caller_save = true; // gdb defaults to true
		reg->exist = true;
		storage_size = DIV_ROUND_UP(reg_data->bit_size, 8);
		if (storage_size < 4)
			storage_size = 4;
		reg->value = calloc(1, storage_size);
		reg->size = reg_data->bit_size;
		reg->reg_data_type = calloc(1, sizeof(struct reg_data_type));
		reg->reg_data_type->type = reg_data->type;
		//reg->group = "group"; // ???
		reg->arch_info = target; // ????
		reg->type = &ppc476fs_reg_type;
	}

	target->reg_cache = cache;
}

static void clear_regs_status(struct target *target)
{
	struct reg_cache *cache = target->reg_cache;
	size_t i;

	while (cache != NULL) {
		for (i = 0; i < cache->num_regs; ++i) {
			cache->reg_list[i].valid = false;
			cache->reg_list[i].dirty = false;
		}

		cache = cache->next;
	}
}

static int load_general_regs(struct target *target)
{
	struct reg_cache *cache = target->reg_cache;
	const struct ppc476fs_reg_info *reg_data;
	int ret;
	size_t i;

	assert(target->state == TARGET_HALTED);

	clear_regs_status(target);

	while (cache != NULL) {
		for (i = 0; i < cache->num_regs; ++i) {
			reg_data = &reg_info[cache->reg_list[i].number];
			ret = read_cpu_reg(target, reg_data, cache->reg_list[i].value);
			if (ret != ERROR_OK) {
				LOG_ERROR("cannot read cpu register 2"); // ??? dup
				printf("=== index %i\n", (int)i); // ???
				return ret;
			}
			cache->reg_list[i].valid = true;
		}

		cache = cache->next;
	}

	return ERROR_OK;
}

static int write_dirty_regs(struct target *target)
{
	struct reg_cache *cache = target->reg_cache;
	const struct ppc476fs_reg_info *reg_data;
	int ret;
	size_t i;

	assert(target->state == TARGET_HALTED);

	while (cache != NULL) {
		for (i = 0; i < cache->num_regs; ++i) {
			if (cache->reg_list[i].dirty) {
				reg_data = &reg_info[cache->reg_list[i].number];
				ret = write_cpu_reg(target, reg_data, cache->reg_list[i].value);
				if (ret != ERROR_OK) {
					LOG_ERROR("cannot write cpu register"); // ??? dup
					return ret;
				}
				cache->reg_list[i].dirty = false;
			}
		}

		cache = cache->next;
	}

	return ERROR_OK;
}

static int ppc476fs_poll(struct target *target)
{
	// ??? struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	enum target_state prev_state = target->state;
	uint32_t jdsr_value, jbsr_value;
	int ret;

	ret = read_JDSR(target, &jdsr_value);
	if (ret != ERROR_OK) {
		target->state = TARGET_UNKNOWN;
		return ret;
	}

	if ((jdsr_value & JDSR_PSP_MASK) != 0)
		target->state = TARGET_HALTED;
	else
		target->state = TARGET_RUNNING;

	if ((prev_state != TARGET_HALTED) && (target->state == TARGET_HALTED)) {
		ret = load_general_regs(target);
		if (ret != ERROR_OK) {
			LOG_ERROR("cannot load general cpu registers"); // ???
			return ret;
		}

		// ???
		// ??? ppc476fs->JDCR |= JDCR_STO_MASK; // ????

		ret = read_DBSR(target, &jbsr_value);
		if (ret != ERROR_OK)
			return ret;

		printf("*** DBSR = 0x%08X\n", jbsr_value); // ???

		if (jbsr_value != 0) {
			if ((jbsr_value & DBSR_IAC_ALL_MASK) != 0)
				target->debug_reason = DBG_REASON_BREAKPOINT;
			else if ((jbsr_value & DBSR_DAC_ALL_MASK) != 0)
				target->debug_reason = DBG_REASON_WATCHPOINT;
			ret = clear_DBSR(target);
			if (ret != ERROR_OK)
				return ret;

			// ???
			// ret = read_DBSR(target);
			// printf("*** DBSR test = 0x%08X\n", ppc476fs->DBSR); // ???
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
	uint32_t IAR_value;

	buf_cpy(find_reg_by_name(target, "PC")->value, &IAR_value, 32);

	LOG_USER("target halted due to %s, IAR: 0x%08X",
		debug_reason_name(target),
		IAR_value);

	return ERROR_OK;
}

static int unset_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target); // ???
	int ret;
	size_t iac_index = 0;
	uint32_t iac_mask;

	assert(breakpoint->set != 0);

	printf("*** unset break\n"); // ???

	iac_mask = (DBCR0_IAC1_MASK >> breakpoint->linked_BRP);
	ret = write_DBCR0(target, ppc476fs->DBCR0_value & ~iac_mask);
	if (ret != ERROR_OK)
		return ret;

	breakpoint->set = 0;

	return ERROR_OK;
}

static int set_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target); // ???
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

	printf("*** index = %i, mask = 0x%08X\n", iac_index, iac_mask); // ???

	breakpoint->linked_BRP = iac_index;

	printf("*** address = 0x%08X\n", breakpoint->address); // ???
	ret = write_cpu_reg(target, &IACx_data[iac_index], &breakpoint->address);
	if (ret != ERROR_OK)
		return ret;
	
	{ // ????
		uint32_t test;
		ret = read_cpu_reg(target, &IACx_data[iac_index], &test);
		printf("*** test = 0x%08X\n", test); // ???
	}

	ret = write_DBCR0(target, ppc476fs->DBCR0_value | iac_mask); // ????
	if (ret != ERROR_OK)
		return ret;

	{ // ????
		uint32_t test;
		ret = read_cpu_reg(target, &DBCR0_data, &test);
		printf("*** test2 = 0x%08X, 0x%08X\n", test, ppc476fs->DBCR0_value); // ???
	}

	breakpoint->set = 1;

	printf("*** setok\n"); // ???

	return ERROR_OK;
}

static int enable_breakpoints(struct target *target)
{
	struct breakpoint *bp = target->breakpoints;
	int ret;

	printf("*** enable"); // ???

	while (bp != NULL) {
		if (bp->set == 0) {
			ret = set_breakpoint(target, bp);
			if (ret != ERROR_OK)
				return ret;
		}
		bp = bp->next;
	}

	return ERROR_OK;
}

// ??? messages to main procedures

static int ppc476fs_halt(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target); // ???
	int ret;

	LOG_DEBUG("target->state: %s", target_state_name(target));

	if (target->state == TARGET_HALTED) {
		LOG_WARNING("target was already halted");
		return ERROR_TARGET_NOT_RUNNING;
	}

	if (target->state == TARGET_UNKNOWN)
		LOG_WARNING("target was in unknown state when halt was requested");

	/* break processor ??? */
	ret = write_JDCR(target, JDCR_STO_MASK);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot set JDCR register"); // ??? many dup
		return ret;
	}

	target->debug_reason = DBG_REASON_DBGRQ;

	return ERROR_OK;
}

static int ppc476fs_resume(struct target *target, int current, uint32_t address, int handle_breakpoints, int debug_execution)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target); // ???
	int ret;

	printf("*** resume\n"); // ???

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	// current = 1: continue on current pc, otherwise continue at <address>
	if (!current) {
		struct reg *IAR = find_reg_by_name(target, "PC");
		ret = IAR->type->set(IAR, (void*)&address);
		if (ret != ERROR_OK) {
			LOG_ERROR("cannot set IAR register");
			return ret;
		}
	}

	ret = write_dirty_regs(target);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot write dirty cpu registers"); // ???
		return ret;
	}

	printf("*** resume 2\n"); // ???

	ret = enable_breakpoints(target);
	if (ret != ERROR_OK)
		return ret;

	printf("*** resume 3\n"); // ???

	target->debug_reason = DBG_REASON_NOTHALTED;

	ret = write_JDCR(target, 0); // ??? ppc476fs->JDCR & ~JDCR_STO_MASK);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot set JDCR register");
		return ret;
	}

	clear_regs_status(target);

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

static int ppc476fs_step(struct target *target, int current, uint32_t address, int handle_breakpoints)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target); // ???
	int ret;

	// ??? struct breakpoint *breakpoint = NULL;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	// current = 1: continue on current pc, otherwise continue at <address>
	if (!current) {
		struct reg *IAR = find_reg_by_name(target, "PC");
		ret = IAR->type->set(IAR, (void*)&address);
		if (ret != ERROR_OK) {
			LOG_ERROR("cannot set IAR register");
			return ret;
		}
	}

	ret = write_dirty_regs(target);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot write dirty cpu registers"); // ???
		return ret;
	}

	ret = enable_breakpoints(target);
	if (ret != ERROR_OK)
		return ret;

	target->debug_reason = DBG_REASON_SINGLESTEP;

	ret = write_JDCR(target, JDCR_STO_MASK | JDCR_SS_MASK);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot set JDCR register");
		return ret;
	}

	clear_regs_status(target);

	target->state = TARGET_RUNNING;
   	target_call_event_callbacks(target, TARGET_EVENT_RESUMED);

	return ERROR_OK;
}

// ??? all register names to UPPER case

static int to_halt_state(struct target *target)
{
	int ret;

	ret = ppc476fs_poll(target);
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

int ppc476fs_get_gdb_reg_list(struct target *target, struct reg **reg_list[], int *reg_list_size, enum target_register_class reg_class)
{
	struct reg_cache *cache;
	const struct ppc476fs_reg_info *reg_data;
	size_t i;

	*reg_list_size = REG_INFO_COUNT;
	*reg_list = malloc(sizeof(struct reg *) * REG_GDB_COUNT);

	for (i = 0; i < REG_GDB_COUNT; ++i)
		(*reg_list)[i] = &dummy_reg;

	cache = target->reg_cache;
	while (cache != NULL) {
		for (i = 0; i < cache->num_regs; ++i) {
			reg_data = &reg_info[cache->reg_list[i].number];
			(*reg_list)[reg_data->gdb_numb] = &cache->reg_list[i];
		}
		cache = cache->next;
	}

	return ERROR_OK;
}

// R0, R1 is already saved
// Register autoincrement mode is not used becasue of JTAG communication BUG
static int read_memory_internal(struct target *target, uint32_t address, uint32_t size, uint32_t count, uint8_t *buffer)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target); // ???
	const struct ppc476fs_reg_info *R0_reg_data = &reg_info[find_reg_by_name(target, "R0")->number];
	const struct ppc476fs_reg_info *R1_reg_data = &reg_info[find_reg_by_name(target, "R1")->number];
	uint32_t code, shift, i, j, value;
	int ret;

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
		ret = write_cpu_reg(target, R1_reg_data, &address);
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			return ret;
		ret = read_cpu_reg(target, R0_reg_data, &value);
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

	return ERROR_OK;
}

static int ppc476fs_read_memory(struct target *target, uint32_t address, uint32_t size, uint32_t count, uint8_t *buffer)
{
	const struct ppc476fs_reg_info *R0_reg_data = &reg_info[find_reg_by_name(target, "R0")->number];
	const struct ppc476fs_reg_info *R1_reg_data = &reg_info[find_reg_by_name(target, "R1")->number];
	uint32_t R0_save_value;
	uint32_t R1_save_value;
	int ret, main_ret;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3)) || ((size == 2) && (address & 0x1)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	memset(buffer, 0, size * count); // clear result buffer

	ret = read_cpu_reg(target, R0_reg_data, &R0_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot read cpu register 3"); // ??? dup
		return ret;
	}

	ret = read_cpu_reg(target, R1_reg_data, &R1_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot read cpu register 4"); // ??? dup
		return ret;
	}

	main_ret = read_memory_internal(target, address, size, count, buffer);
	if (main_ret != ERROR_OK)
		LOG_ERROR("cannot read memory"); // ???

	ret = write_cpu_reg(target, R1_reg_data, &R1_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot write cpu register"); // ??? dup
		if (main_ret == ERROR_OK) main_ret = ret;
	}

	ret = write_cpu_reg(target, R0_reg_data, &R0_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot write cpu register"); // ??? dup
		if (main_ret == ERROR_OK) main_ret = ret;
	}

	return main_ret;
}

// R0, R1 is already saved
// Register autoincrement mode is not used becasue of JTAG communication BUG
static int write_memory_internal(struct target *target, uint32_t address, uint32_t size, uint32_t count, const uint8_t *buffer)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target); // ???
	const struct ppc476fs_reg_info *R0_reg_data = &reg_info[find_reg_by_name(target, "R0")->number];
	const struct ppc476fs_reg_info *R1_reg_data = &reg_info[find_reg_by_name(target, "R1")->number];
	uint32_t code, i, j, value;
	int ret;

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
		ret = write_cpu_reg(target, R1_reg_data, &address);
		if (ret != ERROR_OK)
			return ret;
		value = 0;
		for (j = 0; j < size; ++j)
		{
			value <<= 8;
			value |= (uint32_t)*(buffer++);
		}
		ret = write_cpu_reg(target, R0_reg_data, &value);
		if (ret != ERROR_OK)
			return ret;
		ret = stuff_code(target, code);
		if (ret != ERROR_OK)
			return ret;
		address += size;
	}

	return ERROR_OK;
}

static int ppc476fs_write_memory(struct target *target, uint32_t address, uint32_t size, uint32_t count, const uint8_t *buffer)
{
	const struct ppc476fs_reg_info *R0_reg_data = &reg_info[find_reg_by_name(target, "R0")->number];
	const struct ppc476fs_reg_info *R1_reg_data = &reg_info[find_reg_by_name(target, "R1")->number];
	uint32_t R0_save_value;
	uint32_t R1_save_value;
	int ret, main_ret;

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !(buffer))
		return ERROR_COMMAND_SYNTAX_ERROR;

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u)))
		return ERROR_TARGET_UNALIGNED_ACCESS;

	ret = read_cpu_reg(target, R0_reg_data, &R0_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot read cpu register 5"); // ??? dup
		return ret;
	}

	ret = read_cpu_reg(target, R1_reg_data, &R1_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot read cpu register 6"); // ??? dup
		return ret;
	}

	main_ret = write_memory_internal(target, address, size, count, buffer);
	if (main_ret != ERROR_OK)
		LOG_ERROR("cannot read memory"); // ???

	ret = write_cpu_reg(target, R1_reg_data, &R1_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot write cpu register"); // ??? dup
		if (main_ret == ERROR_OK) main_ret = ret;
	}

	ret = write_cpu_reg(target, R0_reg_data, &R0_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot write cpu register"); // ??? dup
		if (main_ret == ERROR_OK) main_ret = ret;
	}

	return main_ret;
}

static int ppc476fs_add_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	struct breakpoint *bp;
	int ret, bp_count;

	if (breakpoint->type != BKPT_HARD)
		return ERROR_TARGET_FAILURE; // only hardware points
	
	printf("*** length = %i \n", breakpoint->length); // ???
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

	ret = to_halt_state(target);
	if (ret != ERROR_OK)
		return ret;

	breakpoint->set = 0;

	printf("*** ok 1\n"); // ???

	return ERROR_OK;
}

static int ppc476fs_remove_breakpoint(struct target *target, struct breakpoint *breakpoint)
{
	int ret;

	if (breakpoint->set == 0)
		return ERROR_OK;

	ret = to_halt_state(target);
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

	return ERROR_OK;
}

static int ppc476fs_init_target(struct command_context *cmd_ctx, struct target *target)
{
	build_reg_caches(target);

	return ERROR_OK;
}

static int ppc476fs_examine(struct target *target)
{
	struct breakpoint *bp;
	int ret;
	uint32_t value;

	ret = to_halt_state(target); // ??? name
	if (ret != ERROR_OK)
		return ret;

	ret = write_DBCR0(target, DBCR0_EDM_MASK | DBCR0_FT_MASK);
	if (ret != ERROR_OK)
		return ret;

	value = 0;
	ret = write_cpu_reg(target, &DBCR1_data, &value);
	if (ret != ERROR_OK)
		return ret;

	value = 0;
	ret = write_cpu_reg(target, &DBCR2_data, &value);
	if (ret != ERROR_OK)
		return ret;

	ret = clear_DBSR(target);
	if (ret != ERROR_OK)
		return ret;

	// clear breakpoints status
	bp = target->breakpoints;
	while (bp != NULL) {
		bp->set = 0;
		bp = bp->next;
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
		command_print(CMD_CTX, "cannot read JDSR register");
		return ret;
	}

	command_print(CMD_CTX, "PowerPC JTAG status:");
	command_print(CMD_CTX, "  JDSR = 0x%08X", JDSR_value);

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

	// .assert_reset = mips_m4k_assert_reset,
	// .deassert_reset = mips_m4k_deassert_reset,

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
