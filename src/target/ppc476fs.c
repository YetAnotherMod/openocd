#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//??? #include "breakpoints.h"
#include <helper/log.h> // ???
#include <jtag/jtag.h> // ???
#include "target.h"
#include "target_type.h"
#include "register.h"

#define JDSR_PSP_MASK (1 << 31)

#define JDCR_STO_MASK (1 << 0)
#define JDCR_SS_MASK (1 << 2)
#define JDCR_FT_MASK (1 << 6)
#define JDCR_DWS_MASK (1 << 9)

struct ppc476fs_common {
	uint32_t JDSR;
	uint32_t JDCR;
	uint32_t JISB; // ????
	uint32_t DBDR; // ????
	// uint32_t common_magic;
	// void *arch_info;
	// struct reg_cache *core_cache;
	// struct mips_ejtag ejtag_info;
	// uint32_t core_regs[MIPS32NUMCOREREGS];
	// enum mips32_isa_mode isa_mode;

	/* working area for fastdata access */
	// struct working_area *fast_data_area;

	// int bp_scanned;
	// int num_inst_bpoints;
	// int num_data_bpoints;
	// int num_inst_bpoints_avail;
	// int num_data_bpoints_avail;
	// struct mips32_comparator *inst_break_list;
	// struct mips32_comparator *data_break_list;

	// /* register cache to processor synchronization */
	// int (*read_core_reg)(struct target *target, unsigned int num);
	// int (*write_core_reg)(struct target *target, unsigned int num);
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
};

// index of the item equals DGB register number
static const struct ppc476fs_reg_info reg_info[] = {
	{ "R0", 0, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 0 },
	{ "R1", 1, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 1 },
	{ "R2", 2, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 2 },
	{ "R3", 3, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 3 },
	{ "R4", 4, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 4 },
	{ "R5", 5, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 5 },
	{ "R6", 6, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 6 },
	{ "R7", 7, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 7 },
	{ "R8", 8, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 8 },
	{ "R9", 9, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 9 },
	{ "R10", 10, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 10 },
	{ "R11", 11, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 11 },
	{ "R12", 12, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 12 },
	{ "R13", 13, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 13 },
	{ "R14", 14, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 14 },
	{ "R15", 15, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 15 },
	{ "R16", 16, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 16 },
	{ "R17", 17, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 17 },
	{ "R18", 18, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 18 },
	{ "R19", 19, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 19 },
	{ "R20", 20, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 20 },
	{ "R21", 21, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 21 },
	{ "R22", 22, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 22 },
	{ "R23", 23, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 23 },
	{ "R24", 24, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 24 },
	{ "R25", 25, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 25 },
	{ "R26", 26, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 26 },
	{ "R27", 27, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 27 },
	{ "R28", 28, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 28 },
	{ "R29", 29, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 29 },
	{ "R30", 30, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 30 },
	{ "R31", 31, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 31 },
	{ "F0", 32, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 0 },
	{ "F1", 33, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 1 },
	{ "F2", 34, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 2 },
	{ "F3", 35, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 3 },
	{ "F4", 36, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 4 },
	{ "F5", 37, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 5 },
	{ "F6", 38, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 6 },
	{ "F7", 39, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 7 },
	{ "F8", 40, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 8 },
	{ "F9", 41, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 9 },
	{ "F10", 42, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 10 },
	{ "F11", 43, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 11 },
	{ "F12", 44, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 12 },
	{ "F13", 45, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 13 },
	{ "F14", 46, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 14 },
	{ "F15", 47, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 15 },
	{ "F16", 48, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 16 },
	{ "F17", 49, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 17 },
	{ "F18", 50, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 18 },
	{ "F19", 51, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 19 },
	{ "F20", 52, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 20 },
	{ "F21", 53, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 21 },
	{ "F22", 54, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 22 },
	{ "F23", 55, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 23 },
	{ "F24", 56, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 24 },
	{ "F25", 57, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 25 },
	{ "F26", 58, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 26 },
	{ "F27", 59, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 27 },
	{ "F28", 60, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 28 },
	{ "F29", 61, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 29 },
	{ "F30", 62, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 30 },
	{ "F31", 63, REG_TYPE_IEEE_DOUBLE, 64, PPC476FS_REG_TYPE_FPR, 31 },
	{ "IAR", 64, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_IAR, 0 },
	{ "MSR", 65, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_MSR, 0 },
	{ "CR", 66, REG_TYPE_CODE_PTR, 32, PPC476FS_REG_TYPE_CR, 0 },
	{ "LR", 67, REG_TYPE_CODE_PTR, 32, PPC476FS_REG_TYPE_SPR, 8 },
	{ "CTR", 68, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 9 },
	{ "XER", 69, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 1 },
	{ "FPSCR", 70, REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_FPSCR, 0 }
};

#define REG_INFO_COUNT (sizeof reg_info / sizeof reg_info[0])
#define REG_GDB_COUNT 70

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

static void jtag_select_instr(struct target *target, uint32_t instr)
{
	struct scan_field field;
	uint8_t buffer[4];

	buf_set_u32(buffer, 0, target->tap->ir_length, instr);
	field.num_bits = target->tap->ir_length;
	field.out_value = buffer;
	field.in_value = NULL;

	jtag_add_ir_scan(target->tap, &field, TAP_IDLE);
}

static int jtag_read_write_register_32(struct target *target, uint32_t instr, uint32_t valid_bit, uint32_t write_data, uint32_t *read_data)
{
	struct scan_field fields[2];
	uint8_t data_out_buffer[4];
	uint8_t data_in_buffer[4];
	uint8_t valid_buffer[4];
	int ret;

	jtag_select_instr(target, instr);

	buf_set_u32(data_out_buffer, 0, 32, flip_u32(write_data, 32));
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
		*read_data = flip_u32(buf_get_u32(data_in_buffer, 0, 32), 32);

	return ERROR_OK;
}

int read_JDSR(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);

	uint32_t read_data;
	int ret = jtag_read_write_register_32(target, 0x2C, 0, 0, &read_data); // 0b0101100

	if (ret == ERROR_OK)
		ppc476fs->JDSR = read_data;

	return ret;
}

int write_JDCR_read_JDSR(struct target *target, uint32_t write_data)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);

	uint32_t read_data;
	int ret = jtag_read_write_register_32(target, 0x2C, 1, write_data, &read_data); // 0b0101100 ???

	if (ret == ERROR_OK) {
		ppc476fs->JDSR = read_data;
		ppc476fs->JDCR = write_data;
	}

	return ret;
}

int write_JISB_read_JDSR(struct target *target, uint32_t write_data)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);

	uint32_t read_data;
	int ret = jtag_read_write_register_32(target, 0x3C, 1, write_data, &read_data); // 0b0111100 ???
	if (ret == ERROR_OK) {
		ret = jtag_read_write_register_32(target, 0x3C, 0, 0, NULL); // 0b0111100 ??? !!! JTAG communication BUG
		if (ret == ERROR_OK) {
			ppc476fs->JDSR = read_data;
			ppc476fs->JISB = write_data;
		}
	}

	return ret;
}

int read_DBDR(struct target *target)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);

	uint32_t read_data;
	int ret = jtag_read_write_register_32(target, 0x5C, 0, 0, &read_data); // 0b1011100 ???

	if (ret == ERROR_OK)
		ppc476fs->DBDR = read_data;

	return ret;
}

int write_DBDR(struct target *target, uint32_t write_data)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);

	int ret = jtag_read_write_register_32(target, 0x5C, 1, write_data, NULL); // 0b1011100 ???

	if (ret == ERROR_OK)
		ppc476fs->DBDR = write_data;

	return ret;
}

static int stuff_code(struct target *target, uint32_t code)
{
	int ret = write_JISB_read_JDSR(target, flip_u32(code, 32)); // ??? flip
	if (ret != ERROR_OK)
		LOG_ERROR("cannot stuff instruction");
	return ret;
}

static int read_reg_by_code(struct target *target, uint32_t code, void *data)
{
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	int ret;
	uint32_t buf;

	assert(target->state == TARGET_HALTED);

	ret = stuff_code(target, code);
	if (ret != ERROR_OK)
		return ret;

	ret = read_DBDR(target);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot read DBDR register"); // ??? dup
		return ret;
	}

	buf = flip_u32(ppc476fs->DBDR, 32); // ???
	buf_cpy(&buf, data, 32);

	return ERROR_OK;
}

static int write_reg_by_code(struct target *target, uint32_t code, const uint32_t *data)
{
	int ret;
	uint32_t buf;

	assert(target->state == TARGET_HALTED);

	buf_cpy(data, &buf, 32);
	buf = flip_u32(buf, 32); // ???

	ret = write_DBDR(target, buf);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot write DBDR register"); // ??? dup
		return ret;
	}

	return stuff_code(target, code);
}

static int read_cpu_reg(struct target *target, const struct ppc476fs_reg_info *reg_data, void *data);
static int write_cpu_reg(struct target *target, const struct ppc476fs_reg_info *reg_data, const void *data);

static int read_cpu_reg(struct target *target, const struct ppc476fs_reg_info *reg_data, void *data)
{
	int ret;
	uint32_t code;
	uint32_t save_value, temp_value;
	const struct ppc476fs_reg_info *temp_reg_data;

	assert(target->state == TARGET_HALTED);

	switch (reg_data->reg_arch_type) {
	case PPC476FS_REG_TYPE_GPR:
		code = 0x7C13FBA6 | (reg_data->reg_arch_opcode << 21); // mtdbdr Rx
		ret = read_reg_by_code(target, code, data);
		break;
	case PPC476FS_REG_TYPE_FPR:
		/* ???? temp_reg_data = &reg_info[find_reg_by_name(target, "R31")->number];
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
		ret = write_cpu_reg(target, temp_reg_data, &save_value); // restore R31*/
		memset(data, 0, 8); // ???
		ret = ERROR_OK;
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
		memset(data, 0, 4); // ???
		ret = ERROR_OK;
		break;
	default:
		assert(false);
	}

	return ret;
}

static int write_cpu_reg(struct target *target, const struct ppc476fs_reg_info *reg_data, const void *data)
{
	int ret;
	uint32_t code;
	uint32_t save_value;
	const struct ppc476fs_reg_info *temp_reg_data;

	assert(target->state == TARGET_HALTED);

	switch (reg_data->reg_arch_type) {
	case PPC476FS_REG_TYPE_GPR:
		code = 0x7C13FAA6 | (reg_data->reg_arch_opcode << 21); // mfdbdr Rx
		ret = write_reg_by_code(target, code, data);
		break;
	case PPC476FS_REG_TYPE_FPR:
		//
		// ???
		//
		ret = ERROR_OK; // ???
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
		//
		// ???
		//
		ret = ERROR_OK;
	default:
		assert(false);
	}

	return ret;
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
		LOG_ERROR("cannot read cpu register"); // ??? dup
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
		//reg->feature = calloc(1, sizeof(struct reg_feature)); // ???
		//reg->feature->name = "test"; // ???
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
				LOG_ERROR("cannot read cpu register"); // ??? dup
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
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
	enum target_state prev_state = target->state;
	int ret;

	ret = read_JDSR(target);
	if (ret != ERROR_OK) {
		target->state = TARGET_UNKNOWN;
		return ret;
	}

	if ((ppc476fs->JDSR & JDSR_PSP_MASK) != 0)
		target->state = TARGET_HALTED;
	else
		target->state = TARGET_RUNNING;

	if ((prev_state != TARGET_HALTED) && (target->state == TARGET_HALTED)) {
		ret = load_general_regs(target);
		if (ret != ERROR_OK) {
			LOG_ERROR("cannot load general cpu registers");
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
	uint32_t IAR_value;

	buf_cpy(find_reg_by_name(target, "IAR")->value, &IAR_value, 32);

	LOG_USER("target halted due to %s, IAR: 0x%08X",
		debug_reason_name(target),
		IAR_value);
	/* ????LOG_USER("target halted in %s mode due to %s, pc: 0x%8.8" PRIx32 "",
		mips_isa_strings[mips32->isa_mode],
		debug_reason_name(target),
		buf_get_u32(mips32->core_cache->reg_list[MIPS32_PC].value, 0, 32));*/

		// ??? struct mips32_common *mips32 = target_to_mips32(target);

	/* ??? LOG_USER("target halted in %s mode due to %s, pc: 0x%8.8" PRIx32 "",
		mips_isa_strings[mips32->isa_mode],
		debug_reason_name(target),
		buf_get_u32(mips32->core_cache->reg_list[MIPS32_PC].value, 0, 32));*/

	return ERROR_OK;
}

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

	// if (target->state == TARGET_RESET) {
	// 	if ((jtag_get_reset_config() & RESET_SRST_PULLS_TRST) && jtag_get_srst()) {
	// 		LOG_ERROR("can't request a halt while in reset if nSRST pulls nTRST");
	// 		return ERROR_TARGET_FAILURE;
	// 	} else {
	// 		/* we came here in a reset_halt or reset_init sequence
	// 		 * debug entry was already prepared in mips_m4k_assert_reset()
	// 		 */
	// 		target->debug_reason = DBG_REASON_DBGRQ;

	// 		return ERROR_OK;
	// 	}
	// }
	// ???

	/* break processor ??? */
	ret = write_JDCR_read_JDSR(target, ppc476fs->JDCR | JDCR_STO_MASK | JDCR_FT_MASK /*| JDCR_DWS_MASK*/); // ??? JDCR_FT_MASK JDCR_DWS_MASK
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

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	// ??? if (!debug_execution) {
		// ??? target_free_all_working_areas(target);
		// ??? mips_m4k_enable_breakpoints(target);
		// ??? mips_m4k_enable_watchpoints(target);
	// ??? }

	// current = 1: continue on current pc, otherwise continue at <address>
	if (!current) {
		struct reg *IAR = find_reg_by_name(target, "IAR");
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

	// ??? mips32_restore_context(target);

	/* the front-end may request us not to handle breakpoints */
	// ??? if (handle_breakpoints) {
		/* Single step past breakpoint at current address */
		/* ??? breakpoint = breakpoint_find(target, resume_pc);
		if (breakpoint) {
			LOG_DEBUG("unset breakpoint at 0x%8.8" PRIx32 "", breakpoint->address);
			mips_m4k_unset_breakpoint(target, breakpoint);
			mips_m4k_single_step_core(target);
			mips_m4k_set_breakpoint(target, breakpoint);
		}
	}*/

	/* enable interrupts if we are running */
	// ??? mips32_enable_interrupts(target, !debug_execution);

	/* exit debug mode */
	// ??? mips_ejtag_exit_debug(ejtag_info);
	target->debug_reason = DBG_REASON_NOTHALTED;

	/* registers are now invalid */
	// ??? register_cache_invalidate(mips32->core_cache);

	ret = write_JDCR_read_JDSR(target, ppc476fs->JDCR & ~JDCR_STO_MASK);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot set JDCR register");
		return ret;
	}

	clear_regs_status(target);

	if (!debug_execution) {
		target->state = TARGET_RUNNING;
		// ??? target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		// ??? LOG_DEBUG("target resumed at 0x%" PRIx32 "", resume_pc);
	} else {
		target->state = TARGET_DEBUG_RUNNING;
		// ??? target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		// ??? LOG_DEBUG("target debug resumed at 0x%" PRIx32 "", resume_pc);
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
		struct reg *IAR = find_reg_by_name(target, "IAR");
		ret = IAR->type->set(IAR, (void*)&address);
		if (ret != ERROR_OK) {
			LOG_ERROR("cannot set IAR register");
			return ret;
		}
	}

	/* the front-end may request us not to handle breakpoints */
	// ???
	// if (handle_breakpoints) {
	// 	breakpoint = breakpoint_find(target,
	// 			buf_get_u32(mips32->core_cache->reg_list[MIPS32_PC].value, 0, 32));
	// 	if (breakpoint)
	// 		mips_m4k_unset_breakpoint(target, breakpoint);
	// }

	/* restore context */
	// ??? mips32_restore_context(target);
	ret = write_dirty_regs(target);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot write dirty cpu registers"); // ???
		return ret;
	}

	/* configure single step mode */
	// ??? mips_ejtag_config_step(ejtag_info, 1);

	target->debug_reason = DBG_REASON_SINGLESTEP;

	ret = write_JDCR_read_JDSR(target, ppc476fs->JDCR | JDCR_STO_MASK | JDCR_FT_MASK | JDCR_SS_MASK);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot set JDCR register");
		return ret;
	}

	clear_regs_status(target);

	target->state = TARGET_RUNNING;
   	target_call_event_callbacks(target, TARGET_EVENT_RESUMED);

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
// Register autoincrement mode is not used becasue of JTAG communication bug
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
		LOG_ERROR("cannot read cpu register"); // ??? dup
		return ret;
	}

	ret = read_cpu_reg(target, R1_reg_data, &R1_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot read cpu register"); // ??? dup
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
// Register autoincrement mode is not used becasue of JTAG communication bug
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
		LOG_ERROR("cannot read cpu register"); // ??? dup
		return ret;
	}

	ret = read_cpu_reg(target, R1_reg_data, &R1_save_value);
	if (ret != ERROR_OK) {
		LOG_ERROR("cannot read cpu register"); // ??? dup
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

static int ppc476fs_target_create(struct target *target, Jim_Interp *interp)
{
	struct ppc476fs_common *ppc476fs = calloc(1, sizeof(struct ppc476fs_common));

	// ??? mips_m4k->common_magic = MIPSM4K_COMMON_MAGIC;

	/* initialize mips4k specific info */
	// ??? mips32_init_arch_info(target, mips32, tap);
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
	//
	// ????
	//
   	target_set_examined(target);

	return ERROR_OK;
}

COMMAND_HANDLER(ppc476fs_handle_status_command)
{
	struct target *target = get_current_target(CMD_CTX);
	struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	read_JDSR(target);

	command_print(CMD_CTX, "PowerPC Status:");
	command_print(CMD_CTX, "  JDSR = 0x%08X", ppc476fs->JDSR);

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
	// .checksum_memory = mips32_checksum_memory,
	// .blank_check_memory = mips32_blank_check_memory,

	// .run_algorithm = mips32_run_algorithm,

	// .add_breakpoint = mips_m4k_add_breakpoint,
	// .remove_breakpoint = mips_m4k_remove_breakpoint,
	// .add_watchpoint = mips_m4k_add_watchpoint,
	// .remove_watchpoint = mips_m4k_remove_watchpoint,

	.commands = ppc476fs_command_handlers,
	.target_create = ppc476fs_target_create,
	.init_target = ppc476fs_init_target,
	.examine = ppc476fs_examine,
};
