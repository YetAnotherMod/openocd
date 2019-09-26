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
    PPC476FS_REG_TYPE_SPR, // reg_arch_opcode - register code for mfspr/mtspr commmands
    PPC476FS_REG_TYPE_IAR  // reg_arch_opcode is not used
};

struct ppc476fs_reg_info
{
    char *name;
    enum reg_type type;
    int bit_size;
    enum ppc476fs_reg_arch_type reg_arch_type;
    uint32_t reg_arch_opcode;
};

static struct ppc476fs_reg_info reg_info[] = {
    { "R0", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 0 },
    { "R1", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 1 },
    { "R2", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 2 },
    { "R3", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 3 },
    { "R4", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 4 },
    { "R5", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 5 },
    { "R6", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 6 },
    { "R7", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 7 },
    { "R8", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 8 },
    { "R9", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 9 },
    { "R10", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 10 },
    { "R11", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 11 },
    { "R12", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 12 },
    { "R13", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 13 },
    { "R14", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 14 },
    { "R15", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 15 },
    { "R16", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 16 },
    { "R17", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 17 },
    { "R18", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 18 },
    { "R19", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 19 },
    { "R20", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 20 },
    { "R21", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 21 },
    { "R22", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 22 },
    { "R23", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 23 },
    { "R24", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 24 },
    { "R25", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 25 },
    { "R26", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 26 },
    { "R27", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 27 },
    { "R28", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 28 },
    { "R29", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 29 },
    { "R30", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 30 },
    { "R31", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_GPR, 31 },
    { "LR", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 0x008 },
    // ??? { "CTR", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_SPR, 0x009 },
    { "IAR", REG_TYPE_UINT32, 32, PPC476FS_REG_TYPE_IAR, 0 },
};

#define REG_INFO_COUNT (sizeof reg_info / sizeof reg_info[0])

static inline struct ppc476fs_common *target_to_ppc476fs(struct target *target)
{
	return target->arch_info;
}

static struct ppc476fs_reg_info *find_reg_index(const char *reg_name)
{
    int i;
    for (i = 0; i < REG_INFO_COUNT; ++i) {
        if (strcmp(reg_info[i].name, reg_name) == 0)
            return &reg_info[i];
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
    int ret = jtag_read_write_register_32(target, 0x2C, 0, 0, &read_data); // 0b0111100 ??? !!! not 2C

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
    struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
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
    struct ppc476fs_reg_info *temp_reg_data;

    assert(target->state == TARGET_HALTED);

    switch (reg_data->reg_arch_type) {
    case PPC476FS_REG_TYPE_GPR:
        code = 0x7C13FBA6 | (reg_data->reg_arch_opcode << 21); // mtdbdr Rx
        ret = read_reg_by_code(target, code, data);
        break;
    case PPC476FS_REG_TYPE_SPR:
        temp_reg_data = find_reg_index("R31");
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
        temp_reg_data = find_reg_index("LR");
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
    struct ppc476fs_reg_info *temp_reg_data;

    assert(target->state == TARGET_HALTED);

    switch (reg_data->reg_arch_type) {
    case PPC476FS_REG_TYPE_GPR:
        code = 0x7C13FAA6 | (reg_data->reg_arch_opcode << 21); // mfdbdr Rx
        ret = write_reg_by_code(target, code, data);
        break;
    case PPC476FS_REG_TYPE_SPR:
        temp_reg_data = find_reg_index("R31");
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
        temp_reg_data = find_reg_index("LR");
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
    default:
        assert(false);
    }

    return ret;
}

static int ppc476fs_get_reg(struct reg *reg)
{
    struct target *target = reg->arch_info;
    struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target);
    struct ppc476fs_reg_info *reg_data = &reg_info[reg->number];
    int ret;
    uint32_t code;

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

static struct reg_arch_type ppc476fs_reg_type = {
	.get = ppc476fs_get_reg,
	.set = ppc476fs_set_reg
};

static void build_reg_caches(struct target *target)
{
    struct reg_cache *cache = malloc(sizeof(struct reg_cache));
    int i;
    size_t storage_size;

    cache->name = "PowerPC General Purpose Registers";
    cache->next = NULL;
    cache->reg_list = calloc(REG_INFO_COUNT, sizeof(struct reg));
    cache->num_regs = REG_INFO_COUNT;

    for (i = 0; i < REG_INFO_COUNT; ++i) {
        struct ppc476fs_reg_info *reg_data = &reg_info[i];
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

    printf("*** prived 1\n"); // ???
}

static void clear_regs_status(struct target *target)
{
    struct reg_cache *cache = target->reg_cache;
    int i;

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
    struct ppc476fs_reg_info *reg_data;
    int ret, i;

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
    struct ppc476fs_reg_info *reg_data;
    int ret, i;

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
                printf("[*]"); // ???
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
    }

/*  ???    	TARGET_UNKNOWN = 0,
	TARGET_RUNNING = 1,
	TARGET_HALTED = 2,
	TARGET_RESET = 3,
	TARGET_DEBUG_RUNNING = 4,*/

    

    // ???
    //
    return ERROR_OK;
}

int ppc476fs_arch_state(struct target *target)
{
    struct ppc476fs_common *ppc476fs = target_to_ppc476fs(target); // ???

	/* ????LOG_USER("target halted in %s mode due to %s, pc: 0x%8.8" PRIx32 "",
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
	uint32_t resume_pc;
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

	/* current = 1: continue on current pc, otherwise continue at <address> */ //????
	if (!current)
		resume_pc = address;
	else
		resume_pc = 0; // ??? buf_get_u32(mips32->core_cache->reg_list[MIPS32_PC].value, 0, 32);

    // ???

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

	if (!debug_execution) {
		target->state = TARGET_RUNNING;
		// ??? target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		// ??? LOG_DEBUG("target resumed at 0x%" PRIx32 "", resume_pc);
	} else {
		target->state = TARGET_DEBUG_RUNNING;
		// ??? target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		// ??? LOG_DEBUG("target debug resumed at 0x%" PRIx32 "", resume_pc);
	}

    clear_regs_status(target);

    return ERROR_OK;
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
	// {
	// 	.name = "smp_off",
	// 	.handler = mips_m4k_handle_smp_off_command,
	// 	.mode = COMMAND_EXEC,
	// 	.help = "Stop smp handling",
	// 	.usage = "",},

	// {
	// 	.name = "smp_on",
	// 	.handler = mips_m4k_handle_smp_on_command,
	// 	.mode = COMMAND_EXEC,
	// 	.help = "Restart smp handling",
	// 	.usage = "",
	// },
	// {
	// 	.name = "smp_gdb",
	// 	.handler = mips_m4k_handle_smp_gdb_command,
	// 	.mode = COMMAND_EXEC,
	// 	.help = "display/fix current core played to gdb",
	// 	.usage = "",
	// },
	// {
	// 	.name = "scan_delay",
	// 	.handler = mips_m4k_handle_scan_delay_command,
	// 	.mode = COMMAND_ANY,
	// 	.help = "display/set scan delay in nano seconds",
	// 	.usage = "[value]",
	// },
	COMMAND_REGISTRATION_DONE
};

const struct command_registration ppc476fs_command_handlers[] = {
    // ???
	// {
	// 	.chain = mips32_command_handlers,
	// },
	{
		.name = "ppc476fs",
		.mode = COMMAND_ANY,
		.help = "mips_m4k command group",
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
	// .step = mips_m4k_step,

	// .assert_reset = mips_m4k_assert_reset,
	// .deassert_reset = mips_m4k_deassert_reset,

	// .get_gdb_reg_list = mips32_get_gdb_reg_list,

	// .read_memory = mips_m4k_read_memory,
	// .write_memory = mips_m4k_write_memory,
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
