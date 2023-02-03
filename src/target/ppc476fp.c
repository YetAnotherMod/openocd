#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ppc476fp.h"
#include <helper/log.h>

static inline uint32_t get_bits_32(uint32_t value, unsigned pos, unsigned len) {
    return (value >> pos) & ((1U << len) - 1);
}

static inline uint32_t set_bits_32(uint32_t value, unsigned pos, unsigned len,
                                   uint32_t src) {
    uint32_t tmp = src;
    tmp &= ~(((1U << len) - 1U) << pos);
    tmp |= value << pos;
    return tmp;
}

static inline struct ppc476fp_common *
target_to_ppc476fp(struct target *target) {
    return target->arch_info;
}

static inline struct ppc476fp_tap_ext *
target_to_ppc476fp_tap_ext(struct target *target) {
    return target->tap->priv;
}

// обращение к кэшированным данным регистров
static inline uint32_t get_reg_value_32(const struct reg *reg) {
    uint32_t result;
    memcpy(&result, reg->value, 4);
    return result;
}

static inline void set_reg_value_32(struct reg *reg, uint32_t value) {
    reg->dirty = true;
    reg->valid = true;
    memcpy(reg->value, &value, 4);
}

// внутренние функции работы с jtag. все осмысленные действия делаются через
// вызовы этих функций

// операция SCAN у JTAG всегда двунаправленная. по этой причине, низкоуровневая
// функция всегда принимает и отправляет данные, выбор направления выполняется
// при помощи valid_bit (если = 1, значение будет защёлкнуто в регистрах
// tap-контроллера)
static int jtag_read_write_register(struct target *target,
                                    uint32_t instr_without_coreid,
                                    bool valid_bit, uint32_t write_data,
                                    uint8_t *read_data) {
    uint8_t data_in_buffer[8];
    int ret;
    static const uint32_t coreid_mask[4] = {0x4, 0x5, 0x6, 0x3};
    struct ppc476fp_tap_ext *tap_ext = target_to_ppc476fp_tap_ext(target);
    struct scan_field instr_field;
    uint8_t instr_buffer[4];
    struct scan_field data_fields[1];
    uint8_t data_out_buffer[8];
    uint64_t zeros = 0;

    // !!! IMPORTANT
    // prevent the JTAG core switching bug
    if (tap_ext->last_coreid != target->coreid) {
        buf_set_u32(instr_buffer, 0, target->tap->ir_length,
                    JTAG_INSTR_CORE_RELOAD | coreid_mask[target->coreid]);
        instr_field.num_bits = target->tap->ir_length;
        instr_field.out_value = instr_buffer;
        instr_field.in_value = NULL;
        jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);
        tap_ext->last_coreid = target->coreid;
    }

    buf_set_u32(instr_buffer, 0, target->tap->ir_length,
                instr_without_coreid | coreid_mask[target->coreid]);
    instr_field.num_bits = target->tap->ir_length;
    instr_field.out_value = instr_buffer;
    instr_field.in_value = NULL;
    jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);

    buf_set_u32(data_out_buffer, 0, 32, write_data);
    buf_set_u32(data_out_buffer, 32, 1, valid_bit);
    data_fields[0].num_bits = 33;
    data_fields[0].out_value = data_out_buffer;
    data_fields[0].in_value = data_in_buffer;
    jtag_add_dr_scan(target->tap, 1, data_fields, TAP_IDLE);

    // !!! IMPORTANT
    // make additional request with valid bit == 0
    // to correct a JTAG communication BUG
    if (valid_bit != 0) {
        jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);
        data_fields[0].out_value = (uint8_t *)zeros;
        data_fields[0].in_value = NULL;
        jtag_add_dr_scan(target->tap, 1, data_fields, TAP_IDLE);
    }

    ret = jtag_execute_queue();
    if (ret != ERROR_OK)
        return ret;

    if (read_data != NULL) {
        uint32_t tmp = buf_get_u32(data_in_buffer, 0, 32);
        memcpy(read_data, &tmp, sizeof(tmp));
    }
    return ERROR_OK;
}

// чтение JTAG-регистра DBDR. Это единственный способ получить ответные данные
static int read_DBDR(struct target *target, uint8_t *data) {
    return jtag_read_write_register(target, JTAG_INSTR_WRITE_READ_DBDR, false,
                                    0, data);
}

static int write_DBDR(struct target *target, uint32_t data) {
    return jtag_read_write_register(target, JTAG_INSTR_WRITE_READ_DBDR, true,
                                    data, NULL);
}

// чтение JTAG-регистра JDSR. Общая информация о состоянии ядра
// выбран режим записи JDCR, но без valid_bit
static int read_JDSR(struct target *target, uint8_t *data) {
    return jtag_read_write_register(target, JTAG_INSTR_WRITE_JDCR_READ_JDSR,
                                    false, 0, data);
}

// запись JTAG-регистра JDCR. Регистр доступен только для записи. Используется
// для правления отладкой (старт/стоп, ss и т.п.)
static int write_JDCR(struct target *target, uint32_t data) {
    return jtag_read_write_register(target, JTAG_INSTR_WRITE_JDCR_READ_JDSR,
                                    true, data, NULL);
}

// запись JTAG-регистра JISB. Регистр доступен только для записи. Запись в этот
// регистр напрямую вставляет код инструкции в конвеер и исполняет её.
static int stuff_code(struct target *target, uint32_t code) {
    return jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR,
                                    true, code, NULL);
}

// чтение РОН через JTAG. Значение РОН при этом не меняется, но обычно
// происходит после инструкций, изменяющих значене регистра
static int read_gpr_reg(struct target *target, int reg_num, uint8_t *data) {
    uint32_t code = 0x7C13FBA6 | (reg_num << 21); // mtdbdr Rx
    int ret = stuff_code(target, code);
    if (ret != ERROR_OK)
        return ret;

    return read_DBDR(target, data);
}

// запись РОН через JTAG. Никак не связано с управляющими командами от GDB,
// нужно для выполнения отладочных действий (вроде росписи памяти).
// автоматически помечает регистр как dirty для того, чтобы заменить его
// значение на эталонное при снятии halt
static int write_gpr_reg(struct target *target, int reg_num, uint32_t data) {
    uint32_t code;
    int32_t data_signed = data;
    int ret = ERROR_OK;
    if ((data_signed < -32768) || (data_signed >= 32768)) {
        code = 0x3c000000 | (reg_num << 21) | (data >> 16);
        ret = stuff_code(target, code);
        if (ret != ERROR_OK) {
            return ret;
        }
        if (data & 0xffff) {
            code = 0x60000000 | (reg_num << 21) | (reg_num << 16) |
                   (data & 0xffff);
            ret = stuff_code(target, code);
        }
    } else {
        code = 0x38000000 | (reg_num << 21) | (data & 0xffff);
        ret = stuff_code(target, code);
    }
    target_to_ppc476fp(target)->gpr_regs[reg_num]->dirty = true;

    return ret;
}

// запись значения в область рядом с указателем стека. Внимание! адреса после
// указателя стека заняты проверяет чистоту r1, при необходимости
// восстанавливает из эталона
static int write_at_stack(struct target *target, int16_t shift,
                          enum memory_access_size size, const uint8_t *buffer) {
    uint32_t code;
    uint32_t value;
    uint32_t i;

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    if (ppc476fp->gpr_regs[1]->dirty) {
        write_gpr_reg(target, 1, get_reg_value_32(ppc476fp->gpr_regs[1]));
        ppc476fp->gpr_regs[1]->dirty = false;
    }

    switch (size) {
    case memory_access_size_byte:
        code = 0x98010000 | (tmp_reg_data << 21) |
               ((uint32_t)(uint16_t)shift); // stb %tmp_reg_data, 0(%sp)
        break;
    case memory_access_size_half_word:
        code = 0xB0010000 | (tmp_reg_data << 21) |
               ((uint32_t)(uint16_t)shift); // sth %tmp_reg_data, 0(%sp)
        break;
    case memory_access_size_word:
        code = 0x90010000 | (tmp_reg_data << 21) |
               ((uint32_t)(uint16_t)shift); // stw %tmp_reg_data, 0(%sp)
        break;
    default:
        assert(false);
    }

    value = 0;
    for (i = 0; i < size; ++i) {
        value <<= 8;
        value |= (uint32_t) * (buffer++);
    }

    write_gpr_reg(target, tmp_reg_data, value);
    return stuff_code(target, code);
}

// чтение значения из области рядом с указателем стека
// проверяет чистоту r1, при необходимости восстанавливает из эталона
static int read_at_stack(struct target *target, int16_t shift,
                         enum memory_access_size size, uint8_t *buffer) {
    uint32_t code;
    uint32_t ishift;
    uint32_t value;
    uint32_t i;
    int ret;

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    if (ppc476fp->gpr_regs[1]->dirty) {
        write_gpr_reg(target, 1, get_reg_value_32(ppc476fp->gpr_regs[1]));
        ppc476fp->gpr_regs[1]->dirty = false;
    }

    switch (size) {
    case memory_access_size_byte:
        code = 0x88010000 | (tmp_reg_data << 21) |
               ((uint32_t)(uint16_t)shift); // lbz %tmp_reg_data, 0(%sp)
        ishift = 24;
        break;
    case memory_access_size_half_word:
        code = 0xA0010000 | (tmp_reg_data << 21) |
               ((uint32_t)(uint16_t)shift); // lhz %tmp_reg_data, 0(%sp)
        ishift = 16;
        break;
    case memory_access_size_word:
        code = 0x80010000 | (tmp_reg_data << 21) |
               ((uint32_t)(uint16_t)shift); // lwz %tmp_reg_data, 0(%sp)
        ishift = 0;
        break;
    default:
        assert(false);
    }
    ret = stuff_code(target, code);
    if (ret != ERROR_OK)
        return ret;
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    ret = read_gpr_reg(target, tmp_reg_data, (uint8_t *)&value);
    if (ret != ERROR_OK)
        return ret;

    value <<= ishift;
    for (i = 0; i < size; ++i) {
        *(buffer++) = (value >> 24);
        value <<= 8;
    }

    return ERROR_OK;
}

// проверка доступности области стека. Происходит по принципу: проверка
// корректности значения в r1, после чего в свободную часть пытаются записать 8
// байт (2 слова), после чего считать и сравнить с эталоном. если чтение
// удалось, стек считается рабочим
static int test_memory_at_stack(struct target *target) {

    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint32_t value_1;
    uint32_t value_2;
    int ret;

    static const uint32_t magic1 = 0x396F965C;
    static const uint32_t magic2 = 0x44692D7E;

    if (target->state != TARGET_HALTED) {
        return ERROR_TARGET_NOT_HALTED;
    }

    uint32_t sp = get_reg_value_32(ppc476fp->gpr_regs[1]);

    if ((sp < 8) || ((sp & 0x3) != 0)) // check the stack pointer
        return ERROR_MEMORY_AT_STACK;

    ret = write_at_stack(target, -8, 4, (const uint8_t *)&magic1);
    if (ret != ERROR_OK)
        return ret;
    ret = write_at_stack(target, -4, 4, (const uint8_t *)&magic2);
    if (ret != ERROR_OK)
        return ret;

    ppc476fp->gpr_regs[tmp_reg_data]->dirty = true;

    ret = read_at_stack(target, -8, 4, (uint8_t *)&value_1);
    if (ret != ERROR_OK)
        return ret;
    ret = read_at_stack(target, -4, 4, (uint8_t *)&value_2);
    if (ret != ERROR_OK)
        return ret;

    // check the magic values
    if ((value_1 != magic1) || (value_2 != magic2))
        return ERROR_MEMORY_AT_STACK;

    return ERROR_OK;
}

// Запись значения по эффективному адресу
static int write_virt_mem(struct target *target, uint32_t address,
                          enum memory_access_size size, const uint8_t *buffer) {
    uint32_t code;
    uint32_t value;
    uint32_t i;
    int ret;

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    switch (size) {
    case memory_access_size_byte:
        code = 0x98000000 | (tmp_reg_data << 21) |
               (tmp_reg_addr << 16); // stb %tmp_reg_data, 0(%tmp_reg_addr)
        break;
    case memory_access_size_half_word:
        code = 0xB0000000 | (tmp_reg_data << 21) |
               (tmp_reg_addr << 16); // sth %tmp_reg_data, 0(%tmp_reg_addr)
        break;
    case memory_access_size_word:
        code = 0x90000000 | (tmp_reg_data << 21) |
               (tmp_reg_addr << 16); // stw %tmp_reg_data, 0(%tmp_reg_addr)
        break;
    default:
        assert(false);
    }

    ret = write_gpr_reg(target, tmp_reg_addr, address);
    if (ret != ERROR_OK) {
        return ret;
    }

    value = 0;
    for (i = 0; i < size; ++i) {
        value <<= 8;
        value |= (uint32_t) * (buffer++);
    }

    ret = write_gpr_reg(target, tmp_reg_data, value);
    if (ret != ERROR_OK) {
        return ret;
    }
    return stuff_code(target, code);
}

// Чтение значения с эффективного адреса
static int read_virt_mem(struct target *target, uint32_t address,
                         enum memory_access_size size, uint8_t *buffer) {
    uint32_t code;
    uint32_t shift;
    uint32_t value;
    uint32_t i;
    int ret;

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    switch (size) {
    case memory_access_size_byte:
        code = 0x88000000 | (tmp_reg_data << 21) |
               (tmp_reg_addr << 16); // lbz %tmp_reg_data, 0(%tmp_reg_addr)
        shift = 24;
        break;
    case memory_access_size_half_word:
        code = 0xA0000000 | (tmp_reg_data << 21) |
               (tmp_reg_addr << 16); // lhz %tmp_reg_data, 0(%tmp_reg_addr)
        shift = 16;
        break;
    case memory_access_size_word:
        code = 0x80000000 | (tmp_reg_data << 21) |
               (tmp_reg_addr << 16); // lwz %tmp_reg_data, 0(%tmp_reg_addr)
        shift = 0;
        break;
    default:
        assert(false);
    }

    ret = write_gpr_reg(target, tmp_reg_addr, address);
    if (ret != ERROR_OK)
        return ret;
    ret = stuff_code(target, code);
    if (ret != ERROR_OK)
        return ret;
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    ret = read_gpr_reg(target, tmp_reg_data, (uint8_t *)&value);
    if (ret != ERROR_OK)
        return ret;

    value <<= shift;
    for (i = 0; i < size; ++i) {
        *(buffer++) = (value >> 24);
        value <<= 8;
    }

    return ERROR_OK;
}

// чтение spr-регистра в data
static int read_spr_reg(struct target *target, int spr_num, uint8_t *data) {
    uint32_t code = 0x7C0002A6 | (tmp_reg_data << 21) |
                    ((spr_num & 0x1F) << 16) |
                    ((spr_num & 0x3E0) << (11 - 5)); // mfspr tmp_reg_data, spr
    int ret = stuff_code(target, code);
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    if (ret != ERROR_OK)
        return ret;

    return read_gpr_reg(target, tmp_reg_data, data);
}

// запись значения data в spr-регистр
static int write_spr_reg(struct target *target, int spr_num, uint32_t data) {
    uint32_t code;
    int ret = write_gpr_reg(target, tmp_reg_data, data);
    if (ret != ERROR_OK)
        return ret;

    code = 0x7C0003A6 | (tmp_reg_data << 21) | ((spr_num & 0x1F) << 16) |
           ((spr_num & 0x3E0) << (11 - 5)); // mtspr spr, tmp_reg_data
    ret = stuff_code(target, code);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static void memcpy_swapped(void *dst, const void *src, size_t len) {
    uint8_t *dst_ = dst;
    const uint8_t *src_ = src;
    src_ += len;
    while (len--) {
        *(dst_++) = *(--src_);
    }
}

// чтение регистра fpu. Здесь много заковырок. Во-первых, fpu должен быть
// включен. Во-вторых, регистры fpu нельзя напрямую передать в JTAG или хотябы
// РОН, потому обращение к ним происходит через стек, потому он тоже должен
// работать.
static int read_fpr_reg(struct target *target, int reg_num, uint64_t *value) {

    static const uint64_t bad = 0xbabadedababadedaull;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint8_t value_m[8];
    uint32_t code;
    int ret;

    if ((!use_fpu_get(target)) ||
        ((get_reg_value_32(ppc476fp->MSR_reg) & MSR_FP_MASK) == 0)) {
        *value = bad;
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }

    if (use_static_mem_get(target)) {
        ret = write_gpr_reg(target, tmp_reg_addr, use_static_mem_addr(target));
        if (ret != ERROR_OK)
            return ret;
        code = 0xd8000000 | (reg_num << 21) |
               (tmp_reg_addr << 16); // stfd Fx, 0(tmp_reg_addr)
        ret = stuff_code(target, code);
        if (ret != ERROR_OK)
            return ret;
        ret =
            read_virt_mem(target, use_static_mem_addr(target) + 0, 4, value_m);
        if (ret != ERROR_OK)
            return ret;
        ret = read_virt_mem(target, use_static_mem_addr(target) + 4, 4,
                            value_m + 4);
        if (ret != ERROR_OK)
            return ret;
        memcpy_swapped(value, value_m, 8);
    } else if (use_stack_get(target)) {
        code = 0xd801fff8 | (reg_num << 21); // stfd Fx, -8(sp)
        ret = stuff_code(target, code);
        if (ret != ERROR_OK)
            return ret;
        ret = read_at_stack(target, -8, 4, value_m);
        if (ret != ERROR_OK)
            return ret;
        ret = read_at_stack(target, -4, 4, value_m + 4);
        if (ret != ERROR_OK)
            return ret;
        memcpy_swapped(value, value_m, 8);
    } else {
        *value = bad;
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    return ERROR_OK;
}

// запись регистра fpu. Здесь много заковырок. Во-первых, fpu должен быть
// включен. Во-вторых, регистры fpu нельзя напрямую передать в JTAG или хотябы
// РОН, потому обращение к ним происходит через стек, потому он тоже должен
// работать.
static int write_fpr_reg(struct target *target, int reg_num, uint64_t value) {
    uint8_t value_m[8];
    memcpy_swapped(value_m, &value, 8);
    int ret;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint32_t code;

    if ((!use_fpu_get(target)) ||
        ((get_reg_value_32(ppc476fp->MSR_reg) & MSR_FP_MASK) == 0)) {
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    if (use_static_mem_get(target)) {
        ppc476fp->fpr_regs[reg_num]->dirty = true;
        ret =
            write_virt_mem(target, use_static_mem_addr(target) + 0, 4, value_m);
        if (ret != ERROR_OK)
            return ret;
        ret = write_virt_mem(target, use_static_mem_addr(target) + 4, 4,
                             value_m + 4);
        if (ret != ERROR_OK)
            return ret;

        write_gpr_reg(target, tmp_reg_addr, use_static_mem_addr(target));
        code = 0xc800fff8 | (reg_num << 21) |
               (tmp_reg_addr << 16); // lfd Fx, 0(tmp_reg_addr)
        ret = stuff_code(target, code);
        if (ret != ERROR_OK)
            return ret;

    } else if (use_stack_get(target)) {

        ppc476fp->fpr_regs[reg_num]->dirty = true;
        ret = write_at_stack(target, -8, 4, value_m);
        if (ret != ERROR_OK)
            return ret;
        ret = write_at_stack(target, -4, 4, value_m + 4);
        if (ret != ERROR_OK)
            return ret;

        code = 0xc801fff8 | (reg_num << 21); // lfd Fx, -8(sp)
        ret = stuff_code(target, code);
        if (ret != ERROR_OK)
            return ret;

    } else {
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    return ERROR_OK;
}

// запись регистра DBCR0. Подробнее: PowerPC 476FP Embedded Processor Core
// User’s Manual 8.5.1 с. 235
static int write_DBCR0(struct target *target, uint32_t data) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int ret;

    ret = write_spr_reg(target, SPR_REG_NUM_DBCR0, data);
    if (ret != ERROR_OK)
        return ret;

    ppc476fp->DBCR0_value = data;

    return ERROR_OK;
}

// очистка регистра DBSR. Подробнее: PowerPC 476FP Embedded Processor Core
// User’s Manual 8.5.4 с. 239
static int clear_DBSR(struct target *target) {
    return write_JDCR(target, JDCR_STO_MASK | JDCR_RSDBSR_MASK);
}

// запись MSR.Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual
// 7.4.1 с. 173
static int write_MSR(struct target *target, uint32_t value) {
    int ret;

    ret = write_gpr_reg(target, tmp_reg_data, value);
    if (ret != ERROR_OK)
        return ret;
    ret = stuff_code(target,
                     0x7C000124 | (tmp_reg_data << 21)); // mtmsr tmp_reg_data
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

// чтение MSR.Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual
// 7.4.1 с. 173
static int read_MSR(struct target *target, uint8_t *value) {
    int ret;

    ret = stuff_code(target,
                     0x7C0000A6 | (tmp_reg_data << 21)); // mfmsr tmp_reg_data
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_reg(target, tmp_reg_data, value);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int read_DCR(struct target *target, uint32_t addr, uint32_t *value) {
    int ret;
    uint32_t code;
    ret = write_gpr_reg(target, tmp_reg_addr, addr);
    if (ret != ERROR_OK)
        return ret;
    code = 0x7C000206 | (tmp_reg_data << 21) | (tmp_reg_addr << 16);
    LOG_DEBUG("%x", code);
    ret = stuff_code(target, code); // mfdcrx tmp_reg_data,tmp_reg_addr
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_reg(target, tmp_reg_data, (uint8_t *)value);
    if (ret != ERROR_OK)
        return ret;
    return ERROR_OK;
}
static int write_DCR(struct target *target, uint32_t addr, uint32_t value) {
    int ret;
    ret = write_gpr_reg(target, tmp_reg_addr, addr);
    if (ret != ERROR_OK)
        return ret;
    ret = write_gpr_reg(target, tmp_reg_data, value);
    if (ret != ERROR_OK)
        return ret;
    ret = stuff_code(
        target, 0x7C000306 | (tmp_reg_data << 21) |
                    (tmp_reg_addr << 16)); // mtdcrx tmp_reg_addr,tmp_reg_data
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    if (ret != ERROR_OK)
        return ret;
    return ERROR_OK;
}

// Запись грязных (dirty) регистров из кэша OpenOCD в таргет
// Записывает все РОН, LR, CTR, XER, MSR, CR, PC
// Важно: регистры становятся грязными не только при изменении их
// значения через интерфейс OpenOCD, но и при работе внутренних функций JTAG
static int write_dirty_gen_regs(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct reg *reg;
    int i;
    int ret;

    if (target->state != TARGET_HALTED) {
        return ERROR_TARGET_NOT_HALTED;
    }

    if (ppc476fp->PC_reg->dirty) {
        ppc476fp->LR_reg->dirty = true;
        ret = write_spr_reg(target, SPR_REG_NUM_LR,
                            get_reg_value_32(ppc476fp->PC_reg));
        if (ret != ERROR_OK)
            return ret;
        ret = stuff_code(target, 0x4E800020); // blr
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->PC_reg->dirty = false;
    }

    if (ppc476fp->CR_reg->dirty) {
        ret = write_gpr_reg(target, tmp_reg_data,
                            get_reg_value_32(ppc476fp->CR_reg));
        if (ret != ERROR_OK)
            return ret;
        ret = stuff_code(target, 0x7C4FF120); // mtcr R2
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->CR_reg->dirty = false;
    }

    if (ppc476fp->MSR_reg->dirty) {
        ret = write_MSR(target, get_reg_value_32(ppc476fp->MSR_reg));
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->MSR_reg->dirty = false;
    }

    if (ppc476fp->XER_reg->dirty) {
        ret = write_spr_reg(target, SPR_REG_NUM_XER,
                            get_reg_value_32(ppc476fp->XER_reg));
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->XER_reg->dirty = false;
    }

    if (ppc476fp->CTR_reg->dirty) {
        ret = write_spr_reg(target, SPR_REG_NUM_CTR,
                            get_reg_value_32(ppc476fp->CTR_reg));
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->CTR_reg->dirty = false;
    }

    if (ppc476fp->LR_reg->dirty) {
        ret = write_spr_reg(target, SPR_REG_NUM_LR,
                            get_reg_value_32(ppc476fp->LR_reg));
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->LR_reg->dirty = false;
    }
    for (i = 0; i < GPR_REG_COUNT; ++i) {
        reg = ppc476fp->gpr_regs[i];
        if (reg->dirty) {
            ret = write_gpr_reg(target, i, get_reg_value_32(reg));
            if (ret != ERROR_OK)
                return ret;
            reg->dirty = false;
        }
    }

    return ERROR_OK;
}

// более высокоуровневая функция чтения регистров из таргета.
// вычитывает все РОН, LR, CTR, XER, MSR, CR, PC
// по факту, актуализирует кэш регистров в OpenOCD
static int read_required_gen_regs(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct reg *reg;
    int i;
    uint32_t value;
    int ret;

    if (target->state != TARGET_HALTED) {
        return ERROR_TARGET_NOT_HALTED;
    }

    for (i = 0; i < GPR_REG_COUNT; ++i) {
        reg = ppc476fp->gpr_regs[i];
        if (!reg->valid) {
            ret = read_gpr_reg(target, i, reg->value);
            if (ret != ERROR_OK)
                return ret;
            reg->valid = true;
            reg->dirty = false;
        }
    }

    if (!ppc476fp->LR_reg->valid) {
        ret = read_spr_reg(target, SPR_REG_NUM_LR, ppc476fp->LR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->LR_reg->valid = true;
        ppc476fp->LR_reg->dirty = false;
    }

    if (!ppc476fp->CTR_reg->valid) {
        ret = read_spr_reg(target, SPR_REG_NUM_CTR, ppc476fp->CTR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->CTR_reg->valid = true;
        ppc476fp->CTR_reg->dirty = false;
    }

    if (!ppc476fp->XER_reg->valid) {
        ret = read_spr_reg(target, SPR_REG_NUM_XER, ppc476fp->XER_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->XER_reg->valid = true;
        ppc476fp->XER_reg->dirty = false;
    }

    if (!ppc476fp->MSR_reg->valid) {
        ret = read_MSR(target, ppc476fp->MSR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->MSR_reg->valid = true;
        ppc476fp->MSR_reg->dirty = false;
    }

    if (!ppc476fp->CR_reg->valid) {
        ret = stuff_code(target, 0x7C000026 |
                                     (tmp_reg_data << 21)); // mfcr tmp_reg_data
        ppc476fp->gpr_regs[tmp_reg_data]->dirty = true;
        if (ret != ERROR_OK)
            return ret;
        ret = read_gpr_reg(target, tmp_reg_data, ppc476fp->CR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->CR_reg->valid = true;
        ppc476fp->CR_reg->dirty = false;
    }

    if (!ppc476fp->PC_reg->valid) {
        ppc476fp->LR_reg->dirty = true;
        ret = stuff_code(target, 0x48000001); // bl $+0
        if (ret != ERROR_OK)
            return ret;
        ret = read_spr_reg(target, SPR_REG_NUM_LR, (uint8_t *)&value);
        set_reg_value_32(ppc476fp->PC_reg, value - 4);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->PC_reg->valid = true;
        ppc476fp->PC_reg->dirty = false;
    }

    return ERROR_OK;
}

// Запись грязных (dirty) регистров FPU из кэша OpenOCD в таргет
// Важно: регистры становятся грязными не только при изменении их
// значения через интерфейс OpenOCD, но и при работе внутренних функций JTAG
static int write_dirty_fpu_regs(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct reg *reg;
    int i;
    int ret;

    if (target->state != TARGET_HALTED) {
        return ERROR_TARGET_NOT_HALTED;
    }

    if (ppc476fp->FPSCR_reg->dirty) {
        uint64_t value = (uint64_t)get_reg_value_32(ppc476fp->FPSCR_reg);
        ret = write_fpr_reg(target, 0, value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->fpr_regs[0]->dirty = true;
        ret = stuff_code(target, 0xFDFE058E); // mtfsf 255, F0
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->FPSCR_reg->dirty = false;
    }

    for (i = 0; i < FPR_REG_COUNT; ++i) {
        reg = ppc476fp->fpr_regs[i];
        if (reg->dirty) {
            ret = write_fpr_reg(target, i, *((uint64_t *)reg->value));
            if (ret != ERROR_OK) {
                return ret;
            }
            reg->dirty = false;
        }
    }

    return ERROR_OK;
}

// Чтение всех регистров FPU
// по факту, актуализирует кэш регистров в OpenOCD
static int read_required_fpu_regs(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct reg *reg;
    int i;
    uint64_t value;
    int ret;

    if (target->state != TARGET_HALTED) {
        return ERROR_TARGET_NOT_HALTED;
    }

    reg = ppc476fp->fpr_regs[0];
    ret = read_fpr_reg(target, 0, (uint64_t *)reg->value);
    if (ret != ERROR_OK) {
        if (ret == ERROR_TARGET_RESOURCE_NOT_AVAILABLE) {
            for (i = 1; i < FPR_REG_COUNT; ++i) {
                reg = ppc476fp->fpr_regs[i];
                reg->valid = false;
                reg->dirty = false;
            }
            ppc476fp->FPSCR_reg->valid = false;
            ppc476fp->FPSCR_reg->dirty = false;
            return ERROR_OK;
        } else {
            return ret;
        }
    } else {

        reg->valid = true;
        reg->dirty = false;

        for (i = 1; i < FPR_REG_COUNT; ++i) {
            reg = ppc476fp->fpr_regs[i];
            if (!reg->valid) {
                ret = read_fpr_reg(target, i, (uint64_t *)reg->value);
                if (ret != ERROR_OK) {
                    return ret;
                } else {
                    reg->valid = true;
                    reg->dirty = false;
                }
            }
        }

        if (!ppc476fp->FPSCR_reg->valid) {
            ppc476fp->fpr_regs[0]->dirty = true;
            ret = stuff_code(target, 0xFC00048E); // mffs F0
            if (ret != ERROR_OK)
                return ret;
            ret = read_fpr_reg(target, 0, &value);
            set_reg_value_32(ppc476fp->FPSCR_reg, (uint32_t)(value));
            if (ret != ERROR_OK) {
                return ret;
            } else {
                ppc476fp->FPSCR_reg->valid = true;
                ppc476fp->FPSCR_reg->dirty = false;
            }
        }
    }
    return ERROR_OK;
}

// Помечает весь кэш регистров как невалидный
// Используется в процессе сохранения/восстановления контекста и при сбросе
static void invalidate_regs_status(struct target *target) {
    struct reg_cache *cache = target->reg_cache;

    while (cache != NULL) {
        register_cache_invalidate(cache);
        cache = cache->next;
    }
}

// Помечает конкретный регистр как невалидный и запрашивает его чтение из
// таргета Текстовым поиском по коду видно, что функция используется только для
// чтения невалидных регистров Почему регистр инвалидируется - вопрос
static int ppc476fp_get_gen_reg(struct reg *reg) {
    LOG_DEBUG("%s", reg->name);
    struct target *target = reg->arch_info;

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    reg->valid = false;
    reg->dirty = false;

    return read_required_gen_regs(target);
}

// Изменение регистра в кэше. По идее, эта функция парная к
// ppc476fp_get_gen_reg, Но их поведение в общую логику не укладываются, а
// документация openocd не говорит как эта функция должна себя вести в идеале. В
// случае, если меняется значение MSR, запись происходит сразу. Если при
// изменении MSR отключается FPU, предварительно кэш регистров FPU сбрасывается
static int ppc476fp_set_gen_reg(struct reg *reg, uint8_t *buf) {
    struct target *target = reg->arch_info;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint32_t MSR_prev_value = get_reg_value_32(ppc476fp->MSR_reg);
    uint32_t MSR_new_value;
    size_t i;
    int ret;

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    if (reg == ppc476fp->MSR_reg) {
        MSR_new_value = buf_get_u32(buf, 0, 31);
        if (((MSR_prev_value ^ MSR_new_value) & MSR_FP_MASK) != 0) {
            if ((MSR_prev_value & MSR_FP_MASK) != 0) {
                ret = write_dirty_fpu_regs(target);
                if (ret != ERROR_OK)
                    return ret;
            }
            // write MSR to the CPU
            ret = write_MSR(target, MSR_new_value);
            if (ret != ERROR_OK)
                return ret;
            // invalidate FPU registers
            for (i = 0; i < FPR_REG_COUNT; ++i) {
                ppc476fp->fpr_regs[i]->valid = false;
                ppc476fp->fpr_regs[i]->dirty = false;
            }
            ppc476fp->FPSCR_reg->valid = false;
            ppc476fp->FPSCR_reg->dirty = false;
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

// чтение FPU регистра с таргета. аналогична ppc476fp_get_gen_reg
static int ppc476fp_get_fpu_reg(struct reg *reg) {
    struct target *target = reg->arch_info;

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    reg->valid = false;
    reg->dirty = false;

    return read_required_fpu_regs(target);
}

// запись в кэш FPU регистра. аналогична ppc476fp_set_gen_reg
static int ppc476fp_set_fpu_reg(struct reg *reg, uint8_t *buf) {
    struct target *target = reg->arch_info;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    if (!use_fpu_get(target) ||
        ((get_reg_value_32(ppc476fp->MSR_reg) & MSR_FP_MASK) == 0))
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

    buf_cpy(buf, reg->value, reg->size);
    reg->dirty = true;
    reg->valid = true;

    return ERROR_OK;
}

// Заполнение полей структуры reg при её инициализации
// получает на вход указатель на структуру reg, который возвращает
static struct reg *fill_reg(struct target *target, int all_index,
                            struct reg *reg, const char *reg_name,
                            enum reg_type reg_type, int bit_size,
                            const struct reg_arch_type *arch_type,
                            const char *feature_name) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    size_t storage_size;

    ppc476fp->all_regs[all_index] = reg;

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

// Создание всего кэша регистров
static void build_reg_caches(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct reg_cache *gen_cache = calloc(1, sizeof(struct reg_cache));
    struct reg_cache *fpu_cache = calloc(1, sizeof(struct reg_cache));
    int all_index = 0;
    struct reg *gen_regs;
    struct reg *fpu_regs;
    char reg_name[64];
    int i;

    static const struct reg_arch_type ppc476fp_gen_reg_type = {
        .get = ppc476fp_get_gen_reg, .set = ppc476fp_set_gen_reg};

    static const struct reg_arch_type ppc476fp_fpu_reg_type = {
        .get = ppc476fp_get_fpu_reg, .set = ppc476fp_set_fpu_reg};

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
        ppc476fp->gpr_regs[i] = fill_reg(
            target, all_index++, gen_regs++, strdup(reg_name), REG_TYPE_UINT32,
            32, &ppc476fp_gen_reg_type, "org.gnu.gdb.power.core"); // R0-R31
    }

    for (i = 0; i < FPR_REG_COUNT; ++i) {
        sprintf(reg_name, "F%i", i);
        ppc476fp->fpr_regs[i] =
            fill_reg(target, all_index++, fpu_regs++, strdup(reg_name),
                     REG_TYPE_IEEE_DOUBLE, 64, &ppc476fp_fpu_reg_type,
                     "org.gnu.gdb.power.fpu"); // F0-R31
    }

    ppc476fp->PC_reg =
        fill_reg(target, all_index++, gen_regs++, "PC", REG_TYPE_CODE_PTR, 32,
                 &ppc476fp_gen_reg_type, "org.gnu.gdb.power.core");
    ppc476fp->MSR_reg =
        fill_reg(target, all_index++, gen_regs++, "MSR", REG_TYPE_UINT32, 32,
                 &ppc476fp_gen_reg_type, "org.gnu.gdb.power.core");
    ppc476fp->CR_reg =
        fill_reg(target, all_index++, gen_regs++, "CR", REG_TYPE_UINT32, 32,
                 &ppc476fp_gen_reg_type, "org.gnu.gdb.power.core");
    ppc476fp->LR_reg =
        fill_reg(target, all_index++, gen_regs++, "LR", REG_TYPE_CODE_PTR, 32,
                 &ppc476fp_gen_reg_type, "org.gnu.gdb.power.core");
    ppc476fp->CTR_reg =
        fill_reg(target, all_index++, gen_regs++, "CTR", REG_TYPE_UINT32, 32,
                 &ppc476fp_gen_reg_type, "org.gnu.gdb.power.core");
    ppc476fp->XER_reg =
        fill_reg(target, all_index++, gen_regs++, "XER", REG_TYPE_UINT32, 32,
                 &ppc476fp_gen_reg_type, "org.gnu.gdb.power.core");
    ppc476fp->FPSCR_reg =
        fill_reg(target, all_index++, fpu_regs++, "FPSCR", REG_TYPE_UINT32, 32,
                 &ppc476fp_fpu_reg_type, "org.gnu.gdb.power.fpu");

    assert(all_index == ALL_REG_COUNT);
    assert(gen_regs - gen_cache->reg_list == GEN_CACHE_REG_COUNT);
    assert(fpu_regs - fpu_cache->reg_list == FPU_CACHE_REG_COUNT);

    target->reg_cache = gen_cache;
    ppc476fp->use_fpu = false;
    ppc476fp->use_stack = false;
    ppc476fp->use_static_mem = 0xffffffff;
}

// установка аппаратной точки останова (предполагается, что она создана ранее)
static int set_hw_breakpoint(struct target *target, struct breakpoint *bp) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int iac_index = 0;
    uint32_t iac_mask;
    int ret;

    assert(bp->is_set == 0);

    while (true) {
        iac_mask = (DBCR0_IAC1_MASK >> iac_index);
        if ((ppc476fp->DBCR0_value & iac_mask) == 0)
            break;
        ++iac_index;
        assert(iac_index < HW_BP_NUMBER);
    }

    ret = write_spr_reg(target, SPR_REG_NUM_IAC_BASE + iac_index,
                        (uint32_t)bp->address);
    if (ret != ERROR_OK)
        return ret;
    ppc476fp->IAC_value[iac_index] = (uint32_t)bp->address;

    ret = write_DBCR0(target, ppc476fp->DBCR0_value | iac_mask);
    if (ret != ERROR_OK)
        return ret;

    bp->is_set = 1;

    return ERROR_OK;
}

// Снятие ранее установленной аппаратной точки останова
static int unset_hw_breakpoint(struct target *target, struct breakpoint *bp) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int iac_index = 0;
    uint32_t iac_mask;
    int ret;

    assert(bp->is_set != 0);

    while (true) {
        iac_mask = (DBCR0_IAC1_MASK >> iac_index);
        if ((ppc476fp->DBCR0_value & iac_mask) != 0) {
            if (ppc476fp->IAC_value[iac_index] == (uint32_t)bp->address)
                break;
        }
        ++iac_index;
        assert(iac_index < HW_BP_NUMBER);
    }

    ret = write_DBCR0(target, ppc476fp->DBCR0_value & ~iac_mask);
    if (ret != ERROR_OK)
        return ret;

    bp->is_set = 0;

    return ERROR_OK;
}

// установка программной точки останова (предполагается, что она создана ранее)
static int set_soft_breakpoint(struct target *target, struct breakpoint *bp) {
    int ret;
    uint32_t test_value;

    static const uint32_t TRAP_INSTRUCTION_CODE = 0x7FE00008;

    ret = read_virt_mem(target, (uint32_t)bp->address, 4,
                        (uint8_t *)bp->orig_instr);
    if (ret != ERROR_OK)
        return ret;

    ret = write_virt_mem(target, (uint32_t)bp->address, 4,
                         (const uint8_t *)&TRAP_INSTRUCTION_CODE);
    if (ret != ERROR_OK)
        return ret;

    // test
    ret =
        read_virt_mem(target, (uint32_t)bp->address, 4, (uint8_t *)&test_value);
    if (ret != ERROR_OK)
        return ret;

    if (test_value == TRAP_INSTRUCTION_CODE)
        bp->is_set = 1;
    else
        LOG_WARNING("soft breakpoint cannot be set at address 0x%08X",
                    (uint32_t)bp->address);

    return ERROR_OK;
}

// Снятие программной точки останова
static int unset_soft_breakpoint(struct target *target, struct breakpoint *bp) {
    uint32_t test_value;
    int ret;

    assert(bp->is_set != 0);

    ret = write_virt_mem(target, (uint32_t)bp->address, 4,
                         (const uint8_t *)bp->orig_instr);
    if (ret != ERROR_OK)
        return ret;

    // проверка установки
    ret =
        read_virt_mem(target, (uint32_t)bp->address, 4, (uint8_t *)&test_value);
    if (ret != ERROR_OK)
        return ret;

    if (memcmp(&test_value, bp->orig_instr, 4) == 0)
        bp->is_set = 0;
    else
        LOG_WARNING("soft breakpoint cannot be removed at address 0x%08X",
                    (uint32_t)bp->address);

    return ERROR_OK;
}

// Снятие всех программных точек останова
static int unset_all_soft_breakpoints(struct target *target) {
    struct breakpoint *bp;
    int ret;

    bp = target->breakpoints;
    while (bp != NULL) {
        if (bp->type == BKPT_SOFT) {
            ret |= unset_soft_breakpoint(target, bp);
            LOG_WARNING("soft breakpoint cannot be removed at address 0x%08X",
                        (uint32_t)bp->address);
        }
    }

    return ERROR_OK;
}

// установка всех созданных точек останова (программных и аппаратных)
static int enable_breakpoints(struct target *target) {
    struct breakpoint *bp = target->breakpoints;
    int ret;

    while (bp != NULL) {
        if (bp->is_set == 0) {
            if (bp->type == BKPT_HARD) {
                ret = set_hw_breakpoint(target, bp);
            } else {
                ret = set_soft_breakpoint(target, bp);
            }
            if (ret != ERROR_OK)
                return ret;
        }
        bp = bp->next;
    }

    return ERROR_OK;
}

// Пометка всех аппаратных точек останова как не установленных
// Вызывается при записи DBCR0 при инициализации отладочного режима
static void invalidate_hw_breakpoints(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct breakpoint *bp = target->breakpoints;

    assert((ppc476fp->DBCR0_value & DBCR0_IACX_MASK) == 0);

    while (bp != NULL) {
        if (bp->type == BKPT_HARD)
            bp->is_set = 0;
        bp = bp->next;
    }
}

// Внутренняя функция добавления аппаратной точки останова.
// Проверяет, что аппаратных точек останова добавлено не больше, чем
// поддерживает ядро
static int check_add_hw_breakpoint(struct target *target,
                                   struct breakpoint *breakpoint) {
    struct breakpoint *bp;
    int bp_count;

    bp = target->breakpoints;
    bp_count = 0;
    while (bp != NULL) {
        if (bp->type != BKPT_HARD)
            continue;
        if (bp != breakpoint) // do not count the added breakpoint, it may be in
                              // the list
            ++bp_count;
        bp = bp->next;
    }
    if (bp_count == HW_BP_NUMBER)
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

    return ERROR_OK;
}

// Установка точки останова по совпадению адреса данных (предполагается, что она
// создана ранее)
static int set_watchpoint(struct target *target, struct watchpoint *wp) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int ret;
    int dac_index = 0;
    uint32_t dacr_mask;
    uint32_t dacw_mask;
    uint32_t dac_mask;

    assert(wp->is_set == 0);

    while (true) {
        dacr_mask = (DBCR0_DAC1R_MASK >> (dac_index * 2));
        dacw_mask = (DBCR0_DAC1W_MASK >> (dac_index * 2));
        if ((ppc476fp->DBCR0_value & (dacr_mask | dacw_mask)) == 0)
            break;
        ++dac_index;
        assert(dac_index < WP_NUMBER);
    }

    ret = write_spr_reg(target, SPR_REG_NUM_DAC_BASE + dac_index,
                        (uint32_t)wp->address);
    if (ret != ERROR_OK)
        return ret;
    ppc476fp->DAC_value[dac_index] = (uint32_t)wp->address;

    switch (wp->rw) {
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

    ret = write_DBCR0(target, ppc476fp->DBCR0_value | dac_mask);
    if (ret != ERROR_OK)
        return ret;

    wp->is_set = 1;

    return ERROR_OK;
}

// Снятие ранее установленной точки останова по совпадению адреса данных
static int unset_watchpoint(struct target *target, struct watchpoint *wp) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int dac_index = 0;
    uint32_t dacr_mask;
    uint32_t dacw_mask;
    int ret;

    assert(wp->is_set != 0);

    while (true) {
        dacr_mask = (DBCR0_DAC1R_MASK >> (dac_index * 2));
        dacw_mask = (DBCR0_DAC1W_MASK >> (dac_index * 2));
        if ((ppc476fp->DBCR0_value & (dacr_mask | dacw_mask)) != 0) {
            if (ppc476fp->DAC_value[dac_index] == (uint32_t)wp->address)
                break;
        }
        ++dac_index;
        assert(dac_index < WP_NUMBER);
    }

    ret = write_DBCR0(target, ppc476fp->DBCR0_value & ~(dacr_mask | dacw_mask));
    if (ret != ERROR_OK)
        return ret;

    wp->is_set = 0;

    return ERROR_OK;
}

// установка всех созданных точек останова по совпадению адреса данных
static int enable_watchpoints(struct target *target) {
    struct watchpoint *wp = target->watchpoints;
    int ret;

    while (wp != NULL) {
        if (wp->is_set == 0) {
            ret = set_watchpoint(target, wp);
            if (ret != ERROR_OK)
                return ret;
        }
        wp = wp->next;
    }

    return ERROR_OK;
}

// пометка всех точек останова по совпадению адреса как не установленных
// Вызывается при записи DBCR0 при инициализации отладочного режима
static void invalidate_watchpoints(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct watchpoint *wp = target->watchpoints;

    assert((ppc476fp->DBCR0_value & DBCR0_DACX_MASK) == 0);

    while (wp != NULL) {
        wp->is_set = 0;
        wp = wp->next;
    }
}

// пометка всех кэшированных tlb-строк как не валидных
static void invalidate_tlb_cache(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int i;

    for (i = 0; i < TLB_NUMBER; ++i)
        ppc476fp->tlb_cache[i].loaded = false;
}

// сохранение контекста после установки HALT
// процессор обязан быть в состоянии HALT
static int save_state(struct target *target) {
    int ret;

    invalidate_regs_status(target);
    invalidate_tlb_cache(target);

    ret = read_required_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    if (use_stack_get(target)) {
        use_stack_on(target);
    }

    ret = read_required_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int cache_l1i_invalidate(struct target *target) {
    // isync; msync; ici; dci 0; isync; msync;
    int ret = stuff_code(target, 0x4c00012c);
    if (ret != ERROR_OK) {
        return ret;
    }
    ret = stuff_code(target, 0x7c0004ac);
    if (ret != ERROR_OK) {
        return ret;
    }
    ret = stuff_code(target, 0x7c00078c);
    if (ret != ERROR_OK) {
        return ret;
    }
    ret = stuff_code(target, 0x7c00038c);
    if (ret != ERROR_OK) {
        return ret;
    }
    ret = stuff_code(target, 0x4c00012c);
    if (ret != ERROR_OK) {
        return ret;
    }
    ret = stuff_code(target, 0x7c0004ac);
    return ret;
}

// восстановление контекста перед снятием HALT
// процессор обязан быть в состоянии HALT
static int restore_state(struct target *target) {
    int ret;

    ret = write_dirty_fpu_regs(target);
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

    ret = cache_l1i_invalidate(target);
    if (ret != ERROR_OK) {
        return ret;
    }

    invalidate_regs_status(target);
    invalidate_tlb_cache(target);

    return ERROR_OK;
}

// проверка, что процессор в состоянии HALT, правка PC в кэше (при
// необходимости) и восстановление контекста
static int restore_state_before_run(struct target *target, int current,
                                    target_addr_t address,
                                    enum target_debug_reason debug_reason) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int ret;

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    // current = 1: continue on current pc, otherwise continue at <address>
    if (!current) {
        set_reg_value_32(ppc476fp->PC_reg, (uint32_t)address);
        ppc476fp->PC_reg->valid = true;
        ppc476fp->PC_reg->dirty = true;
    }

    target->debug_reason = debug_reason;

    ret = restore_state(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

// сохранение контекста процессора и установка значений регистров, нужных для
// работы отладчика
static int save_state_and_init_debug(struct target *target) {
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

    ret = clear_DBSR(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int reset_and_halt(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint32_t value_JDSR;
    int i;
    int ret;

    unset_all_soft_breakpoints(target); // ignore return value

    target->state = TARGET_RESET;
    invalidate_regs_status(target); // if an error occurs
    ppc476fp->DBCR0_value = 0;
    invalidate_hw_breakpoints(target); // if an error occurs
    invalidate_watchpoints(target);    // if an error occurs

    ret = write_JDCR(target, JDCR_RESET_CHIP | JDCR_STO_MASK);
    if (ret != ERROR_OK)
        return ret;

    // stop the processor
    for (i = 0; i < 100; ++i) {
        ret = write_JDCR(target, JDCR_STO_MASK);
        if (ret != ERROR_OK)
            return ret;

        ret = read_JDSR(target, (uint8_t *)&value_JDSR);
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

static int examine_internal(struct target *target) {
    struct ppc476fp_tap_ext *tap_ext = target_to_ppc476fp_tap_ext(target);
    uint32_t DBDR_value;
    int ret;

    tap_ext->last_coreid = -1;
    ret = read_DBDR(target, (uint8_t *)&DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_DBDR(target, 0xbabadeda);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_DBDR(target, (uint8_t *)&DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    if (DBDR_value != 0xbabadeda) {
        return ERROR_TARGET_FAILURE;
    }

    ret = write_DBDR(target, 0xdedababa);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_DBDR(target, (uint8_t *)&DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    if (DBDR_value != 0xdedababa) {
        return ERROR_TARGET_FAILURE;
    }

    ret = write_DBDR(target, 0xaaaaaaaa);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_DBDR(target, (uint8_t *)&DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    if (DBDR_value != 0xaaaaaaaa) {
        return ERROR_TARGET_FAILURE;
    }

    ret = write_DBDR(target, 0x55555555);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_DBDR(target, (uint8_t *)&DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    if (DBDR_value != 0x55555555) {
        return ERROR_TARGET_FAILURE;
    }

    target->state = TARGET_RUNNING;

    return ERROR_OK;
}

// the target must be halted
static int load_tlb(struct target *target, int index_way,
                    struct tlb_hw_record *hw) {
    int index;
    int way;
    uint32_t search_ind;
    uint32_t mmucr_value;
    int ret;

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    hw->data[0] = 0;
    hw->data[1] = 0;
    hw->data[2] = 0;
    hw->tid = 0;

    index = index_way >> 2;
    way = index_way & 0x3;

    search_ind = (index << 16) | (way << 29);
    ret = write_gpr_reg(target, tmp_reg_addr, search_ind);
    if (ret != ERROR_OK)
        return ret;

    ret =
        stuff_code(target, 0x7C220764 | (tmp_reg_data << 21) |
                               (tmp_reg_addr
                                << 16)); // tlbre tmp_reg_data, tmp_reg_addr, 0
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_reg(target, tmp_reg_data, (uint8_t *)&hw->data[0]);
    if (ret != ERROR_OK)
        return ret;

    // otimization for non-valid UTLB records
    if ((hw->data[0] & TLB_0_V_MASK) == 0)
        return ERROR_OK;

    ret =
        stuff_code(target, 0x7C220F64 | (tmp_reg_data << 21) |
                               (tmp_reg_addr
                                << 16)); // tlbre tmp_reg_data, tmp_reg_addr, 1
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_reg(target, tmp_reg_data, (uint8_t *)&hw->data[1]);
    if (ret != ERROR_OK)
        return ret;

    ret =
        stuff_code(target, 0x7C221764 | (tmp_reg_data << 21) |
                               (tmp_reg_addr
                                << 16)); // tlbre tmp_reg_data, tmp_reg_addr, 2
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_reg(target, tmp_reg_data, (uint8_t *)&hw->data[2]);
    if (ret != ERROR_OK)
        return ret;

    ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, (uint8_t *)&mmucr_value);
    if (ret != ERROR_OK)
        return ret;
    hw->tid = mmucr_value & MMUCR_STID_MASK;

    return ERROR_OK;
}

// the target must be halted
// the function deletes the UTLB record at the specified index_way if the
// 'valid' bit is 0 the function cannot write a bolted UTLB record the function
// does not call 'isync'
static int write_tlb(struct target *target, int index_way,
                     struct tlb_hw_record *hw) {
    uint32_t tid;
    uint32_t data0;
    uint32_t indexed_value;
    int ret;

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
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

    if ((hw->bltd < 6) && (data0 & TLB_0_V_MASK)) {
        indexed_value = 0x8000000 | (hw->bltd << 24);
    } else {
        indexed_value =
            ((index_way & 0x3) << 29) | 0x80000000; // the way is set manually
    }
    ret = write_gpr_reg(target, tmp_reg_data, indexed_value);
    if (ret != ERROR_OK)
        return ret;

    ret = write_gpr_reg(target, tmp_reg_addr, data0);
    if (ret != ERROR_OK)
        return ret;
    ret =
        stuff_code(target, 0x7c0007a4 | (tmp_reg_addr << 21) |
                               (tmp_reg_data
                                << 16)); // tlbwe tmp_reg_addr, tmp_reg_data, 0
    if (ret != ERROR_OK)
        return ret;

    // otimization for non-valid UTLB records
    if ((data0 & TLB_0_V_MASK) == 0)
        return ERROR_OK;

    ret = write_gpr_reg(target, tmp_reg_addr, hw->data[1]);
    if (ret != ERROR_OK)
        return ret;
    ret =
        stuff_code(target, 0x7c000fa4 | (tmp_reg_addr << 21) |
                               (tmp_reg_data
                                << 16)); // tlbwe tmp_reg_addr, tmp_reg_data, 1
    if (ret != ERROR_OK)
        return ret;

    ret = write_gpr_reg(target, tmp_reg_addr, hw->data[2]);
    if (ret != ERROR_OK)
        return ret;
    ret =
        stuff_code(target, 0x7c0017a4 | (tmp_reg_addr << 21) |
                               (tmp_reg_data
                                << 16)); // tlbwe tmp_reg_addr, tmp_reg_data, 2
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int load_uncached_tlb(struct target *target, int index_way) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int ret;

    if (ppc476fp->tlb_cache[index_way].loaded)
        return ERROR_OK;

    ret = load_tlb(target, index_way, &ppc476fp->tlb_cache[index_way].hw);
    if (ret != ERROR_OK)
        return ret;

    ppc476fp->tlb_cache[index_way].loaded = true;

    return ERROR_OK;
}

static int compare_tlb_record(const void *p1, const void *p2) {
    const struct tlb_sort_record *lhv = p1;
    const struct tlb_sort_record *rhv = p2;
    uint32_t v1;
    uint32_t v2;

    if (lhv->hw.tid < rhv->hw.tid)
        return -1;
    if (lhv->hw.tid > rhv->hw.tid)
        return 1;

    v1 = lhv->hw.data[0] & TLB_0_TS_MASK;
    v2 = rhv->hw.data[0] & TLB_0_TS_MASK;
    if (v1 < v2)
        return -1;
    if (v1 > v2)
        return 1;

    v1 = get_bits_32(lhv->hw.data[0], TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN);
    v2 = get_bits_32(rhv->hw.data[0], TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN);
    if (v1 < v2)
        return -1;
    if (v1 > v2)
        return 1;

    return 0;
}

static const char *dsiz_to_string(unsigned dsiz) {
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
    command_print(
        CMD,
        "TID  TS   EPN   V  DSIZ ERPN  RPN  WIMG EN IL1I IL1D U UXWR SXWR  IW");
}

static void print_tlb_table_record(struct command_invocation *cmd,
                                   int index_way, struct tlb_hw_record *hw) {
    char buffer[256];

    sprintf(buffer,
            "%04X  %i %1s%05X  %i  %4s  %03X %05X   %X  %2s  %i    %i   %X   "
            "%X    %X  %02X%i",
            hw->tid, (int)((hw->data[0] & TLB_0_TS_MASK) != 0),
            (hw->data[0] & TLB_0_BLTD_MASK) != 0 ? "*" : "",
            get_bits_32(hw->data[0], TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN),
            (int)((hw->data[0] & TLB_0_V_MASK) != 0),
            dsiz_to_string(get_bits_32(hw->data[0], TLB_0_DSIZ_BIT_POS,
                                       TLB_0_DSIZ_BIT_LEN)),
            get_bits_32(hw->data[1], TLB_1_ERPN_BIT_POS, TLB_1_ERPN_BIT_LEN),
            get_bits_32(hw->data[1], TLB_1_RPN_BIT_POS, TLB_1_RPN_BIT_LEN),
            get_bits_32(hw->data[2], TLB_2_WIMG_BIT_POS, TLB_2_WIMG_BIT_LEN),
            (hw->data[2] & TLB_2_EN_MASK) == 0 ? "BE" : "LE",
            (int)((hw->data[2] & TLB_2_IL1I_MASK) != 0),
            (int)((hw->data[2] & TLB_2_IL1D_MASK) != 0),
            get_bits_32(hw->data[2], TLB_2_U_BIT_POS, TLB_2_U_BIT_LEN),
            get_bits_32(hw->data[2], TLB_2_UXWR_BIT_POS, TLB_2_UXWR_BIT_LEN),
            get_bits_32(hw->data[2], TLB_2_SXWR_BIT_POS, TLB_2_SXWR_BIT_LEN),
            index_way >> 2, index_way & 0x3);
    command_print(CMD, "%s", buffer);
}

static int init_phys_mem(struct target *target, struct phys_mem_state *state) {
    int ret;

    ret = read_MSR(target, (uint8_t *)&state->saved_MSR);
    if (ret != ERROR_OK)
        return ret;

    ret =
        read_spr_reg(target, SPR_REG_NUM_MMUCR, (uint8_t *)&state->saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    ret = read_spr_reg(target, SPR_REG_NUM_PID, (uint8_t *)&state->saved_PID);
    if (ret != ERROR_OK)
        return ret;

    ret =
        read_spr_reg(target, SPR_REG_NUM_USPCR, (uint8_t *)&state->saved_USPCR);
    if (ret != ERROR_OK)
        return ret;

    // set MSR
    ret = write_MSR(target, state->saved_MSR | MSR_PR_MASK |
                                MSR_DS_MASK); // problem mode and TS=1
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
    ret = write_spr_reg(target, SPR_REG_NUM_USPCR,
                        0x70000000); // only 1Gb page with PID
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int restore_phys_mem(struct target *target,
                            struct phys_mem_state *state) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int ret;

    // restore TLB record
    ret = write_tlb(target, PHYS_MEM_TLB_INDEX_WAY,
                    &ppc476fp->tlb_cache[PHYS_MEM_TLB_INDEX_WAY].hw);
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

    return ERROR_OK;
}

static int access_phys_mem(struct target *target, uint32_t new_ERPN_RPN) {
    struct tlb_hw_record hw;
    int ret;

    hw.data[0] = TLB_0_V_MASK | TLB_0_TS_MASK; // TS=1
    hw.data[0] = set_bits_32(PHYS_MEM_BASE_ADDR >> 12, TLB_0_EPN_BIT_POS,
                             TLB_0_EPN_BIT_LEN, hw.data[0]);
    hw.data[0] = set_bits_32(DSIZ_1G, TLB_0_DSIZ_BIT_POS, TLB_0_DSIZ_BIT_LEN,
                             hw.data[0]);

    hw.data[1] = 0;
    hw.data[1] = set_bits_32(new_ERPN_RPN >> 20, TLB_1_ERPN_BIT_POS,
                             TLB_1_ERPN_BIT_LEN, hw.data[1]);
    hw.data[1] = set_bits_32(new_ERPN_RPN & 0xFFFFF, TLB_1_RPN_BIT_POS,
                             TLB_1_RPN_BIT_LEN, hw.data[1]);

    hw.data[2] = TLB_2_IL1I_MASK | TLB_2_IL1D_MASK;
    hw.data[2] =
        set_bits_32(0x7, TLB_2_WIMG_BIT_POS, TLB_2_WIMG_BIT_LEN, hw.data[2]);
    hw.data[2] =
        set_bits_32(0x3, TLB_2_UXWR_BIT_POS, TLB_2_UXWR_BIT_LEN, hw.data[2]);

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

static inline int parse_uint32_params(unsigned param_mask, uint32_t max_value,
                                      const char *param, unsigned *current_mask,
                                      uint32_t *dest) {
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

static inline int parse_dsiz_params(unsigned param_mask, const char *param,
                                    unsigned *current_mask, uint32_t *dest) {
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

static int parse_tlb_command_params(unsigned argc, const char *argv[],
                                    struct tlb_command_params *params) {
    unsigned arg_index;
    const char *arg;
    const char *p;
    char cmd[64];
    int ret;

    memset(params, 0, sizeof *params);
    params->dsiz = DSIZ_4K;
    params->way = -1;
    params->bltd = 6;

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
            ret = parse_uint32_params(TLB_PARAMS_MASK_EPN, 0xFFFFF, p,
                                      &params->mask, &params->epn);
        else if (strcmp(cmd, "rpn") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_RPN, 0xFFFFF, p,
                                      &params->mask, &params->rpn);
        else if (strcmp(cmd, "erpn") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_ERPN, 0x3FF, p,
                                      &params->mask, &params->erpn);
        else if (strcmp(cmd, "tid") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_TID, 0xFFFF, p,
                                      &params->mask, &params->tid);
        else if (strcmp(cmd, "ts") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_TS, 1, p, &params->mask,
                                      &params->ts);
        else if (strcmp(cmd, "il1i") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_IL1I, 1, p, &params->mask,
                                      &params->il1i);
        else if (strcmp(cmd, "il1d") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_IL1D, 1, p, &params->mask,
                                      &params->il1d);
        else if (strcmp(cmd, "u") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_U, 0xF, p, &params->mask,
                                      &params->u);
        else if (strcmp(cmd, "wimg") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_WIMG, 0xF, p,
                                      &params->mask, &params->wimg);
        else if (strcmp(cmd, "uxwr") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_UXWR, 0x7, p,
                                      &params->mask, &params->uxwr);
        else if (strcmp(cmd, "sxwr") == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_SXWR, 0x7, p,
                                      &params->mask, &params->sxwr);
        else if (strcmp(cmd, "dsiz") == 0)
            ret = parse_dsiz_params(TLB_PARAMS_MASK_DSIZ, p, &params->mask,
                                    &params->dsiz);
        else if (strcmp(cmd, "en") == 0) {
            if ((params->mask & TLB_PARAMS_MASK_EN) != 0)
                ret = ERROR_COMMAND_ARGUMENT_INVALID;
            else {
                params->mask |= TLB_PARAMS_MASK_EN;
                if (strcmp(p, "LE") == 0) {
                    params->en = 1;
                    ret = ERROR_OK;
                } else
                    ret = strcmp(p, "BE") == 0 ? ERROR_OK
                                               : ERROR_COMMAND_ARGUMENT_INVALID;
            }
        } else if (strcmp(cmd, "way") == 0) {
            if ((params->mask & TLB_PARAMS_MASK_WAY) != 0)
                ret = ERROR_COMMAND_ARGUMENT_INVALID;
            else {
                if (strcmp(p, "auto") == 0) {
                    params->mask |= TLB_PARAMS_MASK_WAY;
                    params->way = -1;
                    ret = ERROR_OK;
                } else
                    ret = parse_uint32_params(TLB_PARAMS_MASK_WAY, 0x3, p,
                                              &params->mask,
                                              (uint32_t *)&params->way);
            }
        } else if (strcmp(cmd, "bltd") == 0) {
            if ((params->mask & TLB_PARAMS_MASK_BLTD) != 0)
                ret = ERROR_COMMAND_ARGUMENT_INVALID;
            else {
                if (strcmp(p, "no") == 0) {
                    params->mask |= TLB_PARAMS_MASK_BLTD;
                    ret = ERROR_OK;
                } else if (strcmp(p, "auto") == 0) {
                    params->mask |= TLB_PARAMS_MASK_BLTD;
                    ret = ERROR_OK;
                    params->bltd = 7;
                } else
                    ret = parse_uint32_params(TLB_PARAMS_MASK_BLTD, 5, p,
                                              &params->mask, &params->bltd);
            }

        } else
            ret = ERROR_COMMAND_ARGUMENT_INVALID;

        if (ret != ERROR_OK)
            return ret;
    }

    return ERROR_OK;
}

static int handle_tlb_dump_command_internal(struct command_invocation *cmd,
                                            struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct tlb_sort_record records[TLB_NUMBER];
    uint32_t saved_MMUCR;
    uint32_t value_SSPCR;
    uint32_t value_USPCR;
    int i;
    int record_count;
    int ret;

    // save MMUCR
    ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, (uint8_t *)&saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    // load all uncached TLBs
    for (i = 0; i < TLB_NUMBER; ++i) {
        keep_alive();
        ret = load_uncached_tlb(target, i);
        if (ret != ERROR_OK)
            return ret;
    }

    ret = read_spr_reg(target, SPR_REG_NUM_SSPCR, (uint8_t *)&value_SSPCR);
    if (ret != ERROR_OK)
        return ret;
    ret = read_spr_reg(target, SPR_REG_NUM_USPCR, (uint8_t *)&value_USPCR);
    if (ret != ERROR_OK)
        return ret;

    // restore MMUCR
    ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    // process only valid records
    record_count = 0;
    for (i = 0; i < TLB_NUMBER; ++i) {
        if ((ppc476fp->tlb_cache[i].hw.data[0] & TLB_0_V_MASK) != 0) {
            records[record_count].index_way = i;
            records[record_count++].hw = ppc476fp->tlb_cache[i].hw;
        }
    }

    qsort(records, record_count, sizeof(struct tlb_sort_record),
          compare_tlb_record);

    print_tlb_table_header(CMD);
    for (i = 0; i < record_count; ++i) {
        print_tlb_table_record(CMD, records[i].index_way, &records[i].hw);
    }
    command_print(CMD, "SSPCR = 0x%08X, USPCR = 0x%08X", value_SSPCR,
                  value_USPCR);

    return ERROR_OK;
}

static int
handle_tlb_create_command_internal(struct command_invocation *cmd,
                                   struct target *target,
                                   struct tlb_command_params *params) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct tlb_hw_record hw;
    uint32_t saved_MMUCR;
    int index;
    int way;
    int index_way;
    int ret;
    uint32_t bltd;

    // save MMUCR
    ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, (uint8_t *)&saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    switch (params->dsiz) {
    case DSIZ_4K:
        index = (params->tid & 0xFF) ^ (params->epn & 0xFF) ^
                ((params->epn >> 4) & 0xF0) ^ ((params->epn >> 12) & 0xFF);
        break;
    case DSIZ_16K:
        index = (params->tid & 0xFF) ^ ((params->epn >> 2) & 0xFF) ^
                ((params->epn >> 4) & 0xC0) ^ ((params->epn >> 12) & 0xFF);
        break;
    case DSIZ_64K:
        index = (params->tid & 0xFF) ^ ((params->epn >> 4) & 0xFF) ^
                ((params->epn >> 12) & 0xFF);
        break;
    case DSIZ_1M:
        index = (params->tid & 0xFF) ^ ((params->epn >> 8) & 0xFF) ^
                ((params->epn >> 12) & 0xF0);
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

    bltd = params->bltd;

    if (bltd != 6) {
        uint32_t mmube0;
        uint32_t mmube1;
        ret = read_spr_reg(target, SPR_REG_NUM_MMUBE0, (uint8_t *)&mmube0);
        if (ret != ERROR_OK)
            return ret;
        ret = read_spr_reg(target, SPR_REG_NUM_MMUBE1, (uint8_t *)&mmube1);
        if (ret != ERROR_OK)
            return ret;
        way = 0;

        if (bltd == 7) {
            if ((mmube0 & 4) == 0) {
                bltd = 0;
            } else if ((mmube0 & 2) == 0) {
                bltd = 1;
            } else if ((mmube0 & 1) == 0) {
                bltd = 2;
            } else if ((mmube1 & 4) == 0) {
                bltd = 3;
            } else if ((mmube1 & 2) == 0) {
                bltd = 4;
            } else if ((mmube1 & 1) == 0) {
                bltd = 5;
            } else {
                LOG_ERROR("there is no free bltd for the UTLB record");
                return ERROR_FAIL;
            }
        }
        if (((bltd < 3) && (mmube0 & (1 << (2 - bltd)))) ||
            ((bltd >= 3) && (mmube1 & (1 << (5 - bltd))))) {
            LOG_ERROR("the defined bltd is not free");
            return ERROR_FAIL;
        }
    } else {
        way = params->way;
        if (way == -1) {
            for (way = 1; way <= 4; ++way) {
                index_way = (index << 2) | (way % 4);
                ret = load_uncached_tlb(target, index_way);
                if (ret != ERROR_OK)
                    return ret;
                if ((ppc476fp->tlb_cache[index_way].hw.data[0] &
                     TLB_0_V_MASK) == 0)
                    break;
            }
            if (way > 4) {
                LOG_ERROR("there is no free way for the UTLB record");
                return ERROR_FAIL;
            }
            way %= 4;
        }
    }
    index_way = (index << 2) | way;
    ret = load_uncached_tlb(target, index_way);
    if (ret != ERROR_OK)
        return ret;
    if ((ppc476fp->tlb_cache[index_way].hw.data[0] & TLB_0_V_MASK) != 0) {
        LOG_ERROR("the defined way is not free");
        return ERROR_FAIL;
    }

    hw.data[0] = TLB_0_V_MASK;
    hw.data[0] = set_bits_32(params->epn, TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN,
                             hw.data[0]);
    if (params->ts != 0)
        hw.data[0] |= TLB_0_TS_MASK;
    hw.data[0] = set_bits_32(params->dsiz, TLB_0_DSIZ_BIT_POS,
                             TLB_0_DSIZ_BIT_LEN, hw.data[0]);

    hw.data[1] = 0;
    hw.data[1] = set_bits_32(params->rpn, TLB_1_RPN_BIT_POS, TLB_1_RPN_BIT_LEN,
                             hw.data[1]);
    hw.data[1] = set_bits_32(params->erpn, TLB_1_ERPN_BIT_POS,
                             TLB_1_ERPN_BIT_LEN, hw.data[1]);

    hw.data[2] = 0;
    if (params->il1i != 0)
        hw.data[2] |= TLB_2_IL1I_MASK;
    if (params->il1d != 0)
        hw.data[2] |= TLB_2_IL1D_MASK;
    hw.data[2] =
        set_bits_32(params->u, TLB_2_U_BIT_POS, TLB_2_U_BIT_LEN, hw.data[2]);
    hw.data[2] = set_bits_32(params->wimg, TLB_2_WIMG_BIT_POS,
                             TLB_2_WIMG_BIT_LEN, hw.data[2]);
    if (params->en != 0)
        hw.data[2] |= TLB_2_EN_MASK;
    hw.data[2] = set_bits_32(params->uxwr, TLB_2_UXWR_BIT_POS,
                             TLB_2_UXWR_BIT_LEN, hw.data[2]);
    hw.data[2] = set_bits_32(params->sxwr, TLB_2_SXWR_BIT_POS,
                             TLB_2_SXWR_BIT_LEN, hw.data[2]);

    hw.tid = params->tid;
    hw.bltd = bltd;

    ret = write_tlb(target, index_way, &hw);
    if (ret != ERROR_OK)
        return ret;

    // syncing
    ret = stuff_code(target, 0x4C00012C); // isync
    if (ret != ERROR_OK)
        return ret;

    // invalidate and reload UTLB record
    ppc476fp->tlb_cache[index_way].loaded = false;
    ret = load_uncached_tlb(target, index_way);
    if (ret != ERROR_OK)
        return ret;

    print_tlb_table_header(CMD);
    print_tlb_table_record(CMD, index_way, &ppc476fp->tlb_cache[index_way].hw);

    // restore MMUCR
    ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int handle_tlb_drop_command_internal(struct command_invocation *cmd,
                                            struct target *target,
                                            struct tlb_command_params *params) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct tlb_hw_record hw;
    uint32_t saved_MMUCR;
    uint32_t ts;
    int index_way;
    int count = 0;
    int ret;

    // save MMUCR
    ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, (uint8_t *)&saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    memset(&hw, 0, sizeof hw);

    for (index_way = 0; index_way < TLB_NUMBER; ++index_way) {
        keep_alive();
        ret = load_uncached_tlb(target, index_way);
        if (ret != ERROR_OK)
            return ret;

        if ((ppc476fp->tlb_cache[index_way].hw.data[0] & TLB_0_V_MASK) == 0)
            continue;
        if (ppc476fp->tlb_cache[index_way].hw.tid != params->tid)
            continue;
        if (get_bits_32(ppc476fp->tlb_cache[index_way].hw.data[0],
                        TLB_0_EPN_BIT_POS, TLB_0_EPN_BIT_LEN) != params->epn)
            continue;
        ts = ((ppc476fp->tlb_cache[index_way].hw.data[0] & TLB_0_TS_MASK) != 0);
        if (ts != params->ts)
            continue;

        ppc476fp->tlb_cache[index_way].loaded = false;
        ret = write_tlb(target, index_way, &hw);
        if (ret != ERROR_OK)
            return ret;

        // syncing
        ret = stuff_code(target, 0x4C00012C); // isync
        if (ret != ERROR_OK)
            return ret;

        if (count == 0)
            print_tlb_table_header(CMD);
        print_tlb_table_record(CMD, index_way,
                               &ppc476fp->tlb_cache[index_way].hw);
        ++count;
    }

    // restore MMUCR
    ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    if (count == 0)
        command_print(CMD, "No UTLB records have been found");
    else
        command_print(CMD, "The UTLB records above have been deleted (%i)",
                      count);

    return ERROR_OK;
}

static int handle_tlb_drop_all_command_internal(struct target *target) {
    struct tlb_hw_record hw;
    uint32_t saved_MMUCR;
    int i;
    int ret;

    ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, (uint8_t *)&saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    ret = use_fpu_off(target, reg_action_error);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = use_stack_off(target, reg_action_error);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = use_static_mem_off(target, reg_action_error);
    if (ret != ERROR_OK) {
        return ret;
    }

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

    return ERROR_OK;
}

static int ppc476fp_poll(struct target *target) {
    enum target_state state = target->state;
    uint32_t JDSR_value, DBSR_value;
    int ret;

    ret = read_JDSR(target, (uint8_t *)&JDSR_value);
    if (ret != ERROR_OK) {
        target->state = TARGET_UNKNOWN;
        return ret;
    }

    if ((JDSR_value & JDSR_PSP_MASK) != 0)
        state = TARGET_HALTED;
    else
        state = TARGET_RUNNING;

    if ((state == TARGET_HALTED) && (target->state != TARGET_HALTED)) {
        enum target_state prev_state = target->state;
        target->state = state;
        ret = save_state_and_init_debug(target);
        if (ret != ERROR_OK)
            return ret;

        ret = read_spr_reg(target, SPR_REG_NUM_DBSR, (uint8_t *)&DBSR_value);
        if (ret != ERROR_OK)
            return ret;

        if (DBSR_value != 0) {
            if (((DBSR_value & DBSR_IAC_ALL_MASK) != 0) &&
                ((DBSR_value & DBSR_DAC_ALL_MASK) != 0))
                target->debug_reason =
                    DBG_REASON_WPTANDBKPT; // watchpoints and breakpoints
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
static int ppc476fp_arch_state(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);

    LOG_USER("target halted due to %s, coreid=%i, PC: 0x%08X",
             debug_reason_name(target), target->coreid,
             get_reg_value_32(ppc476fp->PC_reg));

    return ERROR_OK;
}

static int ppc476fp_halt(struct target *target) {
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

static int ppc476fp_resume(struct target *target, int current,
                           target_addr_t address, int handle_breakpoints,
                           int debug_execution) {
    LOG_DEBUG("coreid=%i", target->coreid);

    int ret = restore_state_before_run(target, current, address,
                                       DBG_REASON_NOTHALTED);
    if (ret != ERROR_OK)
        return ret;

    ret = write_JDCR(target, 0);
    if (ret != ERROR_OK)
        return ret;

    if (debug_execution) {
        target->state = TARGET_DEBUG_RUNNING;
        target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
    } else {
        target->state = TARGET_RUNNING;
        target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
    }

    return ERROR_OK;
}

static int ppc476fp_step(struct target *target, int current,
                         target_addr_t address, int handle_breakpoints) {
    LOG_DEBUG("coreid=%i", target->coreid);

    uint32_t JDSR_value = 0;
    int ret = restore_state_before_run(target, current, address,
                                       DBG_REASON_SINGLESTEP);
    if (ret != ERROR_OK)
        return ret;

    ret = write_JDCR(target, JDCR_STO_MASK | JDCR_SS_MASK);
    if (ret != ERROR_OK)
        return ret;

    target->state = TARGET_RUNNING;
    target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
    for (int i = 0; i < 100; ++i) {
        ret = read_JDSR(target, (uint8_t *)&JDSR_value);
        if (ret != ERROR_OK) {
            target->state = TARGET_UNKNOWN;
            return ret;
        }
        if ((JDSR_value & JDSR_PSP_MASK) == JDSR_PSP_MASK) {
            target->state = TARGET_HALTED;
            ret = save_state_and_init_debug(target);
            if (ret != ERROR_OK) {
                target->state = TARGET_UNKNOWN;
                return ret;
            }
            target_call_event_callbacks(target, TARGET_EVENT_HALTED);
            return ERROR_OK;
        }
    }

    target->state = TARGET_UNKNOWN;

    return ERROR_OK;
}

static int ppc476fp_assert_reset(struct target *target) {
    LOG_DEBUG("coreid=%i", target->coreid);

    invalidate_regs_status(target);
    invalidate_tlb_cache(target);
    use_fpu_off(target, reg_action_ignore);
    use_stack_off(target, reg_action_ignore);
    use_static_mem_off(target, reg_action_ignore);

    return reset_and_halt(target);
}

static int ppc476fp_deassert_reset(struct target *target) {
    int ret;

    LOG_DEBUG("coreid=%i", target->coreid);

    if (target->reset_halt == 0) {
        // contunue executing
        ret = write_JDCR(target, 0);
        if (ret != ERROR_OK)
            return ret;
    }

    return ERROR_OK;
}

static int ppc476fp_soft_reset_halt(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    int ret;

    LOG_DEBUG("coreid=%i", target->coreid);

    ret = reset_and_halt(target);
    if (ret != ERROR_OK)
        return ret;

    // restore a register state after the reset
    set_reg_value_32(ppc476fp->PC_reg, 0xFFFFFFC);
    ppc476fp->PC_reg->dirty = true;
    set_reg_value_32(ppc476fp->MSR_reg, 0);
    ppc476fp->MSR_reg->dirty = true;
    // [***] other register must be restored - otherwise the soft reset does not
    // work

    // restore state with breakpoints
    ret = restore_state(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int ppc476fp_get_gdb_reg_list(struct target *target,
                                     struct reg **reg_list[],
                                     int *reg_list_size,
                                     enum target_register_class reg_class) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);

    *reg_list_size = GDB_REG_COUNT;
    *reg_list = malloc(sizeof(struct reg *) * GDB_REG_COUNT);
    memcpy(*reg_list, ppc476fp->all_regs, sizeof(struct reg *) * GDB_REG_COUNT);

    return ERROR_OK;
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG
// communication BUG
static int ppc476fp_read_memory(struct target *target, target_addr_t address,
                                uint32_t size, uint32_t count,
                                uint8_t *buffer) {
    uint32_t i;
    int ret;

    LOG_DEBUG("coreid=%i, address: 0x%lX, size: %u, count: 0x%X",
              target->coreid, address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) ||
        !(buffer))
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

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG
// communication BUG
static int ppc476fp_write_memory(struct target *target, target_addr_t address,
                                 uint32_t size, uint32_t count,
                                 const uint8_t *buffer) {
    uint32_t i;
    int ret;

    LOG_DEBUG("coreid=%i, address=0x%lX, size=%u, count=0x%X", target->coreid,
              address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) ||
        !(buffer))
        return ERROR_COMMAND_SYNTAX_ERROR;

    if (((size == 4) && (address & 0x3u)) ||
        ((size == 2) && (address & 0x1u))) {
        LOG_ERROR("unaligned access");
        return ERROR_TARGET_UNALIGNED_ACCESS;
    }

    for (i = 0; i < count; ++i) {
        keep_alive();
        ret = write_virt_mem(target, (uint32_t)address, size, buffer);
        if (ret != ERROR_OK)
            return ret;
        address += size;
        buffer += size;
    }

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int ppc476fp_checksum_memory(struct target *target,
                                    target_addr_t address, uint32_t count,
                                    uint32_t *checksum) {
    return ERROR_FAIL;
}

static int ppc476fp_add_breakpoint(struct target *target,
                                   struct breakpoint *breakpoint) {
    int ret;

    LOG_DEBUG("coreid=%i, address=0x%lX, type=%i, length=0x%X", target->coreid,
              breakpoint->address, breakpoint->type, breakpoint->length);

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    if (breakpoint->length != 4)
        return ERROR_TARGET_UNALIGNED_ACCESS;

    if ((breakpoint->address & 0x3) != 0)
        return ERROR_TARGET_UNALIGNED_ACCESS;

    breakpoint->is_set = 0;
    memset(breakpoint->orig_instr, 0, 4);

    if (breakpoint->type == BKPT_HARD) {
        ret = check_add_hw_breakpoint(target, breakpoint);
        if (ret != ERROR_OK)
            return ret;
    }

    return ERROR_OK;
}

static int ppc476fp_remove_breakpoint(struct target *target,
                                      struct breakpoint *breakpoint) {
    int ret;

    LOG_DEBUG("coreid=%i, address=0x%lX, type=%i, length=0x%X", target->coreid,
              breakpoint->address, breakpoint->type, breakpoint->length);

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    if (breakpoint->is_set == 0)
        return ERROR_OK;

    if (breakpoint->type == BKPT_HARD) {
        ret = unset_hw_breakpoint(target, breakpoint);
        if (ret != ERROR_OK)
            return ret;
    } else {
        ret = unset_soft_breakpoint(target, breakpoint);
        if (ret != ERROR_OK)
            return ret;
    }

    return ERROR_OK;
}

static int ppc476fp_add_watchpoint(struct target *target,
                                   struct watchpoint *watchpoint) {
    struct watchpoint *wp;
    int wp_count;

    LOG_DEBUG("coreid=%i, address=0x%08lX, rw=%i, length=%u, value=0x%08X, "
              "mask=0x%08X",
              target->coreid, watchpoint->address, watchpoint->rw,
              watchpoint->length, watchpoint->value, watchpoint->mask);

    watchpoint->is_set = 0;

    if ((watchpoint->length != 1) && (watchpoint->length != 2) &&
        (watchpoint->length != 4))
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

    if (watchpoint->mask != 0xFFFFFFFF)
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

    wp = target->watchpoints;
    wp_count = 0;
    while (wp != NULL) {
        if (wp != watchpoint) // do not count the added watchpoint, it may be in
                              // the list
            ++wp_count;
        wp = wp->next;
    }
    if (wp_count == WP_NUMBER)
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;

    return ERROR_OK;
}

static int ppc476fp_remove_watchpoint(struct target *target,
                                      struct watchpoint *watchpoint) {
    int ret;

    LOG_DEBUG("coreid=%i, address=0x%08lX, rw=%i, length=%u, value=0x%08X, "
              "mask=0x%08X",
              target->coreid, watchpoint->address, watchpoint->rw,
              watchpoint->length, watchpoint->value, watchpoint->mask);

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    if (watchpoint->is_set == 0)
        return ERROR_OK;

    ret = unset_watchpoint(target, watchpoint);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int ppc476fp_target_create(struct target *target, Jim_Interp *interp) {
    struct ppc476fp_common *ppc476fp =
        calloc(1, sizeof(struct ppc476fp_common));
    target->arch_info = ppc476fp;

    LOG_DEBUG("coreid=%i", target->coreid);

    if ((target->coreid < 0) || (target->coreid > 3)) {
        LOG_ERROR("coreid=%i is not allowed. It must be from 0 to 3. It has "
                  "been set to 0.",
                  target->coreid);
        target->coreid = 0;
    }

    return ERROR_OK;
}

static int ppc476fp_init_target(struct command_context *cmd_ctx,
                                struct target *target) {
    LOG_DEBUG("coreid=%i", target->coreid);

    build_reg_caches(target);

    if (target->tap->priv == NULL) {
        struct ppc476fp_tap_ext *tap_ext =
            malloc(sizeof(struct ppc476fp_tap_ext));
        tap_ext->last_coreid = -1;
        target->tap->priv = tap_ext;
        LOG_DEBUG("The TAP extera struct has been created, coreid=%i",
                  target->coreid);
    } else {
        LOG_DEBUG("The TAP extra struct has already been created, coreid=%i",
                  target->coreid);
    }

    return ERROR_OK;
}

static int ppc476fp_examine(struct target *target) {
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

static int ppc476fp_virt2phys(struct target *target, target_addr_t address,
                              target_addr_t *physical) {
    LOG_DEBUG("coreid=%i", target->coreid);

    *physical = 0;

    return ERROR_TARGET_TRANSLATION_FAULT;
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG
// communication BUG
static int ppc476fp_read_phys_memory(struct target *target,
                                     target_addr_t address, uint32_t size,
                                     uint32_t count, uint8_t *buffer) {
    struct phys_mem_state state;
    uint32_t last_ERPN_RPN = -1; // not setuped yet
    uint32_t new_ERPN_RPN;
    uint32_t i;
    int ret;

    LOG_DEBUG("coreid=%i, address=0x%lX, size=%u, count=0x%X", target->coreid,
              address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) ||
        !(buffer))
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

        ret = read_virt_mem(
            target, (uint32_t)(address & 0x3FFFFFFF) + PHYS_MEM_BASE_ADDR, size,
            buffer);
        if (ret != ERROR_OK)
            return ret;

        address += size;
        buffer += size;
    }

    // restore state
    ret = restore_phys_mem(target, &state);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG
// communication BUG
static int ppc476fp_write_phys_memory(struct target *target,
                                      target_addr_t address, uint32_t size,
                                      uint32_t count, const uint8_t *buffer) {
    struct phys_mem_state state;
    uint32_t last_ERPN_RPN = -1; // not setuped yet
    uint32_t new_ERPN_RPN;
    uint32_t i;
    int ret;

    LOG_DEBUG("coreid=%i, address=0x%lX, size=%u, count=0x%X", target->coreid,
              address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) ||
        !(buffer))
        return ERROR_COMMAND_SYNTAX_ERROR;

    if (((size == 4) && (address & 0x3u)) ||
        ((size == 2) && (address & 0x1u))) {
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
        ret = write_virt_mem(
            target, (uint32_t)(address & 0x3FFFFFFF) + PHYS_MEM_BASE_ADDR, size,
            buffer);
        if (ret != ERROR_OK)
            return ret;
        address += size;
        buffer += size;
    }

    // the JTAG queue will be executed during the state restoring

    // restore state
    ret = restore_phys_mem(target, &state);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int ppc476fp_mmu(struct target *target, int *enabled) {
    *enabled = 1;
    return ERROR_OK;
}

static bool use_fpu_get(struct target *target) {
    return target_to_ppc476fp(target)->use_fpu;
}

static int use_fpu_on(struct target *target) {
    if (use_stack_get(target) || use_static_mem_get(target)) {
        target_to_ppc476fp(target)->use_fpu = true;
        return ERROR_OK;
    }
    return ERROR_FAIL;
}

static int use_fpu_off(struct target *target, enum reg_action action) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    if (!use_fpu_get(target)) {
        return ERROR_OK;
    }
    switch (action) {
    case reg_action_ignore: {
        for (int i = 0; i < FPR_REG_COUNT; ++i) {
            ppc476fp->fpr_regs[i]->valid = false;
            ppc476fp->fpr_regs[i]->dirty = false;
        }
        ppc476fp->use_fpu = false;
    }
        return ERROR_OK;
    case reg_action_error: {
        for (int i = 0; i < FPR_REG_COUNT; ++i) {
            if (ppc476fp->fpr_regs[i]->dirty == true) {
                return ERROR_FAIL;
            }
        }
        ppc476fp->use_fpu = false;
    }
        return ERROR_OK;
    case reg_action_flush: {
        if (target->state == TARGET_RUNNING) {
            return ERROR_OK;
        }
        int ret = write_dirty_fpu_regs(target);
        if (ret != ERROR_OK) {
            return ret;
        }
        ppc476fp->use_fpu = false;
    }
        return ERROR_FAIL;
    }
    return ERROR_FAIL;
}

static bool use_stack_get(struct target *target) {
    return target_to_ppc476fp(target)->use_stack;
}

static int use_stack_on(struct target *target) {
    int ret = ERROR_OK;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    if (target->state == TARGET_HALTED) {
        ret = test_memory_at_stack(target);
        if (ret != ERROR_OK) {
            LOG_ERROR("test_memory_at_stack failed, disable use_stack");
            use_stack_off(target, reg_action_ignore);
            return ret;
        }
    }
    ppc476fp->use_stack = true;
    return ERROR_OK;
}

static int use_stack_off(struct target *target, enum reg_action action) {
    int ret = ERROR_OK;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    if (!use_fpu_get(target) || use_static_mem_get(target)) {
        ppc476fp->use_stack = false;
        return ERROR_OK;
    }
    LOG_INFO("use_fpu enabled, disabling");
    ret = use_fpu_off(target, action);
    if (ret != ERROR_OK) {
        return ret;
    }
    ppc476fp->use_stack = false;
    return ERROR_OK;
}

static bool use_static_mem_get(struct target *target) {
    return target_to_ppc476fp(target)->use_static_mem != 0xffffffff;
}

static uint32_t use_static_mem_addr(struct target *target) {
    return target_to_ppc476fp(target)->use_static_mem;
}

static int use_static_mem_on(struct target *target, uint32_t base_addr) {
    if (base_addr & 0x07) {
        LOG_ERROR("addr must be aligned by 8");
        return ERROR_FAIL;
    }
    target_to_ppc476fp(target)->use_static_mem = base_addr;
    return ERROR_OK;
}

static int use_static_mem_off(struct target *target, enum reg_action action) {
    int ret = ERROR_OK;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    if (!use_fpu_get(target) || use_stack_get(target)) {
        ppc476fp->use_static_mem = 0xffffffff;
        return ERROR_OK;
    }
    LOG_INFO("use_fpu enabled, disabling");
    ret = use_fpu_off(target, action);
    if (ret != ERROR_OK) {
        return ret;
    }
    ppc476fp->use_static_mem = 0xffffffff;
    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_tlb_dump_command) {
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

COMMAND_HANDLER(ppc476fp_handle_tlb_create_command) {
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

    if ((params.mask & TLB_PARAMS_MASK_BLTD) && (params.way > 0)) {
        LOG_ERROR("parameter 'way' is incompatible with 'bltd'");
        return ERROR_COMMAND_ARGUMENT_INVALID;
    }

    ret = handle_tlb_create_command_internal(CMD, target, &params);
    if (ret != ERROR_OK) {
        LOG_ERROR("error executing the command %i", ret);
        return ret;
    }

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_tlb_drop_command) {
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

    if ((params.mask & ~(TLB_PARAMS_MASK_EPN | TLB_PARAMS_MASK_TID |
                         TLB_PARAMS_MASK_TS | TLB_PARAMS_MASK_BLTD)) != 0) {
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

COMMAND_HANDLER(ppc476fp_handle_tlb_drop_all_command) {
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

COMMAND_HANDLER(ppc476fp_handle_status_command) {
    struct target *target = get_current_target(CMD_CTX);
    uint32_t JDSR_value;
    int ret;

    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    ret = read_JDSR(target, (uint8_t *)&JDSR_value);
    if (ret != ERROR_OK) {
        command_print(CMD, "cannot read JDSR register");
        return ret;
    }

    command_print(CMD, "PowerPC JTAG status:");
    command_print(CMD, "  JDSR = 0x%08X", JDSR_value);

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_jtag_speed_command) {
    struct target *target = get_current_target(CMD_CTX);
    int64_t start_time = timeval_ms();
    uint32_t count = 0;
    uint32_t dummy_data;
    int ret;

    while (timeval_ms() - start_time < 1000) {
        ret = read_DBDR(target, (uint8_t *)&dummy_data);
        if (ret != ERROR_OK) {
            command_print(CMD, "JTAG communication error");
            return ret;
        }
        ++count;
    }

    command_print(CMD, "JTAG speed = %u (transaction per second)", count);

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_dcr_read_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);

    int ret = parse_u32(CMD_ARGV[0], &addr);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_DCR(target, addr, &data);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    command_print(CMD, "DCR %u(0x%x) = %u(0x%08x)", addr, addr, data, data);

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_dcr_write_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);

    int ret;
    ret = parse_u32(CMD_ARGV[0], &addr);
    if (ret != ERROR_OK) {
        return ret;
    }
    ret = parse_u32(CMD_ARGV[1], &data);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_DCR(target, addr, data);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_spr_read_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);

    int ret = parse_u32(CMD_ARGV[0], &addr);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_spr_reg(target, addr, (uint8_t *)&data);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    command_print(CMD, "SPR %u(0x%x) = %u(0x%08x)", addr, addr, data, data);

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_spr_write_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);

    int ret;
    ret = parse_u32(CMD_ARGV[0], &addr);
    if (ret != ERROR_OK) {
        return ret;
    }
    ret = parse_u32(CMD_ARGV[1], &data);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_spr_reg(target, addr, data);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_fpu_on_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;
    struct target *target = get_current_target(CMD_CTX);

    int ret = use_fpu_on(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;
    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_fpu_get_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    if (use_fpu_get(get_current_target(CMD_CTX))) {
        command_print(CMD, "fpu using enabled");
    } else {
        command_print(CMD, "fpu using disabled");
    }

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_fpu_off_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;

    struct target *target = get_current_target(CMD_CTX);
    enum reg_action action = reg_action_ignore;

    if (strcmp(CMD_ARGV[0], "flush") == 0) {
        action = reg_action_flush;
    } else if (strcmp(CMD_ARGV[0], "ignore") == 0) {
        action = reg_action_ignore;
    } else if (strcmp(CMD_ARGV[0], "error") == 0) {
        action = reg_action_error;
    } else {
        return ERROR_COMMAND_SYNTAX_ERROR;
    }

    int ret = use_fpu_off(target, action);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;
    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_stack_on_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    struct target *target = get_current_target(CMD_CTX);
    int ret = use_stack_on(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;
    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_stack_get_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    if (use_stack_get(get_current_target(CMD_CTX))) {
        command_print(CMD, "stack using enabled");
    } else {
        command_print(CMD, "stack using disabled");
    }

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_stack_off_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    struct target *target = get_current_target(CMD_CTX);
    int ret = use_stack_off(target, reg_action_error);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;
    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_static_mem_on_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    struct target *target = get_current_target(CMD_CTX);

    int ret = parse_u32(CMD_ARGV[0], &addr);
    if (ret != ERROR_OK) {
        LOG_ERROR("\"%s\" not a valid addr", CMD_ARGV[0]);
        return ERROR_COMMAND_ARGUMENT_INVALID;
    }

    ret = use_static_mem_on(target, addr);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;
    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_static_mem_get_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    struct target *target = get_current_target(CMD_CTX);

    if (use_static_mem_get(target)) {
        command_print(CMD, "static memory using enabled, addr: 0x%08x",
                      use_static_mem_addr(target));
    } else {
        command_print(CMD, "static memory using disabled");
    }

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_static_mem_off_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;
    struct target *target = get_current_target(CMD_CTX);

    int ret = use_static_mem_off(target, reg_action_error);

    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    ret = write_dirty_gen_regs(target);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static const struct command_registration ppc476fp_tlb_drop_command_handlers[] =
    {{.name = "all",
      .handler = ppc476fp_handle_tlb_drop_all_command,
      .mode = COMMAND_EXEC,
      .usage = "",
      .help = "delete all UTLB records"},
     COMMAND_REGISTRATION_DONE};

static const struct command_registration ppc476fp_tlb_exec_command_handlers[] =
    {{.name = "dump",
      .handler = ppc476fp_handle_tlb_dump_command,
      .mode = COMMAND_EXEC,
      .usage = "",
      .help = "dump all valid UTLB records"},
     {.name = "create",
      .handler = ppc476fp_handle_tlb_create_command,
      .mode = COMMAND_EXEC,
      .usage = "epn=<xxx> rpn=<xxx> [erpn=0] [tid=0] [ts=0] [dsiz=4k] "
               "[way=auto] [bltd=no] [il1i=0] [il1d=0] [u=0] [wimg=0] [en=BE] "
               "[uxwr=0] [sxwr=0]",
      .help = "create new UTLB record"},
     {.name = "drop",
      .handler = ppc476fp_handle_tlb_drop_command,
      .mode = COMMAND_EXEC,
      .usage = "epn=<xxx> [tid=0] [ts=0]",
      .help = "delete UTLB record",
      .chain = ppc476fp_tlb_drop_command_handlers},
     COMMAND_REGISTRATION_DONE};
static const struct command_registration ppc476fp_dcr_exec_command_handlers[] =
    {{.name = "read",
      .handler = ppc476fp_handle_dcr_read_command,
      .mode = COMMAND_EXEC,
      .usage = "<num>",
      .help = "read from DCR <num>"},
     {.name = "write",
      .handler = ppc476fp_handle_dcr_write_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <data>",
      .help = "write <data> to DCR <num>"},
     COMMAND_REGISTRATION_DONE};

static const struct command_registration ppc476fp_spr_exec_command_handlers[] =
    {{.name = "read",
      .handler = ppc476fp_handle_spr_read_command,
      .mode = COMMAND_EXEC,
      .usage = "<num>",
      .help = "read from SPR <num>"},
     {.name = "write",
      .handler = ppc476fp_handle_spr_write_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <data>",
      .help = "write <data> to SPR <num>"},
     COMMAND_REGISTRATION_DONE};

static const struct command_registration
    ppc476fp_use_fpu_exec_command_handlers[] = {
        {.name = "on",
         .handler = ppc476fp_handle_use_fpu_on_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "enable read and write fp regs"},
        {.name = "off",
         .handler = ppc476fp_handle_use_fpu_off_command,
         .mode = COMMAND_EXEC,
         .usage = "<flush|ignore|error>",
         .help = "disable read and write fp regs; flush - flush all dirty "
                 "regs; ignore - not flush dirty regs; error - return error if "
                 "there are dirty regs"},
        {.name = "get",
         .handler = ppc476fp_handle_use_fpu_get_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "read and write fp regs enabled?"},
        COMMAND_REGISTRATION_DONE};

static const struct command_registration
    ppc476fp_use_stack_exec_command_handlers[] = {
        {.name = "on",
         .handler = ppc476fp_handle_use_stack_on_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "enable using stack in openocd"},
        {.name = "off",
         .handler = ppc476fp_handle_use_stack_off_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "disable using stack in openocd"},
        {.name = "get",
         .handler = ppc476fp_handle_use_stack_get_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "using stack in openocd enabled?"},
        COMMAND_REGISTRATION_DONE};

static const struct command_registration
    ppc476fp_use_static_mem_exec_command_handlers[] = {
        {.name = "on",
         .handler = ppc476fp_handle_use_static_mem_on_command,
         .mode = COMMAND_EXEC,
         .usage = "<base addr>",
         .help = "enable using static memory in openocd"},
        {.name = "off",
         .handler = ppc476fp_handle_use_static_mem_off_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "disable using static mememory in openocd"},
        {.name = "get",
         .handler = ppc476fp_handle_use_static_mem_get_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "using static memory in openocd enabled?"},
        COMMAND_REGISTRATION_DONE};

static const struct command_registration ppc476fp_exec_command_handlers[] = {
    {.name = "tlb",
     .handler = ppc476fp_handle_tlb_dump_command,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "ppc476fp tlb command group",
     .chain = ppc476fp_tlb_exec_command_handlers},
    {.name = "status",
     .handler = ppc476fp_handle_status_command,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "display status"},
    {.name = "jtag_speed",
     .handler = ppc476fp_handle_jtag_speed_command,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "display jtag speed (transaction per second)"},
    {.name = "dcr",
     .chain = ppc476fp_dcr_exec_command_handlers,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "read and write dcr"},
    {.name = "spr",
     .chain = ppc476fp_spr_exec_command_handlers,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "read and write spr"},
    {.name = "use_fpu",
     .chain = ppc476fp_use_fpu_exec_command_handlers,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "use or not fp regs in openocd"},
    {.name = "use_stack",
     .chain = ppc476fp_use_stack_exec_command_handlers,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "use free stack in openocd internal func"},
    {.name = "use_static_mem",
     .chain = ppc476fp_use_static_mem_exec_command_handlers,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "use static memory region in openocd internal func, must be "
             "aligned at 8 bytes and 1k size"},
    COMMAND_REGISTRATION_DONE};

const struct command_registration ppc476fp_command_handlers[] = {
    {.name = "ppc476fp",
     .mode = COMMAND_ANY,
     .help = "ppc476fp command group",
     .usage = "",
     .chain = ppc476fp_exec_command_handlers},
    COMMAND_REGISTRATION_DONE};

struct target_type ppc476fp_target = {
    .name = "ppc476fp",

    .poll = ppc476fp_poll,
    .arch_state = ppc476fp_arch_state,

    .halt = ppc476fp_halt,
    .resume = ppc476fp_resume,
    .step = ppc476fp_step,

    .assert_reset = ppc476fp_assert_reset,
    .deassert_reset = ppc476fp_deassert_reset,
    .soft_reset_halt = ppc476fp_soft_reset_halt,

    .get_gdb_reg_list = ppc476fp_get_gdb_reg_list,

    .read_memory = ppc476fp_read_memory,
    .write_memory = ppc476fp_write_memory,

    .checksum_memory = ppc476fp_checksum_memory,

    .add_breakpoint = ppc476fp_add_breakpoint,
    .remove_breakpoint = ppc476fp_remove_breakpoint,
    .add_watchpoint = ppc476fp_add_watchpoint,
    .remove_watchpoint = ppc476fp_remove_watchpoint,

    .commands = ppc476fp_command_handlers,
    .target_create = ppc476fp_target_create,
    .init_target = ppc476fp_init_target,
    .examine = ppc476fp_examine,

    .virt2phys = ppc476fp_virt2phys,
    .read_phys_memory = ppc476fp_read_phys_memory,
    .write_phys_memory = ppc476fp_write_phys_memory,
    .mmu = ppc476fp_mmu};
