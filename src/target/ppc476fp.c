#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ppc476fp_stuffs.h"
#include "ppc476fp_l2.h"

#include "ppc476fp.h"

#include <helper/log.h>

static bool is_halted(uint32_t jdsr){
    if ((jdsr&JDSR_DWE_MASK)!=0){
        if ((jdsr & (JDSR_UDE_MASK | JDSR_DE_MASK)))
            return true;
        else
            return false;
    }else{
        if ((jdsr & JDSR_PSP_MASK) != 0)
            return true;
        else
            return false;
    }
}

static int flush_registers(struct target* target){
    int ret = ERROR_OK;
    if ( use_fpu_get(target) ){
        ret = write_dirty_fpu_regs(target);
    }
    if ( ret != ERROR_OK ){
        return ret;
    }
    ret = write_dirty_gen_regs(target);
    if ( ret != ERROR_OK ){
        return ret;
    }
    return ERROR_OK;
}

static int jdsr_log_ser(uint32_t JDSR){
    int ret = ERROR_OK;
    if (JDSR & JDSR_FPU_MASK){
        LOG_ERROR("Floating point unit unavailable exception");
        ret = ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    if (JDSR & JDSR_APU_MASK){
        LOG_ERROR("Auxiliary processor unit unavailable exception");
        ret = ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    if (JDSR & JDSR_ISE_MASK){
        LOG_DEBUG("Instruction storage exception");
    }
    if (JDSR & JDSR_DTM_MASK){
        LOG_ERROR("Data TLB miss exception");
        ret = ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    if (JDSR & JDSR_ITM_MASK){
        LOG_ERROR("Instruction TLB miss exception");
        ret = ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    if (JDSR & JDSR_RMCE_MASK){
        LOG_DEBUG("Return from machine check exception");
    }
    if (JDSR & JDSR_DSE_MASK){
        LOG_ERROR("Data storage exception");
        ret = ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    if (JDSR & JDSR_AE_MASK){
        LOG_ERROR("Alignment error");
        ret = ERROR_TARGET_UNALIGNED_ACCESS;
    }
    if (JDSR & JDSR_PE_MASK){
        LOG_ERROR("Program exception");
        ret = ERROR_TARGET_TRANSLATION_FAULT;
    }
    if (JDSR & JDSR_SC_MASK){
        LOG_DEBUG("System call");
    }
    if (JDSR & JDSR_RFI_MASK){
        LOG_DEBUG("Return from interrupt");
    }
    if (JDSR & JDSR_RCFI_MASK){
        LOG_DEBUG("Return from critical interrupt");
    }
    if (JDSR & JDSR_IMC_MASK){
        LOG_ERROR("Instruction-side machine check");
        ret = ERROR_TARGET_TRANSLATION_FAULT;
    }
    if (JDSR & JDSR_SFP_MASK){
        LOG_ERROR("Stuff pending. Possibly the processor is frozen. Try reset");
        ret = ERROR_TARGET_FAILURE;
    }
    if (JDSR & JDSR_ISO_MASK){
        LOG_ERROR("Instruction stuff overrun. Processor must have frozen. Try reset");
        ret = ERROR_TARGET_FAILURE;
    }
    return ret;
}

static inline uint32_t get_bits_32(uint32_t value, unsigned pos, unsigned len) {
    return (value >> pos) & ((1U << len) - 1);
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
    return buf_get_u32(reg->value,0,32);
}

static inline void set_reg_value_32(struct reg *reg, uint32_t value) {
    reg->dirty = true;
    reg->valid = true;
    buf_set_u32(reg->value, 0, 32, value);
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
    uint8_t instr_buffer[4] = {0,0,0,0};
    uint8_t tap_alive[2][4] = {{0,0,0,0},{0,0,0,0}};
    struct scan_field data_fields;
    uint8_t data_out_buffer[8] = {0,0,0,0,0,0,0,0};
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
    instr_field.in_value = tap_alive[0];
    jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);

    buf_set_u32(data_out_buffer, 0, 32, write_data);
    buf_set_u32(data_out_buffer, 32, 1, valid_bit);
    data_fields.num_bits = 33;
    data_fields.out_value = data_out_buffer;
    data_fields.in_value = data_in_buffer;
    jtag_add_dr_scan(target->tap, 1, &data_fields, TAP_IDLE);
    target_to_ppc476fp(target)->transactions++;

    // !!! IMPORTANT
    // make additional request with valid bit == 0
    // to correct a JTAG communication BUG
    if (valid_bit != 0) {
        instr_field.in_value = tap_alive[1];
        jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);
        data_fields.out_value = (uint8_t *)zeros;
        jtag_add_dr_scan(target->tap, 1, &data_fields, TAP_IDLE);
        target_to_ppc476fp(target)->transactions++;
    }

    ret = jtag_execute_queue();
    if (ret != ERROR_OK)
        return ret;

    if (read_data != NULL) {
        buf_cpy(data_in_buffer, read_data, 32);
    }

    uint32_t tap_alive1 = 0, tap_alive2 = 0;
    buf_cpy(tap_alive[0], &tap_alive1, target->tap->ir_length);
    buf_cpy(tap_alive[1], &tap_alive2, target->tap->ir_length);
    
    if ( (tap_alive1 == 1) && (!valid_bit || (tap_alive2 == 1)) ){
        return ERROR_OK;
    }else{
        target->state = TARGET_UNKNOWN;
        return ERROR_JTAG_DEVICE_ERROR;
    }
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
    uint32_t JDSR = 0;
    int ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_JDCR_READ_JDSR,
                                    true, data, (uint8_t*)&JDSR);
    if (ret != ERROR_OK){
        return ret;
    }

    ret = jdsr_log_ser(JDSR);
    if ( ret == ERROR_TARGET_FAILURE ){
        target->state = TARGET_UNKNOWN;
    }
    return ret;
}

// запись JTAG-регистра JISB. Регистр доступен только для записи. Запись в этот
// регистр напрямую вставляет код инструкции в конвеер и исполняет её.
static int stuff_code(struct target *target, uint32_t code) {
    uint32_t JDSR = 0;
    if ( target->state != TARGET_HALTED ){
        return ERROR_TARGET_NOT_HALTED;
    }
    int ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR,
                                    true, code, (uint8_t *)&JDSR);
    if (ret != ERROR_OK){
        return ret;
    }
    for ( int i = 100 ; (i > 0) && (JDSR&JDSR_SFP_MASK) ; --i ){
        ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR,
                                        false, code, (uint8_t *)&JDSR);
        if (ret != ERROR_OK){
            return ret;
        }
    }

    ret = jdsr_log_ser(JDSR);
    if ( ret == ERROR_TARGET_FAILURE ){
        target->state = TARGET_UNKNOWN;
    }
    return ret;
}

// чтение РОН через JTAG. Значение РОН при этом не меняется, но обычно
// происходит после инструкций, изменяющих значене регистра
static int read_gpr_reg(struct target *target, int reg_num, uint8_t *data) {
    struct ppc476fp_common * ppc476fp = target_to_ppc476fp(target);
    int ret = stuff_code(target, mtspr(SPR_REG_NUM_DBDR,reg_num));
    if (ret != ERROR_OK)
        return ret;

    ret = read_DBDR(target, data);
    if ( ret != ERROR_OK ){
        ppc476fp->current_gpr_values_valid[reg_num] = false;
        return ret;
    }
    ppc476fp->current_gpr_values[reg_num] = buf_get_u32(data,0,32);
    ppc476fp->current_gpr_values_valid[reg_num] = true;

    return ERROR_OK;
}

// запись РОН через JTAG. Никак не связано с управляющими командами от GDB,
// нужно для выполнения отладочных действий (вроде росписи памяти).
// автоматически помечает регистр как dirty для того, чтобы заменить его
// значение на эталонное при снятии halt
static int write_gpr_reg(struct target *target, int reg_num, uint32_t data) {
    int32_t data_signed = data;
    bool need_full_write = true;
    struct ppc476fp_common * ppc476fp = target_to_ppc476fp(target);
    int ret = ERROR_OK;
    ppc476fp->gpr_regs[reg_num]->dirty = true;
    if ( ppc476fp->current_gpr_values_valid[reg_num] ){
        if ( data == ppc476fp->current_gpr_values[reg_num] ){
            need_full_write = false;
        }else{
            int32_t diff = data - ppc476fp->current_gpr_values[reg_num];
            int16_t diff_16 = (uint16_t)((uint32_t)diff);
            if(diff_16 == diff){
                need_full_write = false;
                ret = stuff_code (target,addi(reg_num,reg_num,diff_16));
            }
        }
    }
    if (need_full_write){
        if ((data_signed < -32768) || (data_signed >= 32768)) {
            ret = stuff_code(target, lis(reg_num, data>>16));
            if ((ret == ERROR_OK) && (data & 0xffffu)) {
                ret = stuff_code(target, ori(reg_num,reg_num,data&0xffffu));
            }
        } else {
            ret = stuff_code(target, li(reg_num,data_signed));
        }
    }

    ppc476fp->current_gpr_values[reg_num] = data;
    ppc476fp->current_gpr_values_valid[reg_num] = (ret == ERROR_OK);

    return ret;
}

// проверка доступности области стека. Происходит по принципу: проверка
// корректности значения в r1, после чего в свободную часть пытаются записать 8
// байт (2 слова), после чего считать и сравнить с эталоном. если чтение
// удалось, стек считается рабочим
static int test_memory_at_stack(struct target *target, enum target_endianness *endianness) {
    return test_memory_at_addr(target, reg_sp, -8, endianness);
}
static int test_memory_at_static_mem(struct target *target, enum target_endianness *endianness) {
    write_gpr_reg(target,tmp_reg_addr,use_static_mem_addr(target));
    return test_memory_at_addr(target, tmp_reg_addr, 0, endianness);
}
static int test_memory_at_addr(struct target *target, uint32_t ra, int16_t shift, enum target_endianness *endianness) {
    uint32_t value_1;
    uint32_t value_2;
    uint8_t endian;
    int ret;
    enum MAGIC_WORDS{
        MAGIC_WORD_1 = 0x396F965C,
        MAGIC_WORD_2 = 0x44692D7E
    };

    uint32_t magic1;
    uint32_t magic2;

     h_u32_to_be((uint8_t *)&magic1, MAGIC_WORD_1);
     h_u32_to_be((uint8_t *)&magic2, MAGIC_WORD_2);

    if (target->state != TARGET_HALTED) {
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = write_virt_mem_raw(target, tmp_reg_data, ra, shift+0, memory_access_size_word, (uint8_t *)&magic1);
    if (ret != ERROR_OK)
        return ret;
    ret = write_virt_mem_raw(target, tmp_reg_data, ra, shift+4, memory_access_size_word, (uint8_t *)&magic2);
    if (ret != ERROR_OK)
        return ret;

    ret = read_virt_mem_raw(target, tmp_reg_data, ra, shift+0, memory_access_size_word, (uint8_t *)&value_1);
    if (ret != ERROR_OK)
        return ret;
    ret = read_virt_mem_raw(target, tmp_reg_data, ra, shift+4, memory_access_size_word, (uint8_t *)&value_2);
    if (ret != ERROR_OK)
        return ret;
    ret = read_virt_mem_raw(target, tmp_reg_data, ra, shift+0, memory_access_size_byte, &endian);
    if (ret != ERROR_OK)
        return ret;

    // check the magic values
    if ((value_1 != magic1) || (value_2 != magic2))
        return ERROR_MEMORY_AT_STACK;
    if (endian == (MAGIC_WORD_1 & 0xff)){
        *endianness = TARGET_LITTLE_ENDIAN;
    }else if (endian == (MAGIC_WORD_1>>24)){
        *endianness = TARGET_BIG_ENDIAN;
    }

    return ERROR_OK;
}

// Запись значения по эффективному адресу
static int write_virt_mem_raw(struct target *target, uint32_t rt, uint32_t ra, int16_t d, enum memory_access_size size, const uint8_t *buffer) {
    uint32_t code;

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    switch (size) {
    case memory_access_size_byte:
        code = stb(rt,ra,d);
        break;
    case memory_access_size_half_word:
        code = sth(rt,ra,d);
        break;
    case memory_access_size_word:
        code = stw(rt,ra,d);
        break;
    default:
        assert(false);
    }

    if (buffer != NULL){
        uint32_t value = 0;

        switch (size) {
            case memory_access_size_byte:
                value = *buffer;
                break;
            case memory_access_size_half_word:
                value = target_buffer_get_u16(target,buffer);
                break;
            case memory_access_size_word:
                value = target_buffer_get_u32(target,buffer);
                break;
            default:
                assert(false);
        }

        int ret = write_gpr_reg(target, rt, value);
        if (ret != ERROR_OK) {
            return ret;
        }
    }

    return stuff_code(target, code);
}

// Чтение значения с эффективного адреса
static int read_virt_mem_raw(struct target *target, uint32_t rt, uint32_t ra, int16_t d, enum memory_access_size size, uint8_t *buffer) {
    uint32_t code;
    int ret;

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    switch (size) {
    case memory_access_size_byte:
        code = lbz(rt,ra,d);
        break;
    case memory_access_size_half_word:
        code = lhz(rt,ra,d);
        break;
    case memory_access_size_word:
        code = lwz(rt,ra,d);
        break;
    default:
        assert(false);
    }
    target_to_ppc476fp(target)->gpr_regs[rt]->dirty = true;
    target_to_ppc476fp(target)->current_gpr_values_valid[rt] = false;

    ret = stuff_code(target, code);
    if (ret != ERROR_OK)
        return ret;

    if ( buffer != NULL ){
        uint32_t value;
        ret = read_gpr_reg(target, rt, (uint8_t *)&value);
        if (ret != ERROR_OK)
            return ret;

        switch (size) {
        case memory_access_size_byte:
            *buffer = (uint8_t)value;
            break;
        case memory_access_size_half_word:
            target_buffer_set_u16(target,buffer,value);
            break;
        case memory_access_size_word:
            target_buffer_set_u32(target,buffer,value);
            break;
        default:
            assert(false);
        }
    }

    return ERROR_OK;
}

// чтение spr-регистра в data
static int read_spr_reg(struct target *target, int spr_num, uint8_t *data) {
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    int ret = stuff_code(target, mfspr(tmp_reg_data,spr_num));
    if (ret != ERROR_OK)
        return ret;

    return read_gpr_reg(target, tmp_reg_data, data);
}

// запись значения data в spr-регистр
static int write_spr_reg(struct target *target, int spr_num, uint32_t data) {
    int ret = write_gpr_reg(target, tmp_reg_data, data);
    if (ret != ERROR_OK)
        return ret;

    ret = stuff_code(target, mtspr(spr_num,tmp_reg_data));
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

// чтение регистра fpu. Здесь много заковырок. Во-первых, fpu должен быть
// включен. Во-вторых, регистры fpu нельзя напрямую передать в JTAG или хотябы
// РОН, потому обращение к ним происходит через стек, потому он тоже должен
// работать.
static int read_fpr_reg(struct target *target, int reg_num, uint64_t *value) {

    static const uint64_t bad = 0xbabadedababadedaull;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint8_t value_m[8];
    int ret;
    uint32_t ra;
    int16_t shift;
    enum target_endianness endian;

    if ((!use_fpu_get(target)) ||
        ((get_reg_value_32(ppc476fp->MSR_reg) & MSR_FP_MASK) == 0)) {
        *value = bad;
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    if (use_static_mem_get(target)) {
        ra = tmp_reg_addr;
        shift = 0;
        write_gpr_reg(target,tmp_reg_addr,use_static_mem_addr(target));
        endian = use_static_mem_endianness(target);
    } else if (use_stack_get(target)) {
        ra = reg_sp;
        shift = -8;
        endian = use_stack_endianness(target);
    } else {
        *value = bad;
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    
    ret = stuff_code(target, stfd(reg_num,ra,shift));
    if (ret != ERROR_OK)
        return ret;

    uint8_t *h = (endian == TARGET_BIG_ENDIAN?value_m:value_m+4);
    uint8_t *l = (endian == TARGET_BIG_ENDIAN?value_m+4:value_m);
    ret = read_virt_mem_raw(target, tmp_reg_data, ra, shift + 0, memory_access_size_word, h);
    if (ret != ERROR_OK)
        return ret;
    ret = read_virt_mem_raw(target, tmp_reg_data, ra, shift + 4, memory_access_size_word, l);
    if (ret != ERROR_OK)
        return ret;

    *value = target_buffer_get_u64(target,value_m);
    return ERROR_OK;
}

// запись регистра fpu. Здесь много заковырок. Во-первых, fpu должен быть
// включен. Во-вторых, регистры fpu нельзя напрямую передать в JTAG или хотябы
// РОН, потому обращение к ним происходит через стек, потому он тоже должен
// работать.
static int write_fpr_reg(struct target *target, int reg_num, uint64_t value) {
    uint8_t value_m[8];
    target_buffer_set_u64 (target,value_m,value);
    int ret;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint32_t ra;
    int16_t shift;
    enum target_endianness endian;

    if ((!use_fpu_get(target)) ||
        ((get_reg_value_32(ppc476fp->MSR_reg) & MSR_FP_MASK) == 0)) {
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    if (use_static_mem_get(target)) {
        ra = tmp_reg_addr;
        shift = 0;
        write_gpr_reg(target,tmp_reg_addr,use_static_mem_addr(target));
        endian = use_static_mem_endianness(target);
    } else if (use_stack_get(target)) {
        ra = reg_sp;
        shift = -8;
        endian = use_stack_endianness(target);
    } else {
        return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
    }
    ppc476fp->fpr_regs[reg_num]->dirty = true;

    uint8_t *h = (endian == TARGET_BIG_ENDIAN?value_m:value_m+4);
    uint8_t *l = (endian == TARGET_BIG_ENDIAN?value_m+4:value_m);
    ret = write_virt_mem_raw(target, tmp_reg_data, ra, shift + 0, memory_access_size_word, h);
    if (ret != ERROR_OK)
        return ret;
    ret = write_virt_mem_raw(target, tmp_reg_data, ra, shift + 4, memory_access_size_word, l);
    if (ret != ERROR_OK)
        return ret;
    ret = stuff_code(target, lfd(reg_num,ra,shift));
    if (ret != ERROR_OK)
        return ret;

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

// запись MSR.Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual
// 7.4.1 с. 173
static int write_MSR(struct target *target, uint32_t value) {
    int ret;

    ret = write_gpr_reg(target, tmp_reg_data, value);
    if (ret != ERROR_OK)
        return ret;
    ret = stuff_code(target,mtmsr(tmp_reg_data,true));
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

// чтение MSR.Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual
// 7.4.1 с. 173
static int read_MSR(struct target *target, uint8_t *value) {
    int ret;

    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    ret = stuff_code(target,mfmsr(tmp_reg_data));
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_reg(target, tmp_reg_data, value);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int read_DCR(struct target *target, uint32_t addr, uint32_t *value) {
    int ret;
    ret = write_gpr_reg(target, tmp_reg_addr, addr);
    if (ret != ERROR_OK)
        return ret;
    ret = stuff_code(target, mfdcrx(tmp_reg_data,tmp_reg_addr));
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
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    ret = stuff_code(target, mtdcrx(tmp_reg_addr,tmp_reg_data));
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
        ret = stuff_code(target, blr());
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->PC_reg->dirty = false;
    }

    if (ppc476fp->CR_reg->dirty) {
        ret = write_gpr_reg(target, tmp_reg_data,
                            get_reg_value_32(ppc476fp->CR_reg));
        if (ret != ERROR_OK)
            return ret;
        ret = stuff_code(target, mtcr(tmp_reg_data));
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
        ret = stuff_code(target, mfcr(tmp_reg_data));
        ppc476fp->gpr_regs[tmp_reg_data]->dirty = true;
        ppc476fp->current_gpr_values_valid[tmp_reg_data] = false;
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
        ret = stuff_code(target, bl(0));
        if (ret != ERROR_OK)
            return ret;
        ret = read_spr_reg(target, SPR_REG_NUM_LR, (uint8_t *)&value);
        set_reg_value_32(ppc476fp->PC_reg, value - 4);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->PC_reg->valid = true;
        ppc476fp->PC_reg->dirty = false;
    }

    return write_dirty_gen_regs(target);
}

// Запись грязных (dirty) регистров FPU из кэша OpenOCD в таргет
// Важно: регистры становятся грязными не только при изменении их
// значения через интерфейс OpenOCD, но и при работе внутренних функций JTAG
static int write_dirty_fpu_regs(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    struct reg *reg;
    int i;
    int ret;
    bool need_flush = ppc476fp->FPSCR_reg->dirty;

    for (i = 0 ; i < FPR_REG_COUNT ; ++i){
        need_flush |= ppc476fp->fpr_regs[i]->dirty;
    }

    if (!need_flush){
        return ERROR_OK;
    }

    if (target->state != TARGET_HALTED) {
        return ERROR_TARGET_NOT_HALTED;
    }

    if ( !ppc476fp->memory_checked ){

        if (use_stack_get(target)) {
            use_stack_on(target);
        }

        if (use_static_mem_get(target)) {
            use_static_mem_on(target, use_static_mem_addr(target));
        }
        ppc476fp->memory_checked = true;
    }

    if (ppc476fp->FPSCR_reg->dirty) {
        uint64_t value = (uint64_t)get_reg_value_32(ppc476fp->FPSCR_reg);
        ret = write_fpr_reg(target, 0, value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->fpr_regs[0]->dirty = true;
        ret = stuff_code(target, mtfsf(255,0));
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

    return write_dirty_gen_regs(target);
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

    if ( !ppc476fp->memory_checked ){

        if (use_stack_get(target)) {
            use_stack_on(target);
        }

        if (use_static_mem_get(target)) {
            use_static_mem_on(target, use_static_mem_addr(target));
        }
        ppc476fp->memory_checked = true;
    }


    for (i = 0; i < FPR_REG_COUNT; ++i) {
        reg = ppc476fp->fpr_regs[i];
        reg->dirty = false;
        if (!reg->valid) {
            ret = read_fpr_reg(target, i, (uint64_t *)reg->value);
            if (ret == ERROR_OK) {
                reg->valid = true;
            } else if (ret == ERROR_TARGET_RESOURCE_NOT_AVAILABLE){
                reg->valid = false;
            } else {
                return ret;
            }
        }
    }

    if (!ppc476fp->FPSCR_reg->valid) {
        if ( ppc476fp->fpr_regs[0]->valid ){
            ppc476fp->fpr_regs[0]->dirty = true;
            ret = stuff_code(target, mffs(0));
            if (ret != ERROR_OK)
                return ret;
        }
        read_fpr_reg(target, 0, &value);
        set_reg_value_32(ppc476fp->FPSCR_reg, (uint32_t)(value));
        ppc476fp->FPSCR_reg->dirty = false;
        ppc476fp->FPSCR_reg->valid = ppc476fp->fpr_regs[0]->valid;
    }
    return flush_registers(target);
}

// Помечает весь кэш регистров как невалидный
// Используется в процессе сохранения/восстановления контекста и при сбросе
static void invalidate_regs_status(struct target *target) {
    struct reg_cache *cache = target->reg_cache;

    while (cache != NULL) {
        register_cache_invalidate(cache);
        cache = cache->next;
    }
    for ( int i = 0 ; i < GPR_REG_COUNT ; ++i ){
        target_to_ppc476fp(target)->current_gpr_values_valid[i] = false;
    }
}

static int ppc476fp_get_msr(struct reg *reg){
    struct target *target = reg->arch_info;

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    reg->valid = false;
    reg->dirty = false;

    read_required_gen_regs(target);

    return flush_registers(target);
}

static int ppc476fp_set_msr(struct reg *reg, uint8_t *buf){
    struct target *target = reg->arch_info;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint32_t MSR_prev_value = get_reg_value_32(ppc476fp->MSR_reg);
    uint32_t MSR_new_value;
    size_t i;
    int ret;

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;
    
    MSR_new_value = buf_get_u32(buf, 0, 32);
    if (((MSR_prev_value ^ MSR_new_value) & MSR_FP_MASK) != 0) {
        if ((MSR_prev_value & MSR_FP_MASK) != 0) {
            ret = write_dirty_fpu_regs(target);
            if (ret != ERROR_OK)
                return ret;
        }
        // invalidate FPU registers
        for (i = 0; i < FPR_REG_COUNT; ++i) {
            ppc476fp->fpr_regs[i]->valid = false;
            ppc476fp->fpr_regs[i]->dirty = false;
        }
        ppc476fp->FPSCR_reg->valid = false;
        ppc476fp->FPSCR_reg->dirty = false;
    }

        // write MSR to the CPU
    ret = write_MSR(target, MSR_new_value);
    if (ret != ERROR_OK)
        return ret;
    buf_cpy(buf, reg->value, reg->size);
    reg->valid = true;
    reg->dirty = false;

    if (((MSR_prev_value ^ MSR_new_value) & MSR_FP_MASK) != 0) {
        if ((MSR_new_value & MSR_FP_MASK) != 0) {
            read_required_fpu_regs(target);
        }

    }
    return flush_registers(target);
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

    read_required_gen_regs(target);

    return flush_registers(target);
}

// Изменение регистра в кэше. По идее, эта функция парная к
// ppc476fp_get_gen_reg, Но их поведение в общую логику не укладываются, а
// документация openocd не говорит как эта функция должна себя вести в идеале. В
// случае, если меняется значение MSR, запись происходит сразу. Если при
// изменении MSR отключается FPU, предварительно кэш регистров FPU сбрасывается
static int ppc476fp_set_gen_reg(struct reg *reg, uint8_t *buf) {
    struct target *target = reg->arch_info;

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    buf_cpy(buf, reg->value, reg->size);
    reg->valid = true;
    reg->dirty = true;

    return flush_registers(target);
}

// чтение FPU регистра с таргета. аналогична ppc476fp_get_gen_reg
static int ppc476fp_get_fpu_reg(struct reg *reg) {
    struct target *target = reg->arch_info;

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    reg->valid = false;
    reg->dirty = false;

    int ret = read_required_fpu_regs(target);
    if ( ret != ERROR_OK ){
        return ret;
    }
    return flush_registers(target);
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

    return flush_registers(target);
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
    int i;

    static const struct reg_arch_type ppc476fp_gen_reg_type = {
        .get = ppc476fp_get_gen_reg, .set = ppc476fp_set_gen_reg};

    static const struct reg_arch_type ppc476fp_fpu_reg_type = {
        .get = ppc476fp_get_fpu_reg, .set = ppc476fp_set_fpu_reg};

    static const struct reg_arch_type ppc476fp_msr_type = {
        .get = ppc476fp_get_msr, .set = ppc476fp_set_msr};

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
        static const char names[GPR_REG_COUNT][4] = {
            "R0","R1","R2","R3","R4","R5","R6","R7","R8","R9",
            "R10","R11","R12","R13","R14","R15","R16","R17","R18","R19",
            "R20","R21","R22","R23","R24","R25","R26","R27","R28","R29",
            "R30","R31"
        };
        ppc476fp->gpr_regs[i] = fill_reg(
            target, all_index++, gen_regs++, names[i], REG_TYPE_UINT32,
            32, &ppc476fp_gen_reg_type, "org.gnu.gdb.power.core"); // R0-R31
    }

    for (i = 0; i < FPR_REG_COUNT; ++i) {
        static const char names[FPR_REG_COUNT][4] = {
            "F0","F1","F2","F3","F4","F5","F6","F7","F8","F9",
            "F10","F11","F12","F13","F14","F15","F16","F17","F18","F19",
            "F20","F21","F22","F23","F24","F25","F26","F27","F28","F29",
            "F30","F31"
        };
        ppc476fp->fpr_regs[i] =
            fill_reg(target, all_index++, fpu_regs++, names[i],
                     REG_TYPE_IEEE_DOUBLE, 64, &ppc476fp_fpu_reg_type,
                     "org.gnu.gdb.power.fpu"); // F0-F31
    }

    ppc476fp->PC_reg =
        fill_reg(target, all_index++, gen_regs++, "PC", REG_TYPE_CODE_PTR, 32,
                 &ppc476fp_gen_reg_type, "org.gnu.gdb.power.core");
    ppc476fp->MSR_reg =
        fill_reg(target, all_index++, gen_regs++, "MSR", REG_TYPE_UINT32, 32,
                 &ppc476fp_msr_type, "org.gnu.gdb.power.core");
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
    ppc476fp->use_stack = TARGET_ENDIAN_UNKNOWN;
    ppc476fp->use_static_mem = 0xffffffff;
    ppc476fp->use_static_mem_endianness = TARGET_ENDIAN_UNKNOWN;
    ppc476fp->transactions = 0;
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

    uint32_t trap_code = 0;
    target_buffer_set_u32(target,(uint8_t *)&trap_code,trap());


    ret = write_gpr_reg(target,tmp_reg_addr,(uint32_t)bp->address);
    if (ret != ERROR_OK)
        return ret;

    ret = read_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, (uint8_t *)bp->orig_instr);
    if (ret != ERROR_OK)
        return ret;

    ret = write_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, (const uint8_t *)&trap_code);
    if (ret != ERROR_OK)
        return ret;

    ret = read_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, (uint8_t *)&test_value);
    if (ret != ERROR_OK)
        return ret;

    ret = cache_l1i_invalidate(target, (uint32_t)bp->address, 4);
    if (ret != ERROR_OK)
        return ret;

    if (test_value == trap_code)
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

    ret = write_gpr_reg(target,tmp_reg_addr,(uint32_t)bp->address);
    if (ret != ERROR_OK)
        return ret;

    ret = write_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, (uint8_t *)bp->orig_instr);
    if (ret != ERROR_OK)
        return ret;

    ret = read_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, (uint8_t *)&test_value);
    if (ret != ERROR_OK)
        return ret;

    ret = cache_l1i_invalidate(target, (uint32_t)bp->address, 4);
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
    for(struct breakpoint *bp = target->breakpoints;bp != NULL;bp = bp->next) {
        if ((bp->type == BKPT_SOFT) && (bp-> is_set != 0)) {
            if (unset_soft_breakpoint(target, bp) != ERROR_OK)
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
    
    int bp_count = 0;
    for (struct breakpoint *bp = target->breakpoints; bp != NULL ; bp=bp->next) {
        if (bp->type != BKPT_HARD)
            continue;
        if (bp != breakpoint) // do not count the added breakpoint, it may be in
                              // the list
            ++bp_count;
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

    target_to_ppc476fp(target)->memory_checked = false;

    ret = read_required_fpu_regs(target);
    if (ret != ERROR_OK)
        return ret;

    return flush_registers(target);
}

static int cache_l1i_invalidate(struct target *target, uint32_t addr, uint32_t len) {
    const uint32_t begin = addr & (~31u);
    const uint32_t end = ((addr + len) & (~31u)) + ((addr+len)&31u ? 32 : 0);
    int result = ERROR_OK;
    int ret = stuff_code(target, isync());
    if (ret != ERROR_OK) {
        return ret;
    }
    ret = stuff_code(target, msync());
    if (ret != ERROR_OK) {
        return ret;
    }
    for ( uint32_t i = begin; i < end ; i+= 32 ){
	ret = write_gpr_reg (target, tmp_reg_addr, i);
        if (ret != ERROR_OK) {
	    result = ret;
            break;
        }
        ret = stuff_code(target, icbi(0,tmp_reg_addr));
        if (ret != ERROR_OK) {
	    result = ret;
            break;
        }
    }

    ret = stuff_code(target, isync());
    if (ret != ERROR_OK) {
        result = ret;
    }
    ret = stuff_code(target, msync());
    if (ret != ERROR_OK) {
        return ret;
    }else{
        return result;
    }
}

// восстановление контекста перед снятием HALT
// процессор обязан быть в состоянии HALT
static int restore_state(struct target *target, int handle_breakpoints) {
    int ret;

    if ( handle_breakpoints ){
        ret = enable_breakpoints(target);
        if (ret != ERROR_OK)
           return ret;

       ret = enable_watchpoints(target);
       if (ret != ERROR_OK)
           return ret;
    }else{
        unset_all_soft_breakpoints(target); // ignore return value
        invalidate_hw_breakpoints(target); // if an error occurs
        invalidate_watchpoints(target);    // if an error occurs
    }

    ret = flush_registers(target);
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
                                    target_addr_t address, int handle_breakpoints,
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

    ret = restore_state(target, handle_breakpoints);
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

    ret = write_DBCR0(target, (target_to_ppc476fp(target)->DWE?0:DBCR0_EDM_MASK) | DBCR0_TRAP_MASK | DBCR0_FT_MASK);
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

    return flush_registers(target);
}

static int reset_and_halt(struct target *target) {
    target_to_ppc476fp(target)->DWE = false;
    int ret = halt_and_wait(target, 100);

    if ( ret != ERROR_OK ){
        LOG_ERROR ("Can't stop CPU. send RESET_SYS");
        ret = write_JDCR(target, JDCR_RESET_SYS | JDCR_STO_MASK);
        if (ret != ERROR_OK)
            return ret;
        target->state = TARGET_HALTED;
    }
    ret = write_spr_reg(target, SPR_REG_NUM_SRR1, 0);
    if (ret != ERROR_OK)
        return ret;
    ret = write_spr_reg(target, SPR_REG_NUM_CSRR1, 0);
    if (ret != ERROR_OK)
        return ret;
    ret = write_spr_reg(target, SPR_REG_NUM_MCSRR1, 0);
    if (ret != ERROR_OK)
        return ret;
    unset_all_soft_breakpoints(target); // ignore return value
    write_DBCR0(target, 0);

    target->state = TARGET_RESET;

    invalidate_regs_status(target);
    invalidate_tlb_cache(target);
    use_fpu_off(target, reg_action_ignore);
    use_stack_off(target, reg_action_ignore);
    use_static_mem_off(target, reg_action_ignore);
    ret = write_JDCR(target, JDCR_RESET_CHIP | JDCR_STO_MASK | JDCR_RSDBSR_MASK);
    if (ret != ERROR_OK)
        return ret;

    ret = halt_and_wait(target, 100);
    if (ret != ERROR_OK)
        return ret;

    target->state = TARGET_HALTED;
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

    ret = stuff_code(target, tlbre(tmp_reg_data, tmp_reg_addr, 0));
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    target_to_ppc476fp(target)->current_gpr_values_valid[tmp_reg_data] = false;
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_reg(target, tmp_reg_data, (uint8_t *)&hw->data[0]);
    if (ret != ERROR_OK)
        return ret;

    // otimization for non-valid UTLB records
    if ((hw->data[0] & TLB_0_V_MASK) == 0)
        return ERROR_OK;

    ret = stuff_code(target, tlbre(tmp_reg_data, tmp_reg_addr, 1));
    target_to_ppc476fp(target)->current_gpr_values_valid[tmp_reg_data] = false;
    if (ret != ERROR_OK)
        return ret;

    ret = read_gpr_reg(target, tmp_reg_data, (uint8_t *)&hw->data[1]);
    if (ret != ERROR_OK)
        return ret;

    ret = stuff_code(target, tlbre(tmp_reg_data, tmp_reg_addr, 2));
    target_to_ppc476fp(target)->current_gpr_values_valid[tmp_reg_data] = false;
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

    if ((hw->bltd < bltd_no) && (data0 & TLB_0_V_MASK)) {
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
    
    target_to_ppc476fp(target)->memory_checked = false;

    ret = stuff_code(target,tlbwe(tmp_reg_addr,tmp_reg_data,0));
    if (ret != ERROR_OK)
        return ret;

    // otimization for non-valid UTLB records
    if ((data0 & TLB_0_V_MASK) == 0)
        return ERROR_OK;

    ret = write_gpr_reg(target, tmp_reg_addr, hw->data[1]);
    if (ret != ERROR_OK)
        return ret;

    ret = stuff_code(target,tlbwe(tmp_reg_addr,tmp_reg_data,1));
    if (ret != ERROR_OK)
        return ret;

    ret = write_gpr_reg(target, tmp_reg_addr, hw->data[2]);
    if (ret != ERROR_OK)
        return ret;

    ret = stuff_code(target,tlbwe(tmp_reg_addr,tmp_reg_data,2));
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
    command_print(CMD, 
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
}

static int save_phys_mem(struct target *target, struct phys_mem_state *state){
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
    return ERROR_OK;
}

static int init_phys_mem(struct target *target, struct phys_mem_state *state) {
    int ret;

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
    ret = stuff_code(target, isync());
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int access_phys_mem(struct target *target, uint32_t new_ERPN_RPN) {
    struct tlb_hw_record hw = {{
        TLB_0_V_MASK | TLB_0_TS_MASK |
            ((PHYS_MEM_BASE_ADDR >> 12)<<TLB_0_EPN_BIT_POS) |
            (DSIZ_1G<<TLB_0_DSIZ_BIT_POS),
        
        ((new_ERPN_RPN >> 20)<<TLB_1_ERPN_BIT_POS) |
            ((new_ERPN_RPN & 0xFFFFF)<<TLB_1_RPN_BIT_POS),
        
        TLB_2_IL1I_MASK | TLB_2_IL1D_MASK |
            (0x7<<TLB_2_WIMG_BIT_POS) |
            (0x3<<TLB_2_UXWR_BIT_POS) |
            (target->endianness == TARGET_LITTLE_ENDIAN?TLB_2_EN_MASK:0)},
        PHYS_MEM_MAGIC_PID,
        bltd_no
    };

    int ret;

    ret = write_tlb(target, PHYS_MEM_TLB_INDEX_WAY, &hw);
    if (ret != ERROR_OK)
        return ret;

    // syncing
    ret = stuff_code(target, isync());
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
    int ret;

    params->mask=0;
    params->tid=0;
    params->ts=0;
    params->dsiz = DSIZ_4K;
    params->way = -1;
    params->il1i=0;
    params->il1d=0;
    params->u=0;
    params->wimg=0;
    params->en=0;
    params->uxwr=0;
    params->sxwr=0;
    params->bltd = bltd_no;

    for (arg_index = 0; arg_index < argc; ++arg_index) {
        arg = argv[arg_index];

        p = strchr(arg, '=');
        if (p == NULL)
            return ERROR_COMMAND_ARGUMENT_INVALID;

        ++p;

        if (strncmp(arg, "epn=", p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_EPN, 0xFFFFF, p,
                                      &params->mask, &params->epn);
        else if (strncmp(arg, "rpn=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_RPN, 0xFFFFF, p,
                                      &params->mask, &params->rpn);
        else if (strncmp(arg, "erpn=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_ERPN, 0x3FF, p,
                                      &params->mask, &params->erpn);
        else if (strncmp(arg, "tid=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_TID, 0xFFFF, p,
                                      &params->mask, &params->tid);
        else if (strncmp(arg, "ts=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_TS, 1, p, &params->mask,
                                      &params->ts);
        else if (strncmp(arg, "il1i=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_IL1I, 1, p, &params->mask,
                                      &params->il1i);
        else if (strncmp(arg, "il1d=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_IL1D, 1, p, &params->mask,
                                      &params->il1d);
        else if (strncmp(arg, "u=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_U, 0xF, p, &params->mask,
                                      &params->u);
        else if (strncmp(arg, "wimg=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_WIMG, 0xF, p,
                                      &params->mask, &params->wimg);
        else if (strncmp(arg, "uxwr=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_UXWR, 0x7, p,
                                      &params->mask, &params->uxwr);
        else if (strncmp(arg, "sxwr=",p-arg) == 0)
            ret = parse_uint32_params(TLB_PARAMS_MASK_SXWR, 0x7, p,
                                      &params->mask, &params->sxwr);
        else if (strncmp(arg, "dsiz=",p-arg) == 0)
            ret = parse_dsiz_params(TLB_PARAMS_MASK_DSIZ, p, &params->mask,
                                    &params->dsiz);
        else if (strncmp(arg, "en=",p-arg) == 0) {
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
        } else if (strncmp(arg, "way=",p-arg) == 0) {
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
        } else if (strncmp(arg, "bltd=",p-arg) == 0) {
            if ((params->mask & TLB_PARAMS_MASK_BLTD) != 0)
                ret = ERROR_COMMAND_ARGUMENT_INVALID;
            else {
                if (strcmp(p, "no") == 0) {
                    params->mask |= TLB_PARAMS_MASK_BLTD;
                    ret = ERROR_OK;
                } else if (strcmp(p, "auto") == 0) {
                    params->mask |= TLB_PARAMS_MASK_BLTD;
                    ret = ERROR_OK;
                    params->bltd = bltd_auto;
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

    if (bltd != bltd_no) {
        uint32_t mmube0;
        uint32_t mmube1;
        ret = read_spr_reg(target, SPR_REG_NUM_MMUBE0, (uint8_t *)&mmube0);
        if (ret != ERROR_OK)
            return ret;
        ret = read_spr_reg(target, SPR_REG_NUM_MMUBE1, (uint8_t *)&mmube1);
        if (ret != ERROR_OK)
            return ret;
        way = 0;

        if (bltd == bltd_auto) {
            if ((mmube0 & 4) == 0) {
                bltd = bltd0;
            } else if ((mmube0 & 2) == 0) {
                bltd = bltd1;
            } else if ((mmube0 & 1) == 0) {
                bltd = bltd2;
            } else if ((mmube1 & 4) == 0) {
                bltd = bltd3;
            } else if ((mmube1 & 2) == 0) {
                bltd = bltd4;
            } else if ((mmube1 & 1) == 0) {
                bltd = bltd5;
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

    struct tlb_hw_record hw = {{
        TLB_0_V_MASK | (params->epn<<TLB_0_EPN_BIT_POS) | (params->ts!=0?TLB_0_TS_MASK:0) |
            (params->dsiz << TLB_0_DSIZ_BIT_POS),
        (params->rpn<<TLB_1_RPN_BIT_POS) | (params->erpn<<TLB_1_ERPN_BIT_POS),
        (params->il1i != 0?TLB_2_IL1I_MASK:0) | (params->il1d != 0?TLB_2_IL1D_MASK:0) |
            (params->u<<TLB_2_U_BIT_POS) | (params->wimg<<TLB_2_WIMG_BIT_POS) |
            (params->en != 0?TLB_2_EN_MASK:0) | (params->uxwr<<TLB_2_UXWR_BIT_POS) |
            (params->sxwr<<TLB_2_SXWR_BIT_POS)},
            params->tid,
            bltd};

    ret = write_tlb(target, index_way, &hw);
    if (ret != ERROR_OK)
        return ret;

    // syncing
    ret = stuff_code(target, isync());
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
    struct tlb_hw_record hw = {{0,0,0},0,0};
    uint32_t saved_MMUCR;
    uint32_t ts;
    int index_way;
    int count = 0;
    int ret;

    // save MMUCR
    ret = read_spr_reg(target, SPR_REG_NUM_MMUCR, (uint8_t *)&saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

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
        ret = stuff_code(target, isync());
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
    struct tlb_hw_record hw = {{0,0,0},0,0};
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

    for (i = 0; i < TLB_NUMBER; ++i) {
        keep_alive();
        ret = write_tlb(target, i, &hw);
        if (ret != ERROR_OK)
            return ret;
    }

    // syncing
    ret = stuff_code(target, isync());
    if (ret != ERROR_OK)
        return ret;

    // restore MMUCR
    ret = write_spr_reg(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int poll_internal(struct target *target) {
    enum target_state state;
    uint32_t JDSR_value, DBSR_value;
    int ret;

    ret = read_JDSR(target, (uint8_t *)&JDSR_value);
    if (ret != ERROR_OK) {
        target->state = TARGET_UNKNOWN;
        return ret;
    }

    target_to_ppc476fp(target)->DWE = (JDSR_value&JDSR_DWE_MASK)!=0;
    
    if (is_halted(JDSR_value))
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
            else if ((DBSR_value & DBSR_IAC_ALL_MASK) != 0)
                target->debug_reason = DBG_REASON_BREAKPOINT;
            else if ((DBSR_value & DBSR_DAC_ALL_MASK) != 0)
                target->debug_reason = DBG_REASON_WATCHPOINT;
    	    else if ((DBSR_value & DBSR_TRAP_MASK) != 0)
	    	    target->debug_reason = DBG_REASON_BREAKPOINT;
        }

        if (prev_state == TARGET_DEBUG_RUNNING)
            target_call_event_callbacks(target, TARGET_EVENT_DEBUG_HALTED);
        else
            target_call_event_callbacks(target, TARGET_EVENT_HALTED);

        return flush_registers(target);
    }else if ((state == TARGET_RUNNING) && (target->state == TARGET_HALTED)){
        LOG_WARNING("Unexpected target resume detected!");
        target->state = TARGET_RUNNING;
        invalidate_regs_status(target);
        invalidate_tlb_cache(target);
    }

    return ERROR_OK;
}

static int ppc476fp_poll(struct target *target) {
    unsigned long long transactions_begin = target_to_ppc476fp(target)->transactions;
    int ret = poll_internal(target);
    LOG_DEBUG_IO("poll_transactions: %llu",target_to_ppc476fp(target)->transactions-transactions_begin);
    target_to_ppc476fp(target)->transactions = transactions_begin;
    return ret;
}

// call only then the target is halted
static int ppc476fp_arch_state(struct target *target) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);

    LOG_USER("target halted due to %s, coreid=%i, PC: 0x%08X, DW %s",
             debug_reason_name(target), target->coreid,
             get_reg_value_32(ppc476fp->PC_reg), (ppc476fp->DWE?"enabled":"disabled"));

    return ERROR_OK;
}

static int halt_and_wait(struct target *target, int count){

    int ret = ERROR_OK;
    bool dwe = target_to_ppc476fp(target)->DWE;
    if(dwe){
        ret = write_JDCR(target,JDCR_DWS_MASK|JDCR_UDE_MASK);
    }else{
        ret = write_JDCR(target, JDCR_STO_MASK|JDCR_UDE_MASK);
    }
    if (ret != ERROR_OK)
        return ret;

    for ( int i = 0; i < count ; ++i ){
        uint32_t JDSR_value = 0;
        keep_alive();
        ret = read_JDSR(target, (uint8_t *)&JDSR_value);
        if (ret != ERROR_OK) {
            target->state = TARGET_UNKNOWN;
            return ret;
        }

        if (is_halted(JDSR_value)){
            target->state = TARGET_HALTED;
            break;
        }
    }
    if ( target->state == TARGET_HALTED ){
        return ERROR_OK;
    }else{
        target->state = TARGET_UNKNOWN;
        return ERROR_TARGET_FAILURE;
    }
}

static int ppc476fp_halt(struct target *target) {
    int ret;

    LOG_DEBUG("coreid=%i", target->coreid);

    if (target->state == TARGET_HALTED) {
        LOG_WARNING("target was already halted");
        return ERROR_OK;
    }

    if (target->state == TARGET_UNKNOWN)
        LOG_WARNING("target was in unknown state when halt was requested");

    target->debug_reason = DBG_REASON_DBGRQ;

   ret = halt_and_wait(target, 100);
    if ( ret == ERROR_OK ){
        save_state_and_init_debug(target);
        target_call_event_callbacks(target, TARGET_EVENT_HALTED);
    }else{
        LOG_ERROR("Can't stop CPU, need reset");
    }
    return ret;
}

static int ppc476fp_resume(struct target *target, int current,
                           target_addr_t address, int handle_breakpoints,
                           int debug_execution) {
    LOG_DEBUG("coreid=%i", target->coreid);

    int ret = restore_state_before_run(target, current, address, 1,
                                       DBG_REASON_NOTHALTED);
    if (ret != ERROR_OK)
        return ret;

    ret = write_JDCR(target, JDCR_RSDBSR_MASK | (target_to_ppc476fp(target)->DWE?JDCR_DWS_MASK:0));
    if (ret != ERROR_OK)
        return ret;

    if (debug_execution) {
        target->state = TARGET_DEBUG_RUNNING;
    } else {
        target->state = TARGET_RUNNING;
    }

    return ERROR_OK;
}

static int ppc476fp_step(struct target *target, int current,
                         target_addr_t address, int handle_breakpoints) {
    LOG_DEBUG("coreid=%i", target->coreid);

    int ret = restore_state_before_run(target, current, address, 0,
                                       DBG_REASON_SINGLESTEP);
    if (ret != ERROR_OK)
        return ret;

    ret = write_JDCR(target,  JDCR_SS_MASK | (target_to_ppc476fp(target)->DWE?JDCR_DWS_MASK:JDCR_STO_MASK));
    if (ret != ERROR_OK)
        return ret;

    target->state = TARGET_RUNNING;
    ret = halt_and_wait(target, 100);
    if ( ret == ERROR_OK ){
        target->state = TARGET_HALTED;
        ret = save_state_and_init_debug(target);
        if (ret != ERROR_OK) {
            target->state = TARGET_UNKNOWN;
            return ret;
        }
        return ERROR_OK;
    }

    return ERROR_TARGET_FAILURE;
}

static int ppc476fp_assert_reset(struct target *target) {
    LOG_DEBUG("coreid=%i", target->coreid);

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
        target->state = TARGET_RUNNING;
        invalidate_regs_status(target);
        invalidate_tlb_cache(target);
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
    ret = restore_state(target, 1);
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
    int result = ERROR_OK;
    uint32_t shifted = -32768;
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

    for (i = 0; i < count; ++i) {
        keep_alive();
        if ((int)((i+1)*size-shifted)>32768){
            shifted += 65536;
            ret = write_gpr_reg(target, tmp_reg_addr, address+shifted);
            if (ret != ERROR_OK){
                result = ret;
                break;
            }
        }
        ret = read_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, (int16_t)(i*size-shifted), size, buffer + i*size);
        if (ret != ERROR_OK){
            result = ret;
            break;
        }
    }

    ret = flush_registers(target);
    if (result == ERROR_OK){
        return ret;
    }else{
        return result;
    }
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG
// communication BUG
static int ppc476fp_write_memory(struct target *target, target_addr_t address,
                                 uint32_t size, uint32_t count,
                                 const uint8_t *buffer) {
    uint32_t i;
    int result = ERROR_OK;
    uint32_t shifted = -32768;
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

    for (i = 0; i < count; ++i) {
        keep_alive();
        if ((int)((i+1)*size-shifted)>32768){
            shifted += 65536;
            ret = write_gpr_reg(target, tmp_reg_addr, address+shifted);
            if (ret != ERROR_OK){
                result = ret;
                break;
            }
        }
        ret = write_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, (int16_t)(i*size-shifted), size, buffer + i*size);
        if (ret != ERROR_OK){
            result = ret;
            break;
        }
    }

    ret = flush_registers(target);
    if (result == ERROR_OK){
        return ret;
    }else{
        return result;
    }
}

static int ppc476fp_checksum_memory(struct target *target,
                                    target_addr_t address, uint32_t count,
                                    uint32_t *checksum) {
    return ERROR_FAIL;
}

static int ppc476fp_add_breakpoint(struct target *target,
                                   struct breakpoint *breakpoint) {
    LOG_DEBUG("coreid=%i, address=0x%lX, type=%i, length=0x%X", target->coreid,
              breakpoint->address, breakpoint->type, breakpoint->length);

    if (target->state != TARGET_HALTED)
        return ERROR_TARGET_NOT_HALTED;

    if (breakpoint->length != 4){
        LOG_ERROR("incorrect bp length");
        return ERROR_TARGET_UNALIGNED_ACCESS;
    }

    if ((breakpoint->address & 0x3) != 0)
        return ERROR_TARGET_UNALIGNED_ACCESS;

    breakpoint->is_set = 0;
    memset(breakpoint->orig_instr, 0, 4);

    if (breakpoint->type == BKPT_HARD) {
        int ret = check_add_hw_breakpoint(target, breakpoint);
        if ( ret != ERROR_OK )
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
    } else {
        ret = unset_soft_breakpoint(target, breakpoint);
    }

    if (ret != ERROR_OK){
        flush_registers(target);
        return ret;
    }else{
        return flush_registers(target);
    }
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
    if (ret != ERROR_OK){
        flush_registers(target);
        return ret;
    }else{
    return flush_registers(target);
    }
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

    if (target->state!=TARGET_HALTED){
        *physical = 0;
        return ERROR_TARGET_NOT_HALTED;
    }
    int ret = ERROR_OK;
    uint32_t ispcr_saved = 0, ispcr=0;
    do{
        struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
        uint32_t index,cr;
        ret =read_spr_reg(target,SPR_REG_NUM_ISPCR,(uint8_t*)&ispcr_saved);
        if(ret!=ERROR_OK)
            break;
        ret =read_spr_reg(target,((get_reg_value_32(ppc476fp->MSR_reg)&MSR_PR_MASK)!=0)?SPR_REG_NUM_USPCR:SPR_REG_NUM_SSPCR,(uint8_t*)&ispcr);
        if(ret!=ERROR_OK)
            break;
        ret = write_gpr_reg(target,tmp_reg_addr,(uint32_t)address);
        if(ret!=ERROR_OK)
            break;
        ppc476fp->CR_reg->dirty = true;
        ppc476fp->gpr_regs[tmp_reg_data]->dirty = true;
        ppc476fp->current_gpr_values_valid[tmp_reg_data] = false;
        ret = stuff_code(target,tlbsx_(tmp_reg_data,0,tmp_reg_addr));
        if(ret!=ERROR_OK)
            break;
        ret = read_gpr_reg(target,tmp_reg_data,(uint8_t*)&index);
        if(ret!=ERROR_OK)
            break;
        ret = stuff_code(target,mfcr(tmp_reg_data));
        if(ret!=ERROR_OK)
            break;
        ret = read_gpr_reg(target,tmp_reg_data,(uint8_t*)&cr);
        if(ret!=ERROR_OK)
            break;
        if((cr&1u<<(31-2))==0){
            ret = ERROR_TARGET_TRANSLATION_FAULT;
            break;
        }
        index = ((index>>16)&0xff)*4+(index>>29);
        ret = load_uncached_tlb(target, index);
        if(ret!=ERROR_OK)
            break;
        target_addr_t result = ppc476fp->tlb_cache[index].hw.data[1]&0x3ffu;
        result <<= 32;
        result |= (ppc476fp->tlb_cache[index].hw.data[0]&0xfffff000u)^address^(ppc476fp->tlb_cache[index].hw.data[1]&0xfffff000u);
        *physical = result;
    }while(0);
    if(ispcr!=0){
        ret |= write_spr_reg(target,SPR_REG_NUM_ISPCR,ispcr_saved);
    }
    return ret | flush_registers(target);
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
    int result = ERROR_OK;

    LOG_DEBUG("coreid=%i, address=0x%lX, size=%u, count=0x%X", target->coreid,
              address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) ||
        !(buffer))
        return ERROR_COMMAND_SYNTAX_ERROR;

    memset(buffer, 0, size * count); // clear result buffer

    if ( save_phys_mem(target,&state) != ERROR_OK ){
        LOG_ERROR("Can't save context");
        return ERROR_TARGET_FAILURE;
    }

    ret = init_phys_mem(target, &state);
    if (ret == ERROR_OK){
        for (i = 0; i < count; ++i) {
            keep_alive();

            new_ERPN_RPN = (address >> 12) & 0x3FFC0000;
            if (new_ERPN_RPN != last_ERPN_RPN) {
                ret = access_phys_mem(target, new_ERPN_RPN);
                if (ret != ERROR_OK)
                    break;
                last_ERPN_RPN = new_ERPN_RPN;
            }
            uint32_t pack_count = (0x40000000 - (address+i*size)%0x40000000)/size;
            if (pack_count > count) 
                pack_count = count;

            keep_alive();
            ret = ppc476fp_read_memory(target, (uint32_t)(address&0x3fffffff) + PHYS_MEM_BASE_ADDR, size, pack_count,buffer);
            if (ret != ERROR_OK)
                break;

            address += size;
            buffer += size;
        }
        if(ret != ERROR_OK)
            result = ret;
    }
    // restore state
    ret = restore_phys_mem(target, &state);
    if(ret != ERROR_OK ){
        LOG_ERROR("can't restore phys mem context");
        if ( result == ERROR_OK ){
            result = ret;
        }
    }

    if (result != ERROR_OK){
        if (flush_registers(target))
            LOG_ERROR("can't flush registers");
        return result;
    }else{
        return flush_registers(target);
    }
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
    int result = ERROR_OK;

    LOG_DEBUG("coreid=%i, address=0x%lX, size=%u, count=0x%X", target->coreid,
              address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) ||
        !(buffer))
        return ERROR_COMMAND_SYNTAX_ERROR;

    if ( save_phys_mem(target,&state) != ERROR_OK ){
        LOG_ERROR("Can't save context");
        return ERROR_TARGET_FAILURE;
    }

    ret = init_phys_mem(target, &state);
    if (ret == ERROR_OK){
        for (i = 0; i < count; ++i) {
            new_ERPN_RPN = (address >> 12) & 0x3FFC0000;
            if (new_ERPN_RPN != last_ERPN_RPN) {
                ret = access_phys_mem(target, new_ERPN_RPN);
                if (ret != ERROR_OK)
                    break;
                last_ERPN_RPN = new_ERPN_RPN;
            }

            uint32_t pack_count = (0x40000000 - (address+i*size)%0x40000000)/size;
            if (pack_count > count) 
                pack_count = count;

            keep_alive();
            ret = ppc476fp_write_memory(target, (uint32_t)(address&0x3fffffff) + PHYS_MEM_BASE_ADDR, size, pack_count,buffer);
            if (ret != ERROR_OK)
                break;
            address += size*pack_count;
            buffer += size*pack_count;
        }
        if(ret != ERROR_OK)
            result = ret;
    }
    // restore state
    ret = restore_phys_mem(target, &state);
    if(ret != ERROR_OK ){
        LOG_ERROR("can't restore phys mem context");
        if ( result == ERROR_OK ){
            result = ret;
        }
    }

    if (result != ERROR_OK){
        if (flush_registers(target))
            LOG_ERROR("can't flush registers");
        return result;
    }else{
        return flush_registers(target);
    }
}

static int ppc476fp_mmu(struct target *target, int *enabled) {
    *enabled = 1;
    return ERROR_OK;
}

static const char *ppc476fp_get_gdb_arch(struct target *target){
    return "powerpc:common";
}

static bool use_fpu_get(struct target *target) {
    return target_to_ppc476fp(target)->use_fpu;
}

static int use_fpu_on(struct target *target) {
    if (use_stack_get(target) || use_static_mem_get(target)) {
        target_to_ppc476fp(target)->use_fpu = true;
        return ERROR_OK;
    }
    LOG_ERROR("use_stack or use_static_mem need for use_fpu");
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
        ppc476fp->FPSCR_reg->valid = false;
        ppc476fp->FPSCR_reg->dirty = false;
        ppc476fp->use_fpu = false;
    }
        return ERROR_OK;
    case reg_action_error: {
        for (int i = 0; i < FPR_REG_COUNT; ++i) {
            if (ppc476fp->fpr_regs[i]->dirty == true) {
                return ERROR_FAIL;
            }
        }
        for (int i = 0; i < FPR_REG_COUNT; ++i) {
            ppc476fp->fpr_regs[i]->valid = false;
            ppc476fp->fpr_regs[i]->dirty = false;
        }
        ppc476fp->FPSCR_reg->valid = false;
        ppc476fp->FPSCR_reg->dirty = false;
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
        for (int i = 0; i < FPR_REG_COUNT; ++i) {
            ppc476fp->fpr_regs[i]->valid = false;
            ppc476fp->fpr_regs[i]->dirty = false;
        }
        ppc476fp->FPSCR_reg->valid = false;
        ppc476fp->FPSCR_reg->dirty = false;
        ppc476fp->use_fpu = false;
    }
        return ERROR_OK;
    }
    return ERROR_FAIL;
}

static bool use_stack_get(struct target *target) {
    return target_to_ppc476fp(target)->use_stack != TARGET_ENDIAN_UNKNOWN;
}

static enum target_endianness use_stack_endianness(struct target *target) {
    return target_to_ppc476fp(target)->use_stack;
}

static int use_stack_on(struct target *target) {
    int ret = ERROR_OK;
    enum target_endianness endianness = TARGET_ENDIAN_UNKNOWN;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    if (target->state == TARGET_HALTED) {
        ret = test_memory_at_stack(target, &endianness);
        if (ret != ERROR_OK) {
            LOG_ERROR("test_memory_at_stack failed, disable use_stack");
            use_stack_off(target, reg_action_ignore);
            return ret;
        }
        ppc476fp->use_stack = endianness;
        flush_registers(target);
    }else{
        ppc476fp->use_stack = TARGET_BIG_ENDIAN;
    }
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

static enum target_endianness use_static_mem_endianness(struct target *target){
    return target_to_ppc476fp(target)->use_static_mem_endianness;
}

static uint32_t use_static_mem_addr(struct target *target) {
    return target_to_ppc476fp(target)->use_static_mem;
}

static int use_static_mem_on(struct target *target, uint32_t base_addr) {
    if (base_addr & 0x07) {
        LOG_ERROR("addr must be aligned by 8");
        return ERROR_FAIL;
    }
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    if (target->state == TARGET_HALTED) {
        enum target_endianness endianness = TARGET_ENDIAN_UNKNOWN;
        target_to_ppc476fp(target)->use_static_mem = base_addr;
        int ret = test_memory_at_static_mem(target, &endianness);
        if (ret != ERROR_OK) {
            LOG_ERROR("test_memory_at_static_mem failed, disable use_static_mem");
            use_static_mem_off(target, reg_action_ignore);
            return ret;
        }
        ppc476fp->use_static_mem_endianness = endianness;
        flush_registers(target);
    }else{
        target_to_ppc476fp(target)->use_static_mem = base_addr;
        ppc476fp->use_static_mem_endianness = TARGET_ENDIAN_UNKNOWN;
    }
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

    return flush_registers(target);
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

    return flush_registers(target);
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

    return flush_registers(target);
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

    return flush_registers(target);
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
    command_print(CMD, "  transaction_counter: %llu",--(target_to_ppc476fp(target)->transactions));

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

    command_print(CMD, "DCR %u(0x%x) = %u(0x%08x)", addr, addr, data, data);

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_dcr_get_command) {
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

    command_print_sameline(CMD, "%u", data);

    return flush_registers(target);
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

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_dcr_or_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    uint32_t read;
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

    ret = read_DCR(target, addr, &read);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_DCR(target, addr, (read|data) );
    if (ret != ERROR_OK) {
        return ret;
    }

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_dcr_xor_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    uint32_t read;
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

    ret = read_DCR(target, addr, &read);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_DCR(target, addr, (read^data) );
    if (ret != ERROR_OK) {
        return ret;
    }

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_dcr_and_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    uint32_t read;
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

    ret = read_DCR(target, addr, &read);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_DCR(target, addr, (read&data) );
    if (ret != ERROR_OK) {
        return ret;
    }

    return flush_registers(target);
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

    command_print(CMD, "SPR %u(0x%x) = %u(0x%08x)", addr, addr, data, data);

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_spr_get_command) {
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

    command_print_sameline(CMD, "%u", data);

    return flush_registers(target);
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

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_spr_or_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    uint32_t read;
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

    ret = read_spr_reg(target, addr, (uint8_t *)&read);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_spr_reg(target, addr, (data|read) );
    if (ret != ERROR_OK) {
        return ret;
    }

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_spr_xor_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    uint32_t read;
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

    ret = read_spr_reg(target, addr, (uint8_t *)&read);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_spr_reg(target, addr, (data^read) );
    if (ret != ERROR_OK) {
        return ret;
    }

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_spr_and_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    uint32_t read;
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

    ret = read_spr_reg(target, addr, (uint8_t *)&read);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_spr_reg(target, addr, (data&read) );
    if (ret != ERROR_OK) {
        return ret;
    }

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_use_fpu_on_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;
    struct target *target = get_current_target(CMD_CTX);

    int ret = use_fpu_on(target);
    if (ret != ERROR_OK)
        return ret;
    if ( target->state == TARGET_HALTED ){
        ret = read_required_fpu_regs(target);
        if (ret != ERROR_OK)
            return ret;
    }

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

    return use_fpu_off(target, action);
}

COMMAND_HANDLER(ppc476fp_handle_use_stack_on_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    struct target *target = get_current_target(CMD_CTX);
    return use_stack_on(target);
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
    return use_stack_off(target, reg_action_error);
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

    return use_static_mem_on(target, addr);
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

    return use_static_mem_off(target, reg_action_error);
}

COMMAND_HANDLER(ppc476fp_code_isync_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    return stuff_code(target, isync());
}

COMMAND_HANDLER(ppc476fp_code_msync_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    return stuff_code(target, msync());
}

COMMAND_HANDLER(ppc476fp_code_ici_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    return stuff_code(target, ici());
}

COMMAND_HANDLER(ppc476fp_code_dci_0_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    return stuff_code(target, dci(0));
}

COMMAND_HANDLER(ppc476fp_code_dci_2_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    return stuff_code(target, dci(2));
}

COMMAND_HANDLER(ppc476fp_code_dcbf_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;
    uint32_t addr;
    int ret = parse_u32(CMD_ARGV[0], &addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("%s : is not valid addr", CMD_ARGV[0]);
    }
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = write_gpr_reg(target, tmp_reg_addr, addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't write addr to tmp reg");
        return ret;
    }


    ret = stuff_code(target, dcbf(0,tmp_reg_addr));
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't run dcbf 0, R%i", tmp_reg_addr);
        return ret;
    }
    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_code_dcbt_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;
    uint32_t addr;
    int ret = parse_u32(CMD_ARGV[0], &addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("%s : is not valid addr", CMD_ARGV[0]);
    }
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = write_gpr_reg(target, tmp_reg_addr, addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't write addr to tmp reg");
        return ret;
    }

    ret = stuff_code(target, dcbt(0,tmp_reg_addr));
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't run dcbt 0, R%i", tmp_reg_addr);
        return ret;
    }
    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_code_dcread_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;
    uint32_t addr;
    struct target *target = get_current_target(CMD_CTX);
    int ret = parse_u32(CMD_ARGV[0], &addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("%s : is not valid addr", CMD_ARGV[0]);
    }
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = write_gpr_reg(target, tmp_reg_addr, addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't write addr to tmp reg");
        return ret;
    }

    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;

    ret = stuff_code(target, dcread(tmp_reg_data,0,tmp_reg_addr));
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't run dcread R%i, R0, R%i", tmp_reg_data, tmp_reg_addr);
        return ret;
    }

    uint8_t data[4];
    ret = read_gpr_reg(target, tmp_reg_data, data);
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't read rt value from tmp reg");
        return ret;
    }

    command_print_sameline(CMD, "%u", target_buffer_get_u32(target,data));
    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_code_icbi_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;
    uint32_t addr;
    int ret = parse_u32(CMD_ARGV[0], &addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("%s : is not valid addr", CMD_ARGV[0]);
    }
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = write_gpr_reg(target, tmp_reg_addr, addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't write addr to tmp reg");
        return ret;
    }


    ret = stuff_code(target, icbi(0,tmp_reg_addr));
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't run icbi 0, R%i", tmp_reg_addr);
        return ret;
    }
    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_code_icbt_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;
    uint32_t addr;
    int ret = parse_u32(CMD_ARGV[0], &addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("%s : is not valid addr", CMD_ARGV[0]);
    }
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = write_gpr_reg(target, tmp_reg_addr, addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't write addr to tmp reg");
        return ret;
    }


    ret = stuff_code(target, icbt(0,tmp_reg_addr));
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't run icbt 0, R%i", tmp_reg_addr);
        return ret;
    }
    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_code_icread_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;
    uint32_t addr;
    struct target *target = get_current_target(CMD_CTX);
    int ret = parse_u32(CMD_ARGV[0], &addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("%s : is not valid addr", CMD_ARGV[0]);
    }
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = write_gpr_reg(target, tmp_reg_addr, addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't write addr to tmp reg");
        return ret;
    }

    ret = stuff_code(target, icread(0,tmp_reg_addr) );
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't run icread R0, R%i", tmp_reg_addr);
        return ret;
    }

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_cache_l1d_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    struct target *target = get_current_target(CMD_CTX);
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    ppc476fp->gpr_regs[tmp_reg_data]->dirty = true;
    command_print(
        CMD,
        "SET:W ERA:ADDR     +00      +04      +08      +0c      +10      +14      +18      +1c");
    for ( uint32_t set = 0; set < 256 ; ++set ){
        for ( uint32_t way = 0 ; way < 4 ; ++way ){
            uint32_t dcdbtrh;
            for ( uint32_t i = 0 ; i < 8 ; ++i ){
                keep_alive();
                int ret = write_gpr_reg(target, tmp_reg_addr, way * 0x2000 + set * 0x20 + i * 4);
                if ( ret != ERROR_OK ){
                    LOG_ERROR("Can't write addr to tmp reg");
                    return ret;
                }

                ret = stuff_code(target, dcread(tmp_reg_data,0,tmp_reg_addr) );
                target_to_ppc476fp(target)->current_gpr_values_valid[tmp_reg_data] = false;
                if ( ret != ERROR_OK ){
                    LOG_ERROR("Can't run dcread R%i, R0, R%i", tmp_reg_data, tmp_reg_addr);
                    return ret;
                }
                uint8_t data[4];
                ret = read_gpr_reg(target,tmp_reg_data,data);
                if ( ret != ERROR_OK ){
                    LOG_ERROR("Can't read data register");
                    return ret;
                }

                if ( i == 0 ) {

                    ret = read_spr_reg(target,925,(uint8_t*)&dcdbtrh);
                    if ( ret != ERROR_OK ){
                        LOG_ERROR("Can't read dcdbtrh");
                        return ret;
                    }

                    if ( ( dcdbtrh & DCDBTRH_VALID_MASK ) == 0 ){
                        break;
                    }
                    command_print_sameline(CMD, " %02x:%i %03x:%08x", set,way,dcdbtrh&DCDBTRH_EXTADDR_MASK, (dcdbtrh&DCDBTRH_ADDR_MASK)|(set<<5));

                }
                command_print_sameline(CMD, " %08x", target_buffer_get_u32(target,data));

            }

            if ( ( dcdbtrh & DCDBTRH_VALID_MASK ) != 0 ){
                command_print(CMD," ");
            }
            

        }
    }
    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_cache_l1i_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    struct target *target = get_current_target(CMD_CTX);
    command_print(
        CMD,
        "SET:W ERA:ADDR     +00      +04      +08      +0c      +10      +14      +18      +1c");
    for ( uint32_t set = 0; set < 256 ; ++set ){
        for ( uint32_t way = 0 ; way < 4 ; ++way ){
            uint32_t icdbtrh;
            for ( uint32_t i = 0 ; i < 8 ; ++i ){
                keep_alive();
                int ret = write_gpr_reg(target, tmp_reg_addr, way * 0x2000 + set * 0x20 + i*4);
                if ( ret != ERROR_OK ){
                    LOG_ERROR("Can't write addr to tmp reg");
                    return ret;
                }

                ret = stuff_code(target, icread(0,tmp_reg_addr) );
                if ( ret != ERROR_OK ){
                    LOG_ERROR("Can't run icread R0, R%i", tmp_reg_addr);
                    return ret;
                }

                if ( i == 0 ) {

                    ret = read_spr_reg(target,927,(uint8_t*)&icdbtrh);
                    if ( ret != ERROR_OK ){
                        LOG_ERROR("Can't read icdbtrh");
                        return ret;
                    }

                    if ( ( icdbtrh & DCDBTRH_VALID_MASK ) == 0 ){
                        break;
                    }
                    command_print_sameline(CMD, " %02x:%i %03x:%08x", set,way,icdbtrh&DCDBTRH_EXTADDR_MASK, (icdbtrh&DCDBTRH_ADDR_MASK)|(set<<5));

                }
                uint32_t data;
                ret = read_spr_reg(target,979,(uint8_t*)&data);
                if ( ret != ERROR_OK ){
                    LOG_ERROR("Can't read icdbdr0");
                    return ret;
                }

                command_print_sameline(CMD, " %08x", data);

            }

            if ( ( icdbtrh & DCDBTRH_VALID_MASK ) != 0 ){
                command_print(CMD," ");
            }
            

        }
    }
    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_cache_l2_command) {
    uint32_t ecc_data=0;
    uint32_t *ecc=NULL;
    if (CMD_ARGC != 0){
        if ((CMD_ARGC==1) && (strcmp(CMD_ARGV[0],"ecc")==0)){
            ecc = &ecc_data;
        }else{
            return ERROR_COMMAND_SYNTAX_ERROR;
        }
    }

    struct target *target = get_current_target(CMD_CTX);
    struct l2_context context;
    int ret = l2_init_context(target,&context,tmp_reg_addr,tmp_reg_data);
    if (ret==ERROR_OK){
        command_print_sameline(CMD, "Cache size: ");
        switch (context.size)
        {
        case l2_size_128k:
            command_print(CMD,"128k");
            break;
        case l2_size_256k:
            command_print(CMD,"256k");
            break;
        case l2_size_512k:
            command_print(CMD,"512k");
            break;
        case l2_size_1m:
            command_print(CMD,"1m");
            break;
        }
        keep_alive();
        for (uint32_t set=0;set<(1u<<context.tag_n);++set){
            uint32_t info;
            for (uint32_t way = 0 ; way<4 ; ++way){
                ret = l2_read_tag(&context,set,way,&info,ecc);
                if (ret != ERROR_OK){
                    LOG_ERROR("Can't read tag %i",set);
                    break;
                }
                enum l2_cache_state line_state = info&l2_cache_state_mask;
                static const char line_state_strings[6][3] = {"S","SL","E","T","M","MU"};
                const char *line_state_string = NULL;
                bool valid = true;
                uint32_t eaddr = (info>>19)&0x3ff;
                uint32_t addr = (info<<13)|(set<<7);
                switch (line_state){
                case l2_cache_state_shared:
                    line_state_string = line_state_strings[0];
                    break;
                case l2_cache_state_shared_last:
                    line_state_string = line_state_strings[1];
                    break;
                case l2_cache_state_exclusive:
                    line_state_string = line_state_strings[2];
                    break;
                case l2_cache_state_tagged:
                    line_state_string = line_state_strings[3];
                    break;
                case l2_cache_state_modified:
                    line_state_string = line_state_strings[4];
                    break;
                case l2_cache_state_modified_unsolicited:
                    line_state_string = line_state_strings[5];
                    break;
                case l2_cache_state_invalid:
                case l2_cache_state_undefined:
                    valid = false;
                    break;
                }
                if (valid){
                    command_print(CMD,"Set %4i way %i: %08x:%02x %2s addr: %03x:%08x:",set,way,info,ecc_data>>1,line_state_string,eaddr,addr);
                    for(uint32_t i=0;i<16;++i){
                        keep_alive();
                        uint32_t data_h,data_l;
                        if(i%8==0)
                           command_print_sameline(CMD,"      ");
                        l2_read_data(&context,set*16+i,way,&data_h,&data_l,ecc);
                        command_print_sameline(CMD," %08x:%08x:%02x", target_buffer_get_u32(target,(uint8_t*)&data_h), target_buffer_get_u32(target,(uint8_t*)&data_l), ecc_data);
                        if(i%8==7)
                            command_print(CMD," ");
                    }
                }else{
                    keep_alive();
                }
            }
        }
        l2_restore_context(&context);
    }else{
        command_print(CMD, "init context failed");
    }
    return ret | flush_registers(target);
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

static const struct command_registration ppc476fp_dcr_exec_command_handlers[] ={
     {.name = "read",
      .handler = ppc476fp_handle_dcr_read_command,
      .mode = COMMAND_EXEC,
      .usage = "<num>",
      .help = "read from DCR <num> (long output)"},
     {.name = "get",
      .handler = ppc476fp_handle_dcr_get_command,
      .mode = COMMAND_EXEC,
      .usage = "<num>",
      .help = "read from DCR <num> (only value)"},
     {.name = "write",
      .handler = ppc476fp_handle_dcr_write_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <data>",
      .help = "write <data> to DCR <num>"},
     {.name = "or",
      .handler = ppc476fp_handle_dcr_or_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <mask>",
      .help = "DCR <num> = DCR <num> | <mask>"},
     {.name = "xor",
      .handler = ppc476fp_handle_dcr_xor_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <mask>",
      .help = "DCR <num> = DCR <num> ^ <mask>"},
     {.name = "and",
      .handler = ppc476fp_handle_dcr_and_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <mask>",
      .help = "DCR <num> = DCR <num> & <mask>"},
     COMMAND_REGISTRATION_DONE};

static const struct command_registration ppc476fp_spr_exec_command_handlers[] ={
     {.name = "read",
      .handler = ppc476fp_handle_spr_read_command,
      .mode = COMMAND_EXEC,
      .usage = "<num>",
      .help = "read from SPR <num> (long output)"},
     {.name = "get",
      .handler = ppc476fp_handle_spr_get_command,
      .mode = COMMAND_EXEC,
      .usage = "<num>",
      .help = "read from SPR <num> (only value)"},
     {.name = "write",
      .handler = ppc476fp_handle_spr_write_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <data>",
      .help = "write <data> to SPR <num>"},
     {.name = "or",
      .handler = ppc476fp_handle_spr_or_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <mask>",
      .help = "SPR <num> = SPR <num> | <mask>"},
     {.name = "xor",
      .handler = ppc476fp_handle_spr_xor_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <mask>",
      .help = "SPR <num> = SPR <num> ^ <mask>"},
     {.name = "and",
      .handler = ppc476fp_handle_spr_and_command,
      .mode = COMMAND_EXEC,
      .usage = "<num> <mask>",
      .help = "SPR <num> = SPR <num> & <mask>"},
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

static const struct command_registration ppc476fp_code_dci_command_handlers[] = {
    {.name = "0",
    .handler = ppc476fp_code_dci_0_command,
    .mode = COMMAND_EXEC,
    .usage = "",
    .help = "Invalidate L1D cache"},
    {.name = "2",
    .handler = ppc476fp_code_dci_2_command,
    .mode = COMMAND_EXEC,
    .usage = "",
    .help = "Invalidate L1D and L2 cache"},
    COMMAND_REGISTRATION_DONE};

static const struct command_registration ppc476fp_code_exec_command_handlers[] = {
    {.name = "isync",
    .handler = ppc476fp_code_isync_command,
    .mode = COMMAND_EXEC,
    .usage = "",
    .help = "instruction sync"},
    {.name = "msync",
    .handler = ppc476fp_code_msync_command,
    .mode = COMMAND_EXEC,
    .usage = "",
    .help = "memory sync"},
    {.name = "ici",
    .handler = ppc476fp_code_ici_command,
    .mode = COMMAND_EXEC,
    .usage = "",
    .help = "instruction cache invalidate"},
    {.name = "dci",
    .chain = ppc476fp_code_dci_command_handlers,
    .mode = COMMAND_EXEC,
    .usage = "",
    .help = "data cache invalidate"},
    {.name = "dcbf",
    .handler = ppc476fp_code_dcbf_command,
    .mode = COMMAND_EXEC,
    .usage = "<addr>",
    .help = "Data Cache Block Flush"},
    {.name = "dcbt",
    .handler = ppc476fp_code_dcbt_command,
    .mode = COMMAND_EXEC,
    .usage = "<addr>",
    .help = "Data Cache Block Touch"},
    {.name = "dcread",
    .handler = ppc476fp_code_dcread_command,
    .mode = COMMAND_EXEC,
    .usage = "<addr>",
    .help = "Data Cache Read"},
    {.name = "icbi",
    .handler = ppc476fp_code_icbi_command,
    .mode = COMMAND_EXEC,
    .usage = "<addr>",
    .help = "Instruction Cache Block Invalidate"},
    {.name = "icbt",
    .handler = ppc476fp_code_icbt_command,
    .mode = COMMAND_EXEC,
    .usage = "<addr>",
    .help = "Instruction Cache Block Touch"},
    {.name = "icread",
    .handler = ppc476fp_code_icread_command,
    .mode = COMMAND_EXEC,
    .usage = "<addr>",
    .help = "Instruction Cache Read"},
    COMMAND_REGISTRATION_DONE};

static const struct command_registration ppc476fp_cache_exec_command_handlers[] = {
    {.name = "l1d",
    .handler = ppc476fp_cache_l1d_command,
    .mode = COMMAND_EXEC,
    .usage = "",
    .help = "Dump valid l1d entryes"},
    {.name = "l1i",
    .handler = ppc476fp_cache_l1i_command,
    .mode = COMMAND_EXEC,
    .usage = "",
    .help = "Dump valid l1i entryes"},
    {.name = "l2",
    .handler = ppc476fp_cache_l2_command,
    .mode = COMMAND_EXEC,
    .usage = "[ecc]",
    .help = "Dump valid l2 entryes"},
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
    {.name = "code",
     .chain = ppc476fp_code_exec_command_handlers,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "run some opcodes in stuff mode"},
    {.name = "cache",
     .chain = ppc476fp_cache_exec_command_handlers,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "dump valid cache"},
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

    .get_gdb_arch = ppc476fp_get_gdb_arch,
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
