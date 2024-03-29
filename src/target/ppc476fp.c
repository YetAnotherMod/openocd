#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ppc476fp_stuffs.h"
#include "ppc476fp_l2.h"

#include "ppc476fp.h"

#include <helper/log.h>

static unsigned long long transactions = 0;
static unsigned long long detected_errors = 0;
static unsigned long long poll_transactions = 0;
static unsigned long long poll_detected_errors = 0;

static const uint32_t resident[] = {
//00000000 <write_words>:
/*   0:	*/0x7ff3faa6,	//mfspr   r31,1011
/*   4:	*/0x97fe0004,	//stwu    r31,4(r30)
/*   8:	*/0x4bfffff8,	//b       0 <write_words>

//0000000c <write_halfs>:
/*   c:	*/0x7ff3faa6,	//mfspr   r31,1011
/*  10:	*/0xb7fe0002,	//sthu    r31,2(r30)
/*  14:	*/0x4bfffff8,	//b       c <write_halfs>

//00000018 <write_bytes>:
/*  18:	*/0x7ff3faa6,	//mfspr   r31,1011
/*  1c:	*/0x9ffe0001,	//stbu    r31,1(r30)
/*  20:	*/0x4bfffff8,	//b       18 <write_bytes>

//00000024 <read_words>:
/*  24:	*/0x87fe0004, 	//lwzu    r31,4(r30)
/*  28:	*/0x7ff3fba6, 	//mtspr   1011,r31
/*  2c:	*/0x4bfffff8, 	//b       24 <read_words>

//00000030 <read_halfs>:
/*  30:	*/0xa7fe0002, 	//lhzu    r31,2(r30)
/*  34:	*/0x7ff3fba6, 	//mtspr   1011,r31
/*  38:	*/0x4bfffff8, 	//b       30 <read_halfs>

//0000003c <read_bytes>:
/*  3c:	*/0x8ffe0001, 	//lbzu    r31,1(r30)
/*  40:	*/0x7ff3fba6, 	//mtspr   1011,r31
/*  44:	*/0x4bfffff8, 	//b       3c <read_bytes>

/*
за основу взята функция, указанная ниже, скомпилирована с -Os,
комбинация cmpwl,beqlr заменена на tweq (программная точка останова
вместо прямого возврата)

в качестве параметров:
    in - не значащий, добавлен только чтобы освободить r3
    buffer - указатель на байт ПЕРЕД буфером
    end - указатель на ПОСЛЕДНИЙ байт буфера

параметры именно такие, потому PPC так проще, а хосту без разницы

unsigned crc32(unsigned in,const unsigned char *buffer, const unsigned char *end)
{
	unsigned crc = 0xffffffff;
    while (buffer!=end) {
        unsigned c = ((crc >> 24) ^ *++buffer) << 24;
        for (unsigned j = 8; j > 0; --j)
            c = c & 0x80000000 ? (c << 1) ^ 0x04c11db7 : (c << 1);
        crc = (crc << 8) ^ c;
    }
    return crc;
}
*/
//00000024 <crc32>:
/*  48:	*/0x3860ffff, 	//li      r3,-1
/*  4c:	*/0x7c842808, 	//tweq    r4,r5
/*  50:	*/0x8d440001, 	//lbzu    r10,1(r4)
/*  54:	*/0x5469463e, 	//rlwinm  r9,r3,8,24,31
/*  58:	*/0x7d295278, 	//xor     r9,r9,r10
/*  5c:	*/0x39400008, 	//li      r10,8
/*  60:	*/0x5529c00e, 	//rlwinm  r9,r9,24,0,7
/*  64:	*/0x7d4903a6, 	//mtctr   r10
/*  68:	*/0x2c090000, 	//cmpwi   r9,0
/*  6c:	*/0x5529083c, 	//rlwinm  r9,r9,1,0,30
/*  70:	*/0x4080000c, 	//bge     7c <crc32+0x34>
/*  74:	*/0x6d2904c1, 	//xoris   r9,r9,1217
/*  78:	*/0x69291db7, 	//xori    r9,r9,7607
/*  7c:	*/0x4200ffec, 	//bdnz    68 <crc32+0x20>
/*  80:	*/0x5463402e, 	//rlwinm  r3,r3,8,0,23
/*  84:	*/0x7c634a78, 	//xor     r3,r3,r9
/*  88:	*/0x4bffffc4 	//b       4c <crc32+0x4>
};

static const uint32_t resident_write_words = 0x00;
static const uint32_t resident_write_halfs = 0x0c;
static const uint32_t resident_write_bytes = 0x18;
static const uint32_t resident_read_words  = 0x24;
static const uint32_t resident_read_halfs  = 0x30;
static const uint32_t resident_read_bytes  = 0x3c;
static const uint32_t resident_crc32       = 0x48;

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
    return le_to_h_u32(reg->value);
}

static inline void set_reg_value_32(struct reg *reg, uint32_t value) {
    reg->dirty = true;
    reg->valid = true;
    h_u32_to_le(reg->value, value);
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
    uint8_t zeros[8] = {0,0,0,0,0,0,0,0};

    if ( (target->coreid < 0) || (target->coreid > 3) ){
        LOG_ERROR("incorrect coreid");
        return ERROR_FAIL;
    }

    // !!! IMPORTANT
    // prevent the JTAG core switching bug
    if ((tap_ext->last_coreid != target->coreid) || (target->tap->bypass)) {
        h_u32_to_le(instr_buffer, JTAG_INSTR_CORE_RELOAD | coreid_mask[target->coreid]);
        instr_field.num_bits = target->tap->ir_length;
        instr_field.out_value = instr_buffer;
        instr_field.in_value = NULL;
        jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);
        tap_ext->last_coreid = target->coreid;
    }

    h_u32_to_le(instr_buffer, instr_without_coreid | coreid_mask[target->coreid]);
    instr_field.num_bits = target->tap->ir_length;
    instr_field.out_value = instr_buffer;
    instr_field.in_value = tap_alive[0];
    jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);

    h_u32_to_le(data_out_buffer, write_data);
    data_out_buffer[4] = valid_bit;
    data_fields.num_bits = 33;
    data_fields.out_value = data_out_buffer;
    data_fields.in_value = data_in_buffer;
    jtag_add_dr_scan(target->tap, 1, &data_fields, TAP_IDLE);
    transactions++;

    // !!! IMPORTANT
    // make additional request with valid bit == 0
    // to correct a JTAG communication BUG
    if (valid_bit != 0) {
        instr_field.in_value = tap_alive[1];
        jtag_add_ir_scan(target->tap, &instr_field, TAP_IDLE);
        data_fields.out_value = zeros;
        jtag_add_dr_scan(target->tap, 1, &data_fields, TAP_IDLE);
        transactions++;
    }

    ret = jtag_execute_queue();
    if (ret != ERROR_OK){
        detected_errors++;
        tap_ext->last_coreid = -1;
        target->state = TARGET_UNKNOWN;
    }else{
        if (read_data != NULL) {
            buf_cpy(data_in_buffer, read_data, 32);
        }

    }
    return ret;
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

static int write_DBDR_CONT(struct target *target, uint32_t data) {
    return jtag_read_write_register(target, JTAG_INSTR_WRITE_READ_DBDR_CONT, true,
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
    uint8_t JDSR[4];
    int ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_JDCR_READ_JDSR,
                                    true, data, JDSR);
    if (ret != ERROR_OK){
        return ret;
    }

    ret = jdsr_log_ser(le_to_h_u32(JDSR));
    if ( ret == ERROR_TARGET_FAILURE ){
        target->state = TARGET_UNKNOWN;
    }
    return ret;
}

// запись JTAG-регистра JISB. Регистр доступен только для записи. Запись в этот
// регистр напрямую вставляет код инструкции в конвеер и исполняет её.
static int stuff_code(struct target *target, uint32_t code) {
    uint8_t JDSR[4];
    if ( target->state != TARGET_HALTED ){
        return ERROR_TARGET_NOT_HALTED;
    }
    int ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR,
                                    true, code, JDSR);
    if (ret != ERROR_OK){
        return ret;
    }
    for ( int i = 100 ; (i > 0) && (le_to_h_u32(JDSR)&JDSR_SFP_MASK) ; --i ){
        ret = jtag_read_write_register(target, JTAG_INSTR_WRITE_JISB_READ_JDSR,
                                        false, code, JDSR);
        if (ret != ERROR_OK){
            return ret;
        }
    }

    ret = jdsr_log_ser(le_to_h_u32(JDSR));
    if ( ret == ERROR_TARGET_FAILURE ){
        target->state = TARGET_UNKNOWN;
    }
    return ret;
}

// чтение РОН через JTAG. Значение РОН при этом не меняется, но обычно
// происходит после инструкций, изменяющих значене регистра
static int read_gpr_buf(struct target *target, int reg_num, uint8_t *data) {
    struct ppc476fp_common * ppc476fp = target_to_ppc476fp(target);
    ppc476fp->current_gpr_values_valid[reg_num] = false;
    int ret = stuff_code(target, mtspr(SPR_REG_NUM_DBDR,reg_num));
    if (ret != ERROR_OK)
        return ret;

    ret = read_DBDR(target, data);
    if ( ret != ERROR_OK ){
        return ret;
    }
    ppc476fp->current_gpr_values[reg_num] = le_to_h_u32(data);
    ppc476fp->current_gpr_values_valid[reg_num] = true;

    return ERROR_OK;
}
static int read_gpr_u32(struct target *target, int reg_num, uint32_t *data) {
    uint8_t data_r[4];
    int ret = read_gpr_buf(target,reg_num,data_r);
    if ( ret == ERROR_OK ){
        *data = le_to_h_u32(data_r);
    }
    return ret;
}

// запись РОН через JTAG. Никак не связано с управляющими командами от GDB,
// нужно для выполнения отладочных действий (вроде росписи памяти).
// автоматически помечает регистр как dirty для того, чтобы заменить его
// значение на эталонное при снятии halt
static int write_gpr_u32(struct target *target, int reg_num, uint32_t data) {
    int32_t data_signed = (int32_t)data;
    bool need_full_write = true;
    struct ppc476fp_common * ppc476fp = target_to_ppc476fp(target);
    int ret = ERROR_OK;
    ppc476fp->gpr_regs[reg_num]->dirty = true;
    if ( ppc476fp->current_gpr_values_valid[reg_num] ){
        uint32_t curr = ppc476fp->current_gpr_values[reg_num];
        if ( data == curr ){
            need_full_write = false;
        }else{
            struct ppc476fp_prv_conf *pc = (struct ppc476fp_prv_conf*)target->private_config;
            uint32_t xor_data = data ^ curr;
            if ( pc->use_gpr_xor_optimization ){
                if ( xor_data<<16 == 0 ){
                    ret = stuff_code(target, xoris(reg_num,reg_num,xor_data>>16));
                    need_full_write = false;
                }else if ( xor_data>>16 == 0 ){
                    ret = stuff_code(target, xori(reg_num,reg_num,xor_data&0xffff));
                    need_full_write = false;
                }
            }else{
                if ( (xor_data & 0xffff0000) == 0 ){
                    if ( (curr | xor_data) == data ){
                        ret = stuff_code(target, ori(reg_num,reg_num,xor_data));
                        need_full_write = false;
                    }else if ( (curr & (~xor_data)) == data ){
                        ret = stuff_code(target, andi(reg_num,reg_num,(~xor_data&0xffff)));
                        need_full_write = false;
                    }
                } else if ( (xor_data & 0xffff) == 0 ){
                    if ( (curr | xor_data) == data ){
                        ret = stuff_code(target, oris(reg_num,reg_num,xor_data>>16));
                        need_full_write = false;
                    }else if ( (curr & (~xor_data)) == data ){
                        ret = stuff_code(target, andis(reg_num,reg_num,(~xor_data)>>16));
                        need_full_write = false;
                    }
                }
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

static int write_gpr_buf(struct target *target, int reg_num, const uint8_t *data) {
    return write_gpr_u32(target, reg_num, le_to_h_u32(data));
}


// проверка доступности области стека. Происходит по принципу: проверка
// корректности значения в r1, после чего в свободную часть пытаются записать 8
// байт (2 слова), после чего считать и сравнить с эталоном. если чтение
// удалось, стек считается рабочим
static int test_memory_at_stack(struct target *target, enum target_endianness *endianness) {
    return test_memory_at_addr(target, reg_sp, -8, endianness);
}
static int test_memory_at_static_mem(struct target *target, enum target_endianness *endianness) {
    write_gpr_u32(target,tmp_reg_addr,use_static_mem_addr(target));
    return test_memory_at_addr(target, tmp_reg_addr, 0, endianness);
}
static int test_memory_at_addr(struct target *target, uint32_t ra, int16_t shift, enum target_endianness *endianness) {
    enum MAGIC_WORDS{
        MAGIC_WORD_1 = 0x396F965C,
        MAGIC_WORD_2 = 0x44692D7E
    };
    int ret;
    uint8_t value[8];
    uint8_t magic[8];
    uint8_t endian;

     h_u32_to_be(magic+0, MAGIC_WORD_1);
     h_u32_to_be(magic+4, MAGIC_WORD_2);

    if (target->state != TARGET_HALTED) {
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = write_virt_mem_raw(target, tmp_reg_data, ra, shift+0, memory_access_size_word, magic+0);
    if (ret != ERROR_OK)
        return ret;
    ret = write_virt_mem_raw(target, tmp_reg_data, ra, shift+4, memory_access_size_word, magic+4);
    if (ret != ERROR_OK)
        return ret;

    ret = read_virt_mem_raw(target, tmp_reg_data, ra, shift+0, memory_access_size_word, value+0);
    if (ret != ERROR_OK)
        return ret;
    ret = read_virt_mem_raw(target, tmp_reg_data, ra, shift+4, memory_access_size_word, value+4);
    if (ret != ERROR_OK)
        return ret;
    ret = read_virt_mem_raw(target, tmp_reg_data, ra, shift+0, memory_access_size_byte, &endian);
    if (ret != ERROR_OK)
        return ret;

    // check the magic values
    if (memcmp(value, magic,8)!=0)
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
        code = ori(0,0,0);
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

        int ret = write_gpr_u32(target, rt, value);
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
        code = ori(0,0,0);
        assert(false);
    }
    target_to_ppc476fp(target)->gpr_regs[rt]->dirty = true;
    target_to_ppc476fp(target)->current_gpr_values_valid[rt] = false;

    ret = stuff_code(target, code);
    if (ret != ERROR_OK)
        return ret;

    if ( buffer != NULL ){
        uint32_t value;
        ret = read_gpr_u32(target, rt, &value);
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
static int read_spr_prepare(struct target *target, int spr_num){
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    return stuff_code(target, mfspr(tmp_reg_data,spr_num));
}
static int read_spr_buf(struct target *target, int spr_num, uint8_t *data) {
    int ret = read_spr_prepare(target, spr_num);
    if (ret != ERROR_OK)
        return ret;
    return read_gpr_buf(target, tmp_reg_data, data);
}
static int read_spr_u32(struct target *target, int spr_num, uint32_t *data) {
    int ret = read_spr_prepare(target, spr_num);
    if (ret != ERROR_OK)
        return ret;
    return read_gpr_u32(target, tmp_reg_data, data);
}

// запись значения data в spr-регистр
static int write_spr_complete(struct target *target, int spr_num) {
    return stuff_code(target, mtspr(spr_num,tmp_reg_data));
}
static int write_spr_buf(struct target *target, int spr_num, const uint8_t *data) {
    int ret = write_gpr_buf(target, tmp_reg_data, data);
    if (ret != ERROR_OK)
        return ret;

    ret = write_spr_complete(target, spr_num);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}
static int write_spr_u32(struct target *target, int spr_num, uint32_t data) {
    int ret = write_gpr_u32(target, tmp_reg_data, data);
    if (ret != ERROR_OK)
        return ret;

    ret = write_spr_complete(target, spr_num);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

// чтение регистра fpu. Здесь много заковырок. Во-первых, fpu должен быть
// включен. Во-вторых, регистры fpu нельзя напрямую передать в JTAG или хотябы
// РОН, потому обращение к ним происходит через стек, потому он тоже должен
// работать.
static int read_fpr_reg(struct target *target, int reg_num, uint64_t *value) {

    static const uint64_t bad = 0x7ff00000babadedaull;
    *value = bad;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint8_t value_m[8];
    int ret;
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
        write_gpr_u32(target,tmp_reg_addr,use_static_mem_addr(target));
        endian = use_static_mem_endianness(target);
    } else if (use_stack_get(target)) {
        ra = reg_sp;
        shift = -8;
        endian = use_stack_endianness(target);
    } else {
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
        write_gpr_u32(target,tmp_reg_addr,use_static_mem_addr(target));
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

    ret = write_spr_u32(target, SPR_REG_NUM_DBCR0, data);
    if (ret != ERROR_OK)
        return ret;

    ppc476fp->DBCR0_value = data;

    return ERROR_OK;
}

// запись MSR.Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual
// 7.4.1 с. 173
static int write_MSR_buf(struct target *target, const uint8_t *data) {
    int ret;

    ret = write_gpr_buf(target, tmp_reg_data, data);
    if (ret != ERROR_OK)
        return ret;
    ret = stuff_code(target,mtmsr(tmp_reg_data,true));
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}
static int write_MSR_u32(struct target *target, uint32_t data) {
    int ret;

    ret = write_gpr_u32(target, tmp_reg_data, data);
    if (ret != ERROR_OK)
        return ret;
    ret = stuff_code(target,mtmsr(tmp_reg_data,true));
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

// чтение MSR.Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual
// 7.4.1 с. 173
static int read_MSR_prepare(struct target *target) {
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    return stuff_code(target,mfmsr(tmp_reg_data));
}
static int read_MSR_buf(struct target *target, uint8_t *data) {
    int ret;
    ret = read_MSR_prepare(target);
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_buf(target, tmp_reg_data, data);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}
static int read_MSR_u32(struct target *target, uint32_t *data) {
    int ret;

    ret = read_MSR_prepare(target);
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_u32(target, tmp_reg_data, data);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int read_DCR(struct target *target, uint32_t addr, uint32_t *value) {
    int ret;
    ret = write_gpr_u32(target, tmp_reg_addr, addr);
    if (ret != ERROR_OK)
        return ret;
    ret = stuff_code(target, mfdcrx(tmp_reg_data,tmp_reg_addr));
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_u32(target, tmp_reg_data, value);
    if (ret != ERROR_OK)
        return ret;
    return ERROR_OK;
}
static int write_DCR(struct target *target, uint32_t addr, uint32_t value) {
    int ret;
    ret = write_gpr_u32(target, tmp_reg_addr, addr);
    if (ret != ERROR_OK)
        return ret;
    ret = write_gpr_u32(target, tmp_reg_data, value);
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
        ret = write_spr_buf(target, SPR_REG_NUM_LR,ppc476fp->PC_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ret = stuff_code(target, blr());
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->PC_reg->dirty = false;
    }

    if (ppc476fp->CR_reg->dirty) {
        ret = write_gpr_buf(target, tmp_reg_data, ppc476fp->CR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ret = stuff_code(target, mtcr(tmp_reg_data));
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->CR_reg->dirty = false;
    }

    if (ppc476fp->MSR_reg->dirty) {
        ret = write_MSR_buf(target, ppc476fp->MSR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->MSR_reg->dirty = false;
    }

    if (ppc476fp->XER_reg->dirty) {
        ret = write_spr_buf(target, SPR_REG_NUM_XER,ppc476fp->XER_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->XER_reg->dirty = false;
    }

    if (ppc476fp->CTR_reg->dirty) {
        ret = write_spr_buf(target, SPR_REG_NUM_CTR, ppc476fp->CTR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->CTR_reg->dirty = false;
    }

    if (ppc476fp->LR_reg->dirty) {
        ret = write_spr_buf(target, SPR_REG_NUM_LR, ppc476fp->LR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->LR_reg->dirty = false;
    }
    for (i = 0; i < GPR_REG_COUNT; ++i) {
        reg = ppc476fp->gpr_regs[i];
        if (reg->dirty) {
            ret = write_gpr_buf(target, i, reg->value);
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
    uint32_t value = 0;
    int ret;

    if (target->state != TARGET_HALTED) {
        return ERROR_TARGET_NOT_HALTED;
    }

    for (i = 0; i < GPR_REG_COUNT; ++i) {
        reg = ppc476fp->gpr_regs[i];
        if (!reg->valid) {
            ret = read_gpr_buf(target, i, reg->value);
            if (ret != ERROR_OK)
                return ret;
            reg->valid = true;
            reg->dirty = false;
        }
    }

    if (!ppc476fp->LR_reg->valid) {
        ret = read_spr_buf(target, SPR_REG_NUM_LR, ppc476fp->LR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->LR_reg->valid = true;
        ppc476fp->LR_reg->dirty = false;
    }

    if (!ppc476fp->CTR_reg->valid) {
        ret = read_spr_buf(target, SPR_REG_NUM_CTR, ppc476fp->CTR_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->CTR_reg->valid = true;
        ppc476fp->CTR_reg->dirty = false;
    }

    if (!ppc476fp->XER_reg->valid) {
        ret = read_spr_buf(target, SPR_REG_NUM_XER, ppc476fp->XER_reg->value);
        if (ret != ERROR_OK)
            return ret;
        ppc476fp->XER_reg->valid = true;
        ppc476fp->XER_reg->dirty = false;
    }

    if (!ppc476fp->MSR_reg->valid) {
        ret = read_MSR_buf(target, ppc476fp->MSR_reg->value);
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
        ret = read_gpr_buf(target, tmp_reg_data, ppc476fp->CR_reg->value);
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
        ret = read_spr_u32(target, SPR_REG_NUM_LR, &value);
        if (ret != ERROR_OK)
            return ret;
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
            uint64_t value = le_to_h_u64(reg->value);
            ret = write_fpr_reg(target, i, value);
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
            ret = read_fpr_reg(target, i, &value);
            if (ret == ERROR_OK) {
                h_u64_to_le(reg->value, value);
                reg->valid = true;
            } else if (ret == ERROR_TARGET_RESOURCE_NOT_AVAILABLE){
                h_u64_to_le(reg->value, value);
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

    MSR_new_value = le_to_h_u32(buf);
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
    ret = write_MSR_u32(target, MSR_new_value);
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
        ppc476fp->current_gpr_values_valid[i] = false;
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
    ppc476fp->use_resident = resident_state_disabled;
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

    ret = write_spr_u32(target, SPR_REG_NUM_IAC_BASE + iac_index,
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
    uint8_t test_value[4];

    uint8_t trap_code[4];
    target_buffer_set_u32(target,trap_code,trap());


    ret = write_gpr_u32(target,tmp_reg_addr,(uint32_t)bp->address);
    if (ret != ERROR_OK)
        return ret;

    ret = read_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, bp->orig_instr);
    if (ret != ERROR_OK)
        return ret;

    ret = write_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, trap_code);
    if (ret != ERROR_OK)
        return ret;

    ret = read_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, test_value);
    if (ret != ERROR_OK)
        return ret;

    ret = cache_l1i_invalidate(target, (uint32_t)bp->address, 4);
    if (ret != ERROR_OK)
        return ret;

    if (target_buffer_get_u32(target,test_value) == trap())
        bp->is_set = 1;
    else
        LOG_WARNING("soft breakpoint cannot be set at address 0x%08X",
                    (uint32_t)bp->address);

    return ERROR_OK;
}

// Снятие программной точки останова
static int unset_soft_breakpoint(struct target *target, struct breakpoint *bp) {
    uint8_t test_value[4];
    int ret;

    assert(bp->is_set != 0);

    ret = write_gpr_u32(target,tmp_reg_addr,(uint32_t)bp->address);
    if (ret != ERROR_OK)
        return ret;

    ret = write_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, bp->orig_instr);
    if (ret != ERROR_OK)
        return ret;

    ret = read_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, 0, memory_access_size_word, test_value);
    if (ret != ERROR_OK)
        return ret;

    ret = cache_l1i_invalidate(target, (uint32_t)bp->address, 4);
    if (ret != ERROR_OK)
        return ret;

    if (memcmp(test_value, bp->orig_instr, 4) == 0)
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

    ret = write_spr_u32(target, SPR_REG_NUM_DAC_BASE + dac_index,
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
        dac_mask = 0;
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
	ret = write_gpr_u32 (target, tmp_reg_addr, i);
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

    ret = write_spr_u32(target, SPR_REG_NUM_DBCR1, 0);
    if (ret != ERROR_OK)
        return ret;
    ret = write_spr_u32(target, SPR_REG_NUM_DBCR2, 0);
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
        ret = write_JDCR(target, JDCR_RESET_CHIP | JDCR_STO_MASK);
        if (ret != ERROR_OK)
            return ret;
        target->state = TARGET_HALTED;
    }
    ret = write_spr_u32(target, SPR_REG_NUM_SRR1, 0);
    if (ret != ERROR_OK)
        return ret;
    ret = write_spr_u32(target, SPR_REG_NUM_CSRR1, 0);
    if (ret != ERROR_OK)
        return ret;
    ret = write_spr_u32(target, SPR_REG_NUM_MCSRR1, 0);
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
    uint8_t DBDR_value[4];
    int ret;

    jtag_add_tlr();
    tap_ext->last_coreid = -1;
    ret = read_DBDR(target, DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_DBDR(target, 0xbabadeda);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_DBDR(target, DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    if (le_to_h_u32(DBDR_value) != 0xbabadeda) {
        return ERROR_TARGET_FAILURE;
    }

    ret = write_DBDR(target, 0xdedababa);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_DBDR(target, DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    if (le_to_h_u32(DBDR_value) != 0xdedababa) {
        return ERROR_TARGET_FAILURE;
    }

    ret = write_DBDR(target, 0xaaaaaaaa);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_DBDR(target, DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    if (le_to_h_u32(DBDR_value) != 0xaaaaaaaa) {
        return ERROR_TARGET_FAILURE;
    }

    ret = write_DBDR(target, 0x55555555);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = read_DBDR(target, DBDR_value);
    if (ret != ERROR_OK) {
        return ret;
    }

    if (le_to_h_u32(DBDR_value) != 0x55555555) {
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
    ret = write_gpr_u32(target, tmp_reg_addr, search_ind);
    if (ret != ERROR_OK)
        return ret;

    ret = stuff_code(target, tlbre(tmp_reg_data, tmp_reg_addr, 0));
    target_to_ppc476fp(target)->gpr_regs[tmp_reg_data]->dirty = true;
    target_to_ppc476fp(target)->current_gpr_values_valid[tmp_reg_data] = false;
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_u32(target, tmp_reg_data, &hw->data[0]);
    if (ret != ERROR_OK)
        return ret;

    // otimization for non-valid UTLB records
    if ((hw->data[0] & TLB_0_V_MASK) == 0)
        return ERROR_OK;

    ret = stuff_code(target, tlbre(tmp_reg_data, tmp_reg_addr, 1));
    target_to_ppc476fp(target)->current_gpr_values_valid[tmp_reg_data] = false;
    if (ret != ERROR_OK)
        return ret;

    ret = read_gpr_u32(target, tmp_reg_data, &hw->data[1]);
    if (ret != ERROR_OK)
        return ret;

    ret = stuff_code(target, tlbre(tmp_reg_data, tmp_reg_addr, 2));
    target_to_ppc476fp(target)->current_gpr_values_valid[tmp_reg_data] = false;
    if (ret != ERROR_OK)
        return ret;
    ret = read_gpr_u32(target, tmp_reg_data, &hw->data[2]);
    if (ret != ERROR_OK)
        return ret;

    ret = read_spr_u32(target, SPR_REG_NUM_MMUCR, &mmucr_value);
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

    ret = write_spr_u32(target, SPR_REG_NUM_MMUCR, tid);
    if (ret != ERROR_OK)
        return ret;

    if ((hw->bltd < bltd_no) && (data0 & TLB_0_V_MASK)) {
        indexed_value = 0x8000000 | (hw->bltd << 24);
    } else {
        indexed_value =
            ((index_way & 0x3) << 29) | 0x80000000; // the way is set manually
    }
    ret = write_gpr_u32(target, tmp_reg_data, indexed_value);
    if (ret != ERROR_OK)
        return ret;

    ret = write_gpr_u32(target, tmp_reg_addr, data0);
    if (ret != ERROR_OK)
        return ret;

    target_to_ppc476fp(target)->memory_checked = false;

    ret = stuff_code(target,tlbwe(tmp_reg_addr,tmp_reg_data,0));
    if (ret != ERROR_OK)
        return ret;

    // otimization for non-valid UTLB records
    if ((data0 & TLB_0_V_MASK) == 0)
        return ERROR_OK;

    ret = write_gpr_u32(target, tmp_reg_addr, hw->data[1]);
    if (ret != ERROR_OK)
        return ret;

    ret = stuff_code(target,tlbwe(tmp_reg_addr,tmp_reg_data,1));
    if (ret != ERROR_OK)
        return ret;

    ret = write_gpr_u32(target, tmp_reg_addr, hw->data[2]);
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

    ret = read_MSR_u32(target, &state->saved_MSR);
    if (ret != ERROR_OK)
        return ret;

    ret = read_spr_u32(target, SPR_REG_NUM_MMUCR, &state->saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int init_phys_mem(struct target *target, struct phys_mem_state *state) {
    int ret;

    // set MSR
    ret = write_MSR_u32(target, state->saved_MSR & (~MSR_PR_MASK) ); // problem mode and TS=1
    if (ret != ERROR_OK)
        return ret;

    // set MMUCR
    ret = write_spr_u32(target, SPR_REG_NUM_MMUCR, 0x80000000);
    if (ret != ERROR_OK)
        return ret;

    // syncing
    ret = stuff_code(target, isync());
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int restore_phys_mem(struct target *target,
                            struct phys_mem_state *state) {
    int ret;

    // restore MMUCR
    ret = write_spr_u32(target, SPR_REG_NUM_MMUCR, state->saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    // restore MSR
    ret = write_MSR_u32(target, state->saved_MSR);
    if (ret != ERROR_OK)
        return ret;

    // syncing
    ret = stuff_code(target, isync());
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int access_phys_mem(struct target *target, uint32_t new_erpn) {

    int ret = ERROR_OK;

    ret = write_spr_u32(target, SPR_REG_NUM_RMPD, (new_erpn<<20)|0x28180|(target->endianness==TARGET_LITTLE_ENDIAN?0x4000:0));
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
        return ERROR_COMMAND_ARGUMENT_UNDERFLOW;
    *current_mask |= param_mask;

    ret = parse_ulong(param, &value);
    if (ret != ERROR_OK)
        return ERROR_COMMAND_ARGUMENT_INVALID; // not ret

    if (value > max_value)
        return ERROR_COMMAND_ARGUMENT_OVERFLOW;

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

    params->erpn=0;
    params->mask=0;
    params->tid=0;
    params->ts=0;
    params->dsiz = DSIZ_4K;
    params->way = 4;
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
        if (p == NULL){
            LOG_ERROR("argument without value: %s",arg);
            return ERROR_COMMAND_ARGUMENT_INVALID;
        }

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
                ret = ERROR_COMMAND_ARGUMENT_UNDERFLOW;
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
                ret = ERROR_COMMAND_ARGUMENT_UNDERFLOW;
            else {
                if (strcmp(p, "auto") == 0) {
                    params->mask |= TLB_PARAMS_MASK_WAY;
                    params->way = 4;
                    ret = ERROR_OK;
                } else
                    ret = parse_uint32_params(TLB_PARAMS_MASK_WAY, 0x3, p,
                                              &params->mask,
                                              &params->way);
            }
        } else if (strncmp(arg, "bltd=",p-arg) == 0) {
            if ((params->mask & TLB_PARAMS_MASK_BLTD) != 0)
                ret = ERROR_COMMAND_ARGUMENT_UNDERFLOW;
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

        } else{
            LOG_ERROR("unknown argumnet: %s", arg);
            return ERROR_COMMAND_ARGUMENT_INVALID;
        }

        if (ret != ERROR_OK){
            switch ( ret ){
                case ERROR_COMMAND_ARGUMENT_UNDERFLOW:
                    LOG_ERROR("duplicate param: %s", arg);
                    break;
                case ERROR_COMMAND_ARGUMENT_OVERFLOW:
                    LOG_ERROR("too big value in: %s", arg);
                    break;
                case ERROR_COMMAND_ARGUMENT_INVALID:
                    LOG_ERROR("incorrect value in: %s", arg);
                    break;
            }
            return ERROR_COMMAND_ARGUMENT_INVALID;
        }
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
    uint32_t value_PID;
    int i;
    int record_count;
    int ret;

    // save MMUCR
    ret = read_spr_u32(target, SPR_REG_NUM_MMUCR, &saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    // load all uncached TLBs
    for (i = 0; i < TLB_NUMBER; ++i) {
        keep_alive();
        ret = load_uncached_tlb(target, i);
        if (ret != ERROR_OK)
            return ret;
    }

    ret = read_spr_u32(target, SPR_REG_NUM_SSPCR, &value_SSPCR);
    if (ret != ERROR_OK)
        return ret;
    ret = read_spr_u32(target, SPR_REG_NUM_USPCR, &value_USPCR);
    if (ret != ERROR_OK)
        return ret;
    ret = read_spr_u32(target, SPR_REG_NUM_PID, &value_PID);
    if (ret != ERROR_OK)
        return ret;

    // restore MMUCR
    ret = write_spr_u32(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
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
    command_print(CMD, "SSPCR = 0x%08X, USPCR = 0x%08X, PID = 0x%04X", value_SSPCR,
                  value_USPCR, value_PID);

    return ERROR_OK;
}

static int
handle_tlb_create_command_internal(struct command_invocation *cmd,
                                   struct target *target,
                                   struct tlb_command_params *params) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint32_t saved_MMUCR;
    int index = 0;
    uint32_t way;
    int index_way;
    int ret;
    uint32_t bltd;

    // save MMUCR
    ret = read_spr_u32(target, SPR_REG_NUM_MMUCR, &saved_MMUCR);
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
        ret = read_spr_u32(target, SPR_REG_NUM_MMUBE0, &mmube0);
        if (ret != ERROR_OK)
            return ret;
        ret = read_spr_u32(target, SPR_REG_NUM_MMUBE1, &mmube1);
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
        if (way == 4) {
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
    ret = write_spr_u32(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
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
    ret = read_spr_u32(target, SPR_REG_NUM_MMUCR, &saved_MMUCR);
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
    ret = write_spr_u32(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
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

    ret = read_spr_u32(target, SPR_REG_NUM_MMUCR, &saved_MMUCR);
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
    ret = write_spr_u32(target, SPR_REG_NUM_MMUCR, saved_MMUCR);
    if (ret != ERROR_OK)
        return ret;

    return ERROR_OK;
}

static int poll_internal(struct target *target) {
    enum target_state state;
    uint32_t JDSR_value, DBSR_value;
    int ret;
    uint8_t data_r[4];

    ret = read_JDSR(target, data_r);
    if (ret != ERROR_OK) {
        target->state = TARGET_UNKNOWN;
        return ret;
    }
    JDSR_value = le_to_h_u32(data_r);

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

        ret = read_spr_u32(target, SPR_REG_NUM_DBSR_RC, &DBSR_value);
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
    unsigned long long transactions_begin = transactions;
    unsigned long long detected_errors_begin = detected_errors;
    int ret = poll_internal(target);
    poll_transactions += transactions-transactions_begin;
    poll_detected_errors += detected_errors-detected_errors_begin;
    transactions = transactions_begin;
    detected_errors = detected_errors_begin;
    return ret;
}

static void arch_state(struct target *target, char *st, size_t l) {
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);

    snprintf(st,l,"target halted due to %s, coreid=%i, PC: 0x%08X, DW %s",
             debug_reason_name(target), target->coreid,
             get_reg_value_32(ppc476fp->PC_reg), (ppc476fp->DWE?"enabled":"disabled"));
}

// call only then the target is halted
static int ppc476fp_arch_state(struct target *target) {
    char st[256];
    arch_state(target,st,sizeof(st));
    LOG_USER("%s",st);

    return ERROR_OK;
}

static int halt_and_wait(struct target *target, int count){

    int ret = ERROR_OK;
    bool dwe = target_to_ppc476fp(target)->DWE;
    uint8_t data_r[4];
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
        ret = read_JDSR(target, data_r);
        if (ret != ERROR_OK) {
            target->state = TARGET_UNKNOWN;
            return ret;
        }
        JDSR_value = le_to_h_u32(data_r);

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

        char st[256];
        arch_state(target,st,sizeof(st));
        LOG_INFO("%s",st);
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
    else{
        ppc476fp_arch_state(target);
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

    *reg_list_size = ALL_REG_COUNT;
    *reg_list = malloc(sizeof(struct reg *) * ALL_REG_COUNT);
    memcpy(*reg_list, ppc476fp->all_regs, sizeof(struct reg *) * ALL_REG_COUNT);

    return ERROR_OK;
}

static int fast_read(struct target *target, target_addr_t address, enum memory_access_size size, uint32_t count, uint8_t *data){
    int ret = ERROR_OK;

    struct ppc476fp_common * ppc476fp = target_to_ppc476fp(target);

    LOG_DEBUG("coreid=%i, address: %#" PRIx64 ", size: %" PRIu32 ", count: %#" PRIx32,
              target->coreid, address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = use_resident_load(target);
    if ( ret != ERROR_OK )
        return ret;

    const uint32_t base = use_resident_addr(target)+
        (size == 4 ? resident_read_words : (size == 2 ? resident_read_halfs : resident_read_bytes));

    ret = write_gpr_u32(target,tmp_reg_data,base);
    if (ret != ERROR_OK)
        return ret;

    ret = write_gpr_u32(target,tmp_reg_addr,address-size);
    if (ret != ERROR_OK)
        return ret;

    ppc476fp->PC_reg->dirty = true;
    ppc476fp->CTR_reg->dirty = true;

    ret = stuff_code(target,mtspr(SPR_REG_NUM_CTR,tmp_reg_data));
    if(ret!=ERROR_OK)
        return ret;

    ret = stuff_code(target,bctr());
    if(ret!=ERROR_OK)
        return ret;

    ret = stuff_code(target,mtspr(SPR_REG_NUM_IAC1,tmp_reg_data));
    if(ret!=ERROR_OK)
        return ret;

    ret = write_spr_u32(target,SPR_REG_NUM_DBCR0,ppc476fp->DBCR0_value|DBCR0_IAC1_MASK);
    if(ret!=ERROR_OK)
        return ret;

    ret = write_JDCR(target, JDCR_FT_MASK|JDCR_UDE_MASK);
    if (ret != ERROR_OK)
        return ret;
    ppc476fp->current_gpr_values_valid[tmp_reg_addr]=false;
    ppc476fp->current_gpr_values_valid[tmp_reg_data]=false;
    while ( count-- ){
        // запись JDCR:RSDBSR не приводит к возобновлению исполнения
        ret = write_DBDR_CONT(target, count);
        if(ret!=ERROR_OK)
            return ret;
        uint8_t rd[4];
        ret = read_DBDR(target,rd);
        if(ret!=ERROR_OK)
            return ret;
        switch (size){
            case memory_access_size_word:
                target_buffer_set_u32(target,data,le_to_h_u32(rd));
                break;
            case memory_access_size_half_word:
                target_buffer_set_u16(target,data,le_to_h_u16(rd));
                break;
            case memory_access_size_byte:
                *data = *rd;
                break;
            default:
                assert(0);
        }
        data+=size;
        keep_alive();
    }
    ret = write_JDCR(target, JDCR_UDE_MASK|(ppc476fp->DWE?JDCR_DWS_MASK:JDCR_STO_MASK));
    if (ret != ERROR_OK)
        return ret;

    ret = write_spr_u32(target,SPR_REG_NUM_DBCR0,ppc476fp->DBCR0_value);
    if(ret!=ERROR_OK)
        return ret;

    return flush_registers(target);
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

    LOG_DEBUG("coreid=%i, address: %#" PRIx64 ", size: %" PRIu32 ", count: %#" PRIx32,
              target->coreid, address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) ||
        !(buffer))
        return ERROR_COMMAND_SYNTAX_ERROR;

    if ( count > 16 && use_resident_get(target) ){
        ret = fast_read(target,address,size,count,buffer);
        return ret;
    }

    for (i = 0; i < count; ++i) {
        keep_alive();
        if ((int)((i+1)*size-shifted)>32768){
            shifted += 65536;
            ret = write_gpr_u32(target, tmp_reg_addr, address+shifted);
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

static int fast_write(struct target *target, target_addr_t address, enum memory_access_size size, uint32_t count, const uint8_t *data){
    int ret = ERROR_OK;

    LOG_DEBUG("coreid=%i, address: %#" PRIx64 ", size: %" PRIu32 ", count: %#" PRIx32,
        target->coreid, address, size, count);
    struct ppc476fp_common * ppc476fp = target_to_ppc476fp(target);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    ret = use_resident_load(target);
    if ( ret != ERROR_OK )
        return ret;

    const uint32_t base = use_resident_addr(target)+
        (size == 4 ? resident_write_words : (size == 2 ? resident_write_halfs : resident_write_bytes));

    ret = write_gpr_u32(target,tmp_reg_data,base);
    if (ret != ERROR_OK)
        return ret;

    ret = write_gpr_u32(target,tmp_reg_addr,address-size);
    if (ret != ERROR_OK)
        return ret;

    ppc476fp->PC_reg->dirty = true;
    ppc476fp->CTR_reg->dirty = true;

    ret = stuff_code(target,mtspr(SPR_REG_NUM_CTR,tmp_reg_data));
    if(ret!=ERROR_OK)
        return ret;

    ret = stuff_code(target,bctr());
    if(ret!=ERROR_OK)
        return ret;

    ret = stuff_code(target,mtspr(SPR_REG_NUM_IAC1,tmp_reg_data));
    if(ret!=ERROR_OK)
        return ret;

    ret = write_spr_u32(target,SPR_REG_NUM_DBCR0,ppc476fp->DBCR0_value|DBCR0_IAC1_MASK);
    if(ret!=ERROR_OK)
        return ret;

    ret = write_JDCR(target, JDCR_FT_MASK|JDCR_UDE_MASK);
    if (ret != ERROR_OK)
        return ret;
    ppc476fp->current_gpr_values_valid[tmp_reg_addr]=false;
    ppc476fp->current_gpr_values_valid[tmp_reg_data]=false;
    while ( count-- ){
        const uint32_t word = 
        (size == 4 ? target_buffer_get_u32(target,data) : (size == 2 ? target_buffer_get_u16(target,data) : *data));
        ret = write_DBDR_CONT(target, word);
        data+=size;
        if ( ret != ERROR_OK ){
            return ret;
        }
        keep_alive();
    }
    ret = write_JDCR(target, JDCR_UDE_MASK|(ppc476fp->DWE?JDCR_DWS_MASK:JDCR_STO_MASK));
    if (ret != ERROR_OK)
        return ret;

    ret = write_spr_u32(target,SPR_REG_NUM_DBCR0,ppc476fp->DBCR0_value);
    if(ret!=ERROR_OK)
        return ret;

    return flush_registers(target);
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

    LOG_DEBUG("coreid=%i, address: %#" PRIx64 ", size: %" PRIu32 ", count: %#" PRIx32,
        target->coreid, address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) ||
        !(buffer))
        return ERROR_COMMAND_SYNTAX_ERROR;

    if ( count > 16 && use_resident_get(target) ){
        ret = fast_write(target,address,size,count,buffer);
        return ret;
    }
    for (i = 0; i < count; ++i) {
        keep_alive();
        if ((int)((i+1)*size-shifted)>32768){
            shifted += 65536;
            ret = write_gpr_u32(target, tmp_reg_addr, address+shifted);
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

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = use_resident_load(target);
    if (ret != ERROR_OK)
        return ret;

    const uint32_t base = use_resident_addr(target)+resident_crc32;

    ret = write_gpr_u32(target,3,base);
    if (ret != ERROR_OK)
        return ret;

    struct ppc476fp_common * ppc476fp = target_to_ppc476fp(target);

    ppc476fp->gpr_regs[9]->dirty = true;
    ppc476fp->gpr_regs[10]->dirty = true;
    ppc476fp->PC_reg->dirty = true;
    ppc476fp->CR_reg->dirty = true;
    ppc476fp->CTR_reg->dirty = true;

    ppc476fp->current_gpr_values_valid[9]=false;
    ppc476fp->current_gpr_values_valid[10]=false;

    ret = write_gpr_u32(target,4,address-1);
    if (ret != ERROR_OK)
        return ret;
    ret = write_gpr_u32(target,5,address+count-1);
    if (ret != ERROR_OK)
        return ret;

    ret = stuff_code(target,mtspr(SPR_REG_NUM_CTR,3));
    if(ret!=ERROR_OK)
        return ret;

    ret = stuff_code(target,bctr());
    if(ret!=ERROR_OK)
        return ret;

    ret = write_JDCR(target, JDCR_FT_MASK|JDCR_UDE_MASK);
    if (ret != ERROR_OK)
        return ret;

    ret = write_DBDR_CONT(target, 0);
    if(ret!=ERROR_OK)
        return ret;

    for ( uint32_t i = count ; i > 0 ; --i ){
        uint32_t JDSR_value = 0;
        uint8_t data_r[4];
        keep_alive();
        ret = read_JDSR(target, data_r);
        if (ret != ERROR_OK) {
            target->state = TARGET_UNKNOWN;
            return ret;
        }
        JDSR_value = le_to_h_u32(data_r);

        if (is_halted(JDSR_value)){
            break;
        }
    }

    ret = write_JDCR(target, JDCR_UDE_MASK|(ppc476fp->DWE?JDCR_DWS_MASK:JDCR_STO_MASK));
    if(ret!=ERROR_OK)
        return ret;

    ret = read_gpr_u32(target,3,checksum);
    if (ret != ERROR_OK)
        return ret;
    LOG_DEBUG("crc %08x",*checksum);

    return flush_registers(target);
}

static int ppc476fp_add_breakpoint(struct target *target,
                                   struct breakpoint *breakpoint) {
    LOG_DEBUG("coreid=%i, address=%#" PRIx64 ", type=%i, length=%#x",
            target->coreid, breakpoint->address, breakpoint->type, breakpoint->length);

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

    LOG_DEBUG("coreid=%i, address=%#" PRIx64 ", type=%i, length=%#x", target->coreid,
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

    LOG_DEBUG("coreid=%i, address=%#" PRIx64 ", rw=%i, length=%#" PRIx32 ", value=%#" PRIx32 ", mask=%#" PRIx32,
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

    LOG_DEBUG("coreid=%i, address=%#" PRIx64 ", rw=%i, length=%#" PRIx32 ", value=%#" PRIx32 ", mask=%#" PRIx32,
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
    ppc476fp->common_magic = PPC476FP_COMMON_MAGIC;

    LOG_DEBUG("coreid=%i", target->coreid);

    if ((target->coreid < 0) || (target->coreid > 3)) {
        LOG_ERROR("coreid=%i is not allowed. It must be from 0 to 3. It has "
                  "been set to 0.",
                  target->coreid);
        target->coreid = 0;
    }

    return ERROR_OK;
}

static int ppc476fp_jim_configure(struct target *target, struct jim_getopt_info *goi){

    struct ppc476fp_prv_conf *pc;
    int e;
    enum ppc476fp_prv_conf_param{
        CFG_L2_DCR_BASE,
        CFG_USE_GPR_XOR_OPTIMIZATION,
    };
    static const struct jim_nvp nvp_config_opts[] = {
        { .name = "-l2-dcr-base",           .value = CFG_L2_DCR_BASE },
        { .name = "-gpr-xor-optimization",  .value = CFG_USE_GPR_XOR_OPTIMIZATION },
        { .name = NULL, .value = -1 }
    };

    pc = (struct ppc476fp_prv_conf*)target->private_config;
    if ( pc == NULL ){
        pc = calloc(1, sizeof(struct ppc476fp_prv_conf));
        if ( pc == NULL ){
            LOG_ERROR("Out of memory");
            return JIM_ERR;
        }
        pc->cache_base = DCR_L2_BASE_ADDR;
        target->private_config = pc;
    }

	Jim_SetEmptyResult(goi->interp);
	struct jim_nvp *n;
	e = jim_nvp_name2value_obj(goi->interp, nvp_config_opts,
				goi->argv[0], &n);
    if ( e != JIM_OK ) return JIM_CONTINUE;
	e = jim_getopt_obj(goi, NULL);
	if (e != JIM_OK)
		return e;
    switch (n->value){
    case CFG_L2_DCR_BASE:
        if ( goi->isconfigure ){
            Jim_Obj *o_t;
            long r;
            e = jim_getopt_obj(goi, &o_t);
            if ( e!= JIM_OK )
                return e;
            e = Jim_GetLong(goi->interp, o_t, &r);
            if ( e!= JIM_OK )
                return e;
            if (((unsigned long)r>0xffffffffu)){
				Jim_SetResultString(goi->interp,
					"incorrect DCR addr", -1);
				return JIM_ERR;
            }
            pc->cache_base = r;
        }else{
            Jim_WrongNumArgs(goi->interp, goi->argc, goi->argv, "NO PARAMS");
        }
        break;
    case CFG_USE_GPR_XOR_OPTIMIZATION:
        if ( goi->isconfigure ){
            Jim_Obj *o_t;
            int r;
            e = jim_getopt_obj(goi, &o_t);
            if ( e!= JIM_OK )
                return e;
            e = Jim_GetBoolean(goi->interp, o_t, &r);
            if ( e!= JIM_OK )
                return e;
            pc->use_gpr_xor_optimization = r;
        }else{
            Jim_WrongNumArgs(goi->interp, goi->argc, goi->argv, "NO PARAMS");
        }
        break;
    }
    return JIM_OK;
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
    uint32_t ispcr_saved = 0, ispcr = 0, ispcr_local = 0, ispcr_global = 0;
    uint32_t mmucr_saved = 0, mmucr = 0;
    struct ppc476fp_common *ppc476fp = target_to_ppc476fp(target);
    uint32_t pid, msr = get_reg_value_32(ppc476fp->MSR_reg);
    do{
        uint32_t index,cr;
        ret = read_spr_u32(target,SPR_REG_NUM_ISPCR,&ispcr_saved);
        if(ret!=ERROR_OK)
            break;
        ret = read_spr_u32(target,SPR_REG_NUM_MMUCR,&mmucr_saved);
        if(ret!=ERROR_OK)
            break;
        ret = read_spr_u32(target,SPR_REG_NUM_PID,&pid);
        if(ret!=ERROR_OK)
            break;
        ret = read_spr_u32(target,((msr&MSR_PR_MASK)!=0)?SPR_REG_NUM_USPCR:SPR_REG_NUM_SSPCR,&ispcr);
        if(ret!=ERROR_OK)
            break;
        ispcr_local = ispcr & 0x77777777u;
        // оставляем поля порядка поиска только там, где есть ведущие единицы
        // нужно для поиска глобальных записей
        ispcr_global = (((ispcr & 0x88888888u) >> 3)*0x7)&ispcr;

        ret = write_gpr_u32(target,tmp_reg_addr,(uint32_t)address);
        if(ret!=ERROR_OK)
            break;

        if ( ispcr_global ){
            mmucr = (mmucr_saved & 0xfffe0000u) | (msr&MSR_DS_MASK?0x10000:0);
            ret = write_spr_u32(target,SPR_REG_NUM_ISPCR,ispcr_global);
            if(ret!=ERROR_OK)
                break;
            ret = write_spr_u32(target,SPR_REG_NUM_MMUCR,mmucr);
            if(ret!=ERROR_OK)
                break;
            ppc476fp->CR_reg->dirty = true;
            ppc476fp->gpr_regs[tmp_reg_data]->dirty = true;
            ppc476fp->current_gpr_values_valid[tmp_reg_data] = false;
            ret = stuff_code(target,tlbsx_(tmp_reg_data,0,tmp_reg_addr));
            if(ret!=ERROR_OK)
                break;
            ret = read_gpr_u32(target,tmp_reg_data,&index);
            if(ret!=ERROR_OK)
                break;
            ret = stuff_code(target,mfcr(tmp_reg_data));
            if(ret!=ERROR_OK)
                break;
            ret = read_gpr_u32(target,tmp_reg_data,&cr);
            if(ret!=ERROR_OK)
                break;
            if((cr&1u<<(31-2))!=0){
                index = ((index>>16)&0xff)*4+(index>>29);
                ret = load_uncached_tlb(target, index);
                if(ret!=ERROR_OK)
                    break;
                target_addr_t result = ppc476fp->tlb_cache[index].hw.data[1]&0x3ffu;
                result <<= 32;
                result |= (ppc476fp->tlb_cache[index].hw.data[0]&0xfffff000u)^address^(ppc476fp->tlb_cache[index].hw.data[1]&0xfffff000u);
                *physical = result;
                break;
            }
        }
        if ( ispcr_local ){
            mmucr = (mmucr_saved & 0xfffe0000u) | (msr&MSR_DS_MASK?0x10000:0) | (pid);
            ret = write_spr_u32(target,SPR_REG_NUM_ISPCR,ispcr_local);
            if(ret!=ERROR_OK)
                break;
            ret = write_spr_u32(target,SPR_REG_NUM_MMUCR,mmucr);
            if(ret!=ERROR_OK)
                break;
            ppc476fp->CR_reg->dirty = true;
            ppc476fp->gpr_regs[tmp_reg_data]->dirty = true;
            ppc476fp->current_gpr_values_valid[tmp_reg_data] = false;
            ret = stuff_code(target,tlbsx_(tmp_reg_data,0,tmp_reg_addr));
            if(ret!=ERROR_OK)
                break;
            ret = read_gpr_u32(target,tmp_reg_data,&index);
            if(ret!=ERROR_OK)
                break;
            ret = stuff_code(target,mfcr(tmp_reg_data));
            if(ret!=ERROR_OK)
                break;
            ret = read_gpr_u32(target,tmp_reg_data,&cr);
            if(ret!=ERROR_OK)
                break;
            if((cr&1u<<(31-2))!=0){
                index = ((index>>16)&0xff)*4+(index>>29);
                ret = load_uncached_tlb(target, index);
                if(ret!=ERROR_OK)
                    break;
                target_addr_t result = ppc476fp->tlb_cache[index].hw.data[1]&0x3ffu;
                result <<= 32;
                result |= (ppc476fp->tlb_cache[index].hw.data[0]&0xfffff000u)^address^(ppc476fp->tlb_cache[index].hw.data[1]&0xfffff000u);
                *physical = result;
                break;
            }
        }
        ret = ERROR_TARGET_TRANSLATION_FAULT;
    }while(0);
    if(ispcr!=0){
        ret |= write_spr_u32(target,SPR_REG_NUM_ISPCR,ispcr_saved);
        ret |= write_spr_u32(target,SPR_REG_NUM_MMUCR,mmucr_saved);
    }
    return ret | flush_registers(target);
}

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG
// communication BUG
static int ppc476fp_read_phys_memory(struct target *target,
                                     target_addr_t address, uint32_t size,
                                     uint32_t count, uint8_t *buffer) {
    struct phys_mem_state state;
    uint32_t last_erpn = -1; // not setuped yet
    uint32_t new_erpn;
    uint32_t i;
    int ret;
    int result = ERROR_OK;

    LOG_DEBUG("coreid=%i, address=%#" PRIx64 ", size=%" PRIu32 ", count=%#" PRIx32,
            target->coreid, address, size, count);

    if (target->state != TARGET_HALTED) {
        LOG_ERROR("target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    if ( address + size * count > 0x3ffffffffffull ){
        return ERROR_COMMAND_ARGUMENT_OVERFLOW;
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
        uint32_t pack_count = 0;
        for (i = 0; i < count; i+= pack_count) {
            new_erpn = (address >> 32) & 0x3ff;
            if (new_erpn != last_erpn) {
                ret = access_phys_mem(target, new_erpn);
                if (ret != ERROR_OK)
                    break;
                last_erpn = new_erpn;
            }
            pack_count = (0x100000000ull - (address+i*size)%0x100000000ull)/size;
            if (pack_count > count)
                pack_count = count;

            keep_alive();
            ret = ppc476fp_read_memory(target, (uint32_t)address, size, pack_count,buffer);
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

// IMPORTANT: Register autoincrement mode is not used becasue of JTAG
// communication BUG
static int ppc476fp_write_phys_memory(struct target *target,
                                      target_addr_t address, uint32_t size,
                                      uint32_t count, const uint8_t *buffer) {
    struct phys_mem_state state;
    uint32_t last_erpn = -1; // not setuped yet
    uint32_t new_erpn;
    uint32_t i;
    int ret;
    int result = ERROR_OK;


    LOG_DEBUG("coreid=%i, address=%#" PRIx64 ", size=%" PRIu32 ", count=%#" PRIx32,
            target->coreid, address, size, count);

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
        uint32_t pack_count = 0;
        for (i = 0; i < count; i+= pack_count) {
            new_erpn = (address >> 32) & 0x3ff;
            if (new_erpn != last_erpn) {
                ret = access_phys_mem(target, new_erpn);
                if (ret != ERROR_OK)
                    break;
                last_erpn = new_erpn;
            }
            pack_count = (0x100000000ull - (address+i*size)%0x100000000ull)/size;
            if (pack_count > count)
                pack_count = count;

            keep_alive();
            ret = ppc476fp_write_memory(target, (uint32_t)address, size, pack_count,buffer);
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

static bool use_resident_get(struct target *target) {
    return target_to_ppc476fp(target)->use_resident != resident_state_disabled;
}

static bool use_resident_loaded(struct target *target) {
    return target_to_ppc476fp(target)->use_resident == resident_state_loaded;
}

static int use_resident_on(struct target *target) {
    if ( use_static_mem_get(target) ){
        if ( target_to_ppc476fp(target)->use_resident == resident_state_disabled ){
            target_to_ppc476fp(target)->use_resident = resident_state_enabled;
        }
        return ERROR_OK;
    }
    LOG_ERROR("use_static_mem need for use_resident");
    return ERROR_FAIL;
}

static int use_resident_off(struct target *target) {
    target_to_ppc476fp(target)->use_resident = resident_state_disabled;
    return ERROR_OK;
}

static uint32_t use_resident_addr(struct target *target){
    return use_static_mem_addr(target)+0x240;
}

static int use_resident_load(struct target *target){
    if ( use_resident_loaded(target) ){
        return ERROR_OK;
    }
    if ( use_resident_get(target) ){

        int ret = write_gpr_u32(target,tmp_reg_addr,use_resident_addr(target));
        if (ret != ERROR_OK)
            return ret;

        for ( size_t i = 0 ; i < sizeof(resident)/sizeof(resident[0]) ; i++ ){
            ret = write_gpr_u32(target,tmp_reg_data,resident[i]);
            if (ret != ERROR_OK)
                return ret;
            ret = write_virt_mem_raw(target, tmp_reg_data, tmp_reg_addr, i*4, memory_access_size_word, NULL);
            if (ret != ERROR_OK)
                return ret;
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
    LOG_WARNING("use_fpu enabled, disabling");
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
    ret = use_resident_off(target);
    if (ret != ERROR_OK) {
        return ret;
    }
    if (!use_fpu_get(target) || use_stack_get(target)) {
        ppc476fp->use_static_mem = 0xffffffff;
        return ERROR_OK;
    }
    LOG_WARNING("use_fpu enabled, disabling");
    ret = use_fpu_off(target, action);
    if (ret != ERROR_OK) {
        return ret;
    }
    ppc476fp->use_static_mem = 0xffffffff;
    return ERROR_OK;
}

static uint32_t decode_spr(const char *name){
#define REGNAME(x) if (strcmp(name,#x)==0){return SPR_REG_NUM_##x;}
    REGNAME(CCR0)
    REGNAME(CCR1)
    REGNAME(CCR2)
    REGNAME(CTR)
    REGNAME(CSRR0)
    REGNAME(CSRR1)
    REGNAME(DAC1)
    REGNAME(DAC2)
    REGNAME(DCDBTRH)
    REGNAME(DCDBTRL)
    REGNAME(DEAR)
    REGNAME(DVC1)
    REGNAME(DVC2)
    REGNAME(DCESR)
    REGNAME(DCRIPR)
    REGNAME(DBCR0)
    REGNAME(DBCR1)
    REGNAME(DBCR2)
    REGNAME(DBDR)
    REGNAME(DBSR_RC)
    REGNAME(DBSR_WO)
    REGNAME(DEC)
    REGNAME(DECAR)
    REGNAME(ESR)
    REGNAME(ICESR)
    REGNAME(IAC1)
    REGNAME(IAC2)
    REGNAME(IAC3)
    REGNAME(IAC4)
    REGNAME(ICDBDR0)
    REGNAME(ICDBDR1)
    REGNAME(ICDBTRH)
    REGNAME(ICDBTRL)
    REGNAME(IOCCR)
    REGNAME(IOCR1)
    REGNAME(IOCR2)
    REGNAME(XER)
    REGNAME(IVOR0 )
    REGNAME(IVOR1 )
    REGNAME(IVOR2 )
    REGNAME(IVOR3 )
    REGNAME(IVOR4 )
    REGNAME(IVOR5 )
    REGNAME(IVOR6 )
    REGNAME(IVOR7 )
    REGNAME(IVOR8 )
    REGNAME(IVOR9 )
    REGNAME(IVOR10)
    REGNAME(IVOR11)
    REGNAME(IVOR12)
    REGNAME(IVOR13)
    REGNAME(IVOR14)
    REGNAME(IVOR15)
    REGNAME(IVPR)
    REGNAME(LR)
    REGNAME(MCSRR0)
    REGNAME(MCSRR1)
    REGNAME(MCSR_RW)
    REGNAME(MCSR_CO)
    REGNAME(MMUBE0)
    REGNAME(MMUBE1)
    REGNAME(MMUCR)
    REGNAME(PMUCC0)
    REGNAME(PID)
    REGNAME(PIR)
    REGNAME(PVR)
    REGNAME(PWM)
    REGNAME(RMPD)
    REGNAME(RSTCFG)
    REGNAME(SRR0)
    REGNAME(SRR1)
    REGNAME(SPRG0)
    REGNAME(SPRG1)
    REGNAME(SPRG2)
    REGNAME(SPRG3)
    REGNAME(SPRG4)
    REGNAME(SPRG5)
    REGNAME(SPRG6)
    REGNAME(SPRG7)
    REGNAME(SPRG8)
    REGNAME(SSPCR)
    REGNAME(TBL_R)
    REGNAME(TBL_W)
    REGNAME(TBU_R)
    REGNAME(TBU_W)
    REGNAME(TCR)
    REGNAME(TSR_RC)
    REGNAME(TSR_WO)
    REGNAME(ISPCR)
    REGNAME(USPCR)
    REGNAME(USPGR0)
    return 0xffffffff;
#undef REGNAME
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

    if ((params.bltd < bltd_no) && (params.way > 0) && (params.way < 4)) {
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
COMMAND_HANDLER(ppc476fp_handle_tlb_drop_shadow_command){
    uint32_t saved_CCR2;
    struct target *target = get_current_target(CMD_CTX);

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = read_spr_u32(target, SPR_REG_NUM_CCR2, &saved_CCR2);
    if (ret != ERROR_OK) {
        LOG_ERROR("Can't read CCR2");
        return ret;
    }
    ret = write_spr_u32(target, SPR_REG_NUM_CCR2, saved_CCR2&0xf7ffffffu);
    if (ret != ERROR_OK) {
        LOG_ERROR("Can't write CCR2");
        return ret;
    }
    ret = stuff_code(target, isync());
    if (ret != ERROR_OK) {
        LOG_ERROR("Can't execute isync");
        return ret;
    }
    ret = write_spr_u32(target, SPR_REG_NUM_CCR2, saved_CCR2);
    if (ret != ERROR_OK) {
        LOG_ERROR("Can't write CCR2");
        return ret;
    }
    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_status_command) {
    struct target *target = get_current_target(CMD_CTX);
    uint8_t JDSR_value[4];
    int ret;

    unsigned long long transactions_begin = transactions;
    unsigned long long detected_errors_begin = detected_errors;

    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    command_print(CMD, "PowerPC JTAG status:");
    ret = read_JDSR(target, JDSR_value);
    if (ret != ERROR_OK) {
        command_print(CMD, "cannot read JDSR register");
    }else{
        command_print(CMD, "  JDSR = 0x%08X", le_to_h_u32(JDSR_value));
    }

    poll_transactions += transactions - transactions_begin;
    poll_detected_errors += detected_errors - detected_errors_begin;

    transactions = transactions_begin;
    detected_errors = detected_errors_begin;

    LOG_DEBUG("  transaction_counter: %llu",transactions);
    LOG_DEBUG("  detected_error_counter: %llu (%f%%)",detected_errors,100.0*detected_errors/transactions);
    LOG_DEBUG("  poll_transaction_counter: %llu",poll_transactions);
    LOG_DEBUG("  poll_detected_error_counter: %llu (%f%%)",poll_detected_errors,100.0*poll_detected_errors/poll_transactions);
    LOG_DEBUG("  detected_error_summary: %llu (%f%%)",detected_errors+poll_detected_errors,100.0*(detected_errors+poll_detected_errors)/(transactions+poll_transactions));

    return ret;
}

COMMAND_HANDLER(ppc476fp_handle_jtag_speed_command) {
    struct target *target = get_current_target(CMD_CTX);
    int64_t start_time = timeval_ms();
    uint32_t count = 0;
    uint8_t dummy_data[4];
    int ret = ERROR_OK;

    unsigned long long transactions_begin = transactions;
    unsigned long long detected_errors_begin = detected_errors;

    while (timeval_ms() - start_time < 1000) {
        ret = read_DBDR(target, dummy_data);
        if (ret != ERROR_OK) {
            LOG_ERROR("JTAG communication error");
            break;
        }
        ++count;
    }

    poll_transactions += transactions - transactions_begin;
    poll_detected_errors += detected_errors - detected_errors_begin;

    transactions = transactions_begin;
    detected_errors = detected_errors_begin;

    if ( ret == ERROR_OK ){
        command_print(CMD, "JTAG speed = %u (transaction per second)", count);
    }

    return ret;
}

COMMAND_HANDLER(ppc476fp_handle_dcr_read_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);

    int ret = read_DCR(target, addr, &data);
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

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);

    int ret = read_DCR(target, addr, &data);
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

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);

    int ret = write_DCR(target, addr, data);
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

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);

    int ret = read_DCR(target, addr, &read);
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

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);

    int ret = read_DCR(target, addr, &read);
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

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);

    int ret = read_DCR(target, addr, &read);
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

    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    uint32_t addr = decode_spr(CMD_ARGV[0]);
    if ( addr == 0xffffffff ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    }

    int ret = read_spr_u32(target, addr, &data);
    if (ret != ERROR_OK) {
        return ret;
    }

    command_print(CMD, "SPR %u(0x%x) = %u(0x%08x)", addr, addr, data, data);

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_spr_get_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    uint32_t addr = decode_spr(CMD_ARGV[0]);
    if ( addr == 0xffffffff ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    }

    int ret = read_spr_u32(target, addr, &data);
    if (ret != ERROR_OK) {
        return ret;
    }

    command_print_sameline(CMD, "%u", data);

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_spr_write_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    uint32_t addr = decode_spr(CMD_ARGV[0]);
    if ( addr == 0xffffffff ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    }
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);

    int ret = write_spr_u32(target, addr, data);
    if (ret != ERROR_OK) {
        return ret;
    }

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_spr_or_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t data;
    uint32_t read;
    struct target *target = get_current_target(CMD_CTX);

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    uint32_t addr = decode_spr(CMD_ARGV[0]);
    if ( addr == 0xffffffff ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    }
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);

    int ret = read_spr_u32(target, addr, &read);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_spr_u32(target, addr, (data|read) );
    if (ret != ERROR_OK) {
        return ret;
    }

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_spr_xor_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t data;
    uint32_t read;
    struct target *target = get_current_target(CMD_CTX);

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    uint32_t addr = decode_spr(CMD_ARGV[0]);
    if ( addr == 0xffffffff ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    }
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);

    int ret = read_spr_u32(target, addr, &read);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_spr_u32(target, addr, (data^read) );
    if (ret != ERROR_OK) {
        return ret;
    }

    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_handle_spr_and_command) {
    if (CMD_ARGC != 2)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t data;
    uint32_t read;
    struct target *target = get_current_target(CMD_CTX);

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    uint32_t addr = decode_spr(CMD_ARGV[0]);
    if ( addr == 0xffffffff ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    }
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);

    int ret = read_spr_u32(target, addr, &read);
    if (ret != ERROR_OK) {
        return ret;
    }

    ret = write_spr_u32(target, addr, (data&read) );
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

COMMAND_HANDLER(ppc476fp_handle_use_resident_on_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    struct target *target = get_current_target(CMD_CTX);
    return use_resident_on(target);
}

COMMAND_HANDLER(ppc476fp_handle_use_resident_get_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    if (use_resident_get(get_current_target(CMD_CTX))) {
        command_print(CMD, "resident using enabled %s",(use_resident_loaded(get_current_target(CMD_CTX))?"loaded":"not loaded"));
    } else {
        command_print(CMD, "resident using disabled");
    }

    return ERROR_OK;
}

COMMAND_HANDLER(ppc476fp_handle_use_resident_off_command) {
    if (CMD_ARGC != 0)
        return ERROR_COMMAND_SYNTAX_ERROR;

    struct target *target = get_current_target(CMD_CTX);
    return use_resident_off(target);
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
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);

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
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = write_gpr_u32(target, tmp_reg_addr, addr);
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
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = write_gpr_u32(target, tmp_reg_addr, addr);
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

COMMAND_HANDLER(ppc476fp_code_dcbz_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;
    uint32_t addr;
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = write_gpr_u32(target, tmp_reg_addr, addr);
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't write addr to tmp reg");
        return ret;
    }

    ret = stuff_code(target, dcbz(0,tmp_reg_addr));
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't run dcbz 0, R%i", tmp_reg_addr);
        return ret;
    }
    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_code_dcread_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;
    uint32_t addr;
    struct target *target = get_current_target(CMD_CTX);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = write_gpr_u32(target, tmp_reg_addr, addr);
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

    uint32_t data;
    ret = read_gpr_u32(target, tmp_reg_data, &data);
    if ( ret != ERROR_OK ){
        LOG_ERROR("Can't read rt value from tmp reg");
        return ret;
    }

    command_print_sameline(CMD, "%u", data);
    return flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_code_icbi_command) {
    if (CMD_ARGC != 1)
        return ERROR_COMMAND_SYNTAX_ERROR;
    uint32_t addr;
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = write_gpr_u32(target, tmp_reg_addr, addr);
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
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    struct target *target = get_current_target(CMD_CTX);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = write_gpr_u32(target, tmp_reg_addr, addr);
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
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    if (target->state != TARGET_HALTED){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = write_gpr_u32(target, tmp_reg_addr, addr);
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
                int ret = write_gpr_u32(target, tmp_reg_addr, way * 0x2000 + set * 0x20 + i * 4);
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
                uint32_t data;
                ret = read_gpr_u32(target,tmp_reg_data,&data);
                if ( ret != ERROR_OK ){
                    LOG_ERROR("Can't read data register");
                    return ret;
                }

                if ( i == 0 ) {

                    ret = read_spr_u32(target,SPR_REG_NUM_DCDBTRH,&dcdbtrh);
                    if ( ret != ERROR_OK ){
                        LOG_ERROR("Can't read dcdbtrh");
                        return ret;
                    }

                    if ( ( dcdbtrh & DCDBTRH_VALID_MASK ) == 0 ){
                        break;
                    }
                    command_print_sameline(CMD, " %02x:%i %03x:%08x", set,way,dcdbtrh&DCDBTRH_EXTADDR_MASK, (dcdbtrh&DCDBTRH_ADDR_MASK)|(set<<5));

                }
                command_print_sameline(CMD, " %08x", data);

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
                int ret = write_gpr_u32(target, tmp_reg_addr, way * 0x2000 + set * 0x20 + i*4);
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

                    ret = read_spr_u32(target,SPR_REG_NUM_ICDBTRH,&icdbtrh);
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
                ret = read_spr_u32(target,SPR_REG_NUM_ICDBDR0,&data);
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

static unsigned int addr_to_set(struct l2_context *context, uint64_t addr){
    return (addr/128)%(1u<<context->tag_n);
}

static unsigned int addr_to_tag(struct l2_context *context, uint64_t addr){
    return (addr/128)>>context->tag_n;
}

static void cache_l2_print_lru(struct command_invocation *cmd, int set, uint32_t lru_info){
    command_print(cmd, "set % 4i, LRU: %02x, Lock Bits: %x(%x), Inclusion Bits: %02x(%02x) [lru reg: %x]"
        ,set
        ,(lru_info>>26)&0x3f
        ,(lru_info>>18)&0xf, (lru_info>>22)&0xf
        ,(lru_info>>2)&0xff, (lru_info>>10)&0xff
        ,lru_info);
}

static void cache_l2_print_line(struct command_invocation *cmd, struct l2_line *line, int way, int ecc){
    static const char line_state_strings[8][3] = {"I ","--","S ","SL","E ","T ","M ","MU"};
    int subline = 0;
    if ( ecc ){
        command_print(cmd,"Way %i: state: %s, phys addr: %03x_%08x [tag reg: %08x(%02x)]:"
                ,way
                ,line_state_strings[((uint32_t)line->line_state)>>l2_cache_state_shift]
                ,(uint32_t)(line->base_addr>>32),(uint32_t)(line->base_addr)
                ,line->tag_info,line->ecc_tag);
        command_print(cmd," [+00] %08x_%08x(%02x) %08x_%08x(%02x) %08x_%08x(%02x) %08x_%08x(%02x)",
                line->data[subline+0][0],line->data[subline+0][1],line->ecc_data[subline+0],
                line->data[subline+1][0],line->data[subline+1][1],line->ecc_data[subline+1],
                line->data[subline+2][0],line->data[subline+2][1],line->ecc_data[subline+2],
                line->data[subline+3][0],line->data[subline+3][1],line->ecc_data[subline+3]
        );
        subline+=4;
        command_print(cmd," [+20] %08x_%08x(%02x) %08x_%08x(%02x) %08x_%08x(%02x) %08x_%08x(%02x)",
                line->data[subline+0][0],line->data[subline+0][1],line->ecc_data[subline+0],
                line->data[subline+1][0],line->data[subline+1][1],line->ecc_data[subline+1],
                line->data[subline+2][0],line->data[subline+2][1],line->ecc_data[subline+2],
                line->data[subline+3][0],line->data[subline+3][1],line->ecc_data[subline+3]
        );
        subline+=4;
        command_print(cmd," [+40] %08x_%08x(%02x) %08x_%08x(%02x) %08x_%08x(%02x) %08x_%08x(%02x)",
                line->data[subline+0][0],line->data[subline+0][1],line->ecc_data[subline+0],
                line->data[subline+1][0],line->data[subline+1][1],line->ecc_data[subline+1],
                line->data[subline+2][0],line->data[subline+2][1],line->ecc_data[subline+2],
                line->data[subline+3][0],line->data[subline+3][1],line->ecc_data[subline+3]
        );
        subline+=4;
        command_print(cmd," [+60] %08x_%08x(%02x) %08x_%08x(%02x) %08x_%08x(%02x) %08x_%08x(%02x)",
                line->data[subline+0][0],line->data[subline+0][1],line->ecc_data[subline+0],
                line->data[subline+1][0],line->data[subline+1][1],line->ecc_data[subline+1],
                line->data[subline+2][0],line->data[subline+2][1],line->ecc_data[subline+2],
                line->data[subline+3][0],line->data[subline+3][1],line->ecc_data[subline+3]
        );
    }else{
        command_print(cmd,"Way %i: state: %s, phys addr: %03x_%08x [tag reg: %08x]:"
                ,way
                ,line_state_strings[((uint32_t)line->line_state)>>l2_cache_state_shift]
                ,(uint32_t)(line->base_addr>>32),(uint32_t)(line->base_addr)
                ,line->tag_info);
        command_print(cmd," [+00] %08x_%08x %08x_%08x %08x_%08x %08x_%08x",
                line->data[subline+0][0],line->data[subline+0][1],
                line->data[subline+1][0],line->data[subline+1][1],
                line->data[subline+2][0],line->data[subline+2][1],
                line->data[subline+3][0],line->data[subline+3][1]
        );
        subline+=4;
        command_print(cmd," [+20] %08x_%08x %08x_%08x %08x_%08x %08x_%08x",
                line->data[subline+0][0],line->data[subline+0][1],
                line->data[subline+1][0],line->data[subline+1][1],
                line->data[subline+2][0],line->data[subline+2][1],
                line->data[subline+3][0],line->data[subline+3][1]
        );
        subline+=4;
        command_print(cmd," [+40] %08x_%08x %08x_%08x %08x_%08x %08x_%08x",
                line->data[subline+0][0],line->data[subline+0][1],
                line->data[subline+1][0],line->data[subline+1][1],
                line->data[subline+2][0],line->data[subline+2][1],
                line->data[subline+3][0],line->data[subline+3][1]
        );
        subline+=4;
        command_print(cmd," [+60] %08x_%08x %08x_%08x %08x_%08x %08x_%08x",
                line->data[subline+0][0],line->data[subline+0][1],
                line->data[subline+1][0],line->data[subline+1][1],
                line->data[subline+2][0],line->data[subline+2][1],
                line->data[subline+3][0],line->data[subline+3][1]
        );
    }
}

static int cache_l2_command_internal(struct l2_context *context, const uint64_t* addrs, int addr_count, int read_invalid, int ecc, struct command_invocation *cmd){
    int ret = ERROR_OK;
    for (uint32_t set=0;set<(1u<<context->tag_n);++set){
        uint32_t lru_info = 1;
        if ( addr_count > 0 ){
            int i;
            for ( i=0; i < addr_count ; i++ ){
                uint64_t wanted_set = addr_to_set(context,addrs[i]);
                if (set == wanted_set)
                    break;
            }
            if ( i == addr_count )
                continue;
        }
        for (uint32_t way = 0 ; way<4 ; ++way){
            struct l2_line line;
            ret = l2_read_line(context,set,way,ecc,read_invalid,0,0,&line);
            if (ret != ERROR_OK){
                LOG_ERROR("Can't read tag from set %i way %i", set, way);
                return ret;
            }
            bool need_print = (addr_count==0);
            if (!need_print){
                unsigned int tag = addr_to_tag ( context, line.base_addr);
                for ( int i=0; i < addr_count ; i++ ){
                    if ( addr_to_tag ( context, addrs[i] ) == tag ){
                        need_print = true;
                        break;
                    }
                }
            }
            if (
                    (!read_invalid) &&
                    ((line.line_state==l2_cache_state_invalid)||
                    (line.line_state==l2_cache_state_undefined))
                ){
                need_print = false;
            }
            if (need_print){
                // из-за битов чётности, LRU не может быть нулём
                if ( lru_info == 1 ){
                    ret = l2_read_lru(context, set, &lru_info);
                    if ( ret != ERROR_OK ){
                        LOG_ERROR("Can't read LRU from set %i", set);
                        return ret;
                    }
                    cache_l2_print_lru ( cmd, set, lru_info );
                }
                cache_l2_print_line(cmd,&line,way,ecc);
            }
            keep_alive();
        }
    }
    return ret;
}

COMMAND_HANDLER(ppc476fp_cache_l2_command) {
    enum param_type{
        L2_PARAM_TYPE_UNKNOWN,
        L2_PARAM_TYPE_ECC,
        L2_PARAM_TYPE_INVALID,
        L2_PARAM_TYPE_ADDR,
    };
    struct param_name{
        const char *name;
        int with_param;
        enum param_type ind;
    };
    enum internal{
        max_addrs_count=32,
    };
    uint64_t addrs[max_addrs_count];
    int addrs_count = 0;
    int read_invalid = 0;
    int ecc = 0;
    int ret = ERROR_OK;
    static const struct param_name params[]={
        {"ecc",0,L2_PARAM_TYPE_ECC},
        {"invalid",0,L2_PARAM_TYPE_INVALID},
        {"addr",1,L2_PARAM_TYPE_ADDR}
    };
    for (unsigned int i=0; i < CMD_ARGC; i++){
        char comm[32];
        enum param_type current_param = L2_PARAM_TYPE_UNKNOWN;
        const char *p = strchr(CMD_ARGV[i], '=');
        size_t param_len = p==NULL?strlen(CMD_ARGV[i]):(size_t)(p-CMD_ARGV[i]);
        strncpy(comm,CMD_ARGV[i],sizeof(comm)<param_len?sizeof(comm):param_len);
        comm[sizeof(comm)-1<param_len?sizeof(comm)-1:param_len]='\0';
        for (unsigned int j = 0; j < sizeof(params)/sizeof(params[0]) ; j++ ){
            if (((p==NULL)^(params[j].with_param?1:0))&&(strcmp(params[j].name,comm)==0)){
                current_param = params[j].ind;
            }
        }
        switch(current_param)
        {

            case L2_PARAM_TYPE_UNKNOWN:
                LOG_ERROR("%s: unknown param",CMD_ARGV[i]);
                return ERROR_COMMAND_SYNTAX_ERROR;
            case L2_PARAM_TYPE_ECC:
                ecc = 1;
                break;
            case L2_PARAM_TYPE_INVALID:
                read_invalid = true;
                break;
            case L2_PARAM_TYPE_ADDR:
                if(addrs_count>=max_addrs_count){
                    LOG_ERROR ("too many addrs");
                    return ERROR_COMMAND_SYNTAX_ERROR;
                }
                ret = parse_u64(p+1, &addrs[addrs_count++]);
                if(ret!=ERROR_OK){
                    LOG_ERROR ("%s is not u64", p+1);
                    return ERROR_COMMAND_SYNTAX_ERROR;
                }

                break;
        }
    }

    struct target *target = get_current_target(CMD_CTX);
    struct l2_context context;
    ret = l2_init_context(target,&context,tmp_reg_addr,tmp_reg_data,
            29,28,27,26,25);
    if (ret==ERROR_OK){
        keep_alive();
        ret = cache_l2_command_internal(&context, addrs, addrs_count, read_invalid, ecc, CMD);

        ret |= l2_restore_context(&context);
    }else{
        LOG_ERROR("init context failed");
    }
    return ret | flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_cache_l2_write_lru_command){
    struct target *target = get_current_target(CMD_CTX);
    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    int ret = ERROR_OK;
    if ( CMD_ARGC != 2 ){
        return ERROR_COMMAND_SYNTAX_ERROR;
    }
    uint32_t set;
    uint32_t data;
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], set);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);
    struct l2_context context;
    ret = l2_init_context(target,&context,tmp_reg_addr,tmp_reg_data,
            tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr);
    if (ret==ERROR_OK){
        if ( set < (1u<<context.tag_n) ){
            ret = l2_write_lru ( &context,set,data );
        }else{
            LOG_ERROR("Set too big");
            ret = ERROR_COMMAND_ARGUMENT_OVERFLOW;
        }
        ret |= l2_restore_context(&context);
    }else{
        LOG_ERROR("init context failed");
    }
    return ret | flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_cache_l2_write_tag_command){
    struct target *target = get_current_target(CMD_CTX);
    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    uint32_t set;
    uint32_t way;
    uint32_t data;
    uint32_t ecc = 0xffffffff;
    int ret = ERROR_OK;
    if ( CMD_ARGC < 3 ){
        return ERROR_COMMAND_SYNTAX_ERROR;
    } else {
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], set);
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], way);
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[2], data);
        if ( CMD_ARGC == 4 ){
            COMMAND_PARSE_NUMBER(u32, CMD_ARGV[3], ecc);
            if ( ecc > 0x7f ){
                LOG_ERROR("Ecc too big");
                return ERROR_COMMAND_ARGUMENT_OVERFLOW;
            }
        }else if (CMD_ARGC > 4 ){
            return ERROR_COMMAND_SYNTAX_ERROR;
        }
    }
    if ( way > 3 ){
        LOG_ERROR("Way too big");
        return ERROR_COMMAND_ARGUMENT_OVERFLOW;
    }
    struct l2_context context;
    ret = l2_init_context(target,&context,tmp_reg_addr,tmp_reg_data,
            tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr);
    if (ret==ERROR_OK){
        if ( set < (1u<<context.tag_n) ){
            ret = l2_write_tag ( &context,set,way,data,ecc );
        }else{
            LOG_ERROR("Set too big");
            ret = ERROR_COMMAND_ARGUMENT_OVERFLOW;
        }
        ret |= l2_restore_context(&context);
    }else{
        LOG_ERROR("init context failed");
    }
    return ret | flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_cache_l2_write_data_command){
    struct target *target = get_current_target(CMD_CTX);
    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    uint32_t set;
    uint32_t way;
    uint32_t shift;
    uint32_t datah;
    uint32_t datal;
    uint32_t ecc = 0xffffffff;
    int ret = ERROR_OK;
    if ( CMD_ARGC < 5 ){
        return ERROR_COMMAND_SYNTAX_ERROR;
    } else {
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], set);
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], way);
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[2], shift);
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[3], datah);
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[4], datal);
        if ( CMD_ARGC == 6 ){
            COMMAND_PARSE_NUMBER(u32, CMD_ARGV[5], ecc);
            if ( ecc > 0xff ){
                LOG_ERROR("Ecc too big");
                return ERROR_COMMAND_ARGUMENT_OVERFLOW;
            }
        }else if (CMD_ARGC > 6 ){
            return ERROR_COMMAND_SYNTAX_ERROR;
        }
    }
    if ( way > 3 ){
        LOG_ERROR("Way too big");
        return ERROR_COMMAND_ARGUMENT_OVERFLOW;
    }
    if ( shift > 15 ){
        LOG_ERROR("Shift too big");
        return ERROR_COMMAND_ARGUMENT_OVERFLOW;
    }
    struct l2_context context;
    ret = l2_init_context(target,&context,tmp_reg_addr,tmp_reg_data,
            tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr);
    if (ret==ERROR_OK){
        if ( set < (1u<<context.tag_n) ){
            ret = l2_write_data ( &context,set,way,shift,datah,datal,ecc );
        }else{
            LOG_ERROR("Set too big");
            ret = ERROR_COMMAND_ARGUMENT_OVERFLOW;
        }
        ret |= l2_restore_context(&context);
    }else{
        LOG_ERROR("init context failed");
    }
    return ret | flush_registers(target);
}

COMMAND_HANDLER(ppc475fp_cache_l2_info_command){
    struct target *target = get_current_target(CMD_CTX);
    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    struct l2_context context;
    int ret = ERROR_OK;
    ret = l2_init_context(target,&context,tmp_reg_addr,tmp_reg_data,
            tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr);
    if (ret==ERROR_OK){
        static const char sizes[4][8] = {"128k","256k","512k","1m"};
        const char *p = sizes[0];
        switch (context.size)
        {
        case l2_size_128k:
            p = sizes[0];
            break;
        case l2_size_256k:
            p = sizes[1];
            break;
        case l2_size_512k:
            p = sizes[2];
            break;
        case l2_size_1m:
            p = sizes[3];
            break;
        }
        command_print(CMD, "PNCR: %2" PRIu32 , context.pncr&0xff);
        command_print(CMD, "VerNo: %3" PRIu32 " RevID: %2" PRIu32, (context.rev_id>>8)&0xfff, context.rev_id&0xff);
        command_print(CMD, "MasterID: %2" PRIu32 " TSnoop: %" PRIu32 " PlbClkRation: %" PRIu32 " Size: %s (%" PRIu32 " sets)",
                (context.cfg0>>12)&0x1f, (context.cfg0>>8)&0x7, (context.cfg0>>4)&0x3 , p, 1<<context.tag_n);
        ret |= l2_restore_context(&context);
    }else{
        LOG_ERROR("init context failed");
    }
    return ret | flush_registers(target);
}

COMMAND_HANDLER(ppc475fp_cache_l2_reg_command){
    struct target *target = get_current_target(CMD_CTX);
    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    int ret = ERROR_OK;
    if ( (CMD_ARGC == 0) || (CMD_ARGC > 2) ){
        return ERROR_COMMAND_SYNTAX_ERROR;
    }
    uint32_t reg;
    uint32_t data;
    reg = decode_l2_reg(CMD_ARGV[0]);
    if ( reg == L2C_L2BAD_REG ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], reg);
    }
    struct l2_context context;
    ret = l2_init_context(target,&context,tmp_reg_addr,tmp_reg_data,
            tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr);
    if (ret==ERROR_OK){
        if ( CMD_ARGC == 2){
            COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);
            ret = l2_write_u32(&context, reg, data);
            if ( ret != ERROR_OK ){
                LOG_ERROR("Can't write");
            }
        }else{
            ret = l2_read_u32(&context, reg, &data);
            if ( ret != ERROR_OK ){
                LOG_ERROR("Can't read");
            }else{
                command_print(CMD, "0x%08" PRIx32, data);
            }
        }
        ret |= l2_restore_context(&context);
    }else{
        LOG_ERROR("init context failed");
    }
    return ret | flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_cache_l2_read_command){
    struct target *target = get_current_target(CMD_CTX);
    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }
    uint32_t set;
    uint32_t way;
    int ret = ERROR_OK;
    if ( CMD_ARGC != 2 ){
        return ERROR_COMMAND_SYNTAX_ERROR;
    } else {
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], set);
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], way);
    }
    if ( way > 3 ){
        LOG_ERROR("Way too big");
        return ERROR_COMMAND_ARGUMENT_OVERFLOW;
    }
    struct l2_context context;
    ret = l2_init_context(target,&context,tmp_reg_addr,tmp_reg_data,
            tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr,tmp_reg_addr);
    if (ret==ERROR_OK){
        if ( set < (1u<<context.tag_n) ){
            struct l2_line line;
            uint32_t lru_info;
            ret = l2_read_lru(&context, set, &lru_info);
            if ( ret != ERROR_OK ){
                LOG_ERROR("Can't read LRU from set %i", set);
                return ret;
            }
            cache_l2_print_lru ( cmd, set, lru_info );
            ret = l2_read_line(&context,set,way,1,1,0,0,&line);
            if (ret != ERROR_OK){
                LOG_ERROR("Can't read tag from set %i way %i", set, way);
            }else{
                cache_l2_print_line(cmd,&line,way,1);
            }
        }else{
            LOG_ERROR("Set too big");
            ret = ERROR_COMMAND_ARGUMENT_OVERFLOW;
        }
        ret |= l2_restore_context(&context);
    }else{
        LOG_ERROR("init context failed");
    }
    return ret | flush_registers(target);
}

COMMAND_HANDLER(ppc476fp_tb_command) {
    if (CMD_ARGC > 1)
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint64_t tb;
    uint32_t tbl;
    uint32_t tbu;
    struct target *target = get_current_target(CMD_CTX);

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    int ret = ERROR_OK;

    if ( CMD_ARGC == 1 ){
        ret = parse_u64(CMD_ARGV[0], &tb);
        if (ret != ERROR_OK) {
            return ret;
        }
        tbu = tb>>32;
        tbl = tb &0xffffffff;
        ret = write_spr_u32(target,SPR_REG_NUM_TBL_W,tbl);
        if (ret != ERROR_OK)
            return ret;
        ret = write_spr_u32(target,SPR_REG_NUM_TBU_W,tbu);
        if (ret != ERROR_OK)
            return ret;
    }else{
        ret = read_spr_u32(target, SPR_REG_NUM_TBU_R, &tbu);
        if (ret != ERROR_OK)
            return ret;
        ret = read_spr_u32(target, SPR_REG_NUM_TBL_R, &tbl);
        if (ret != ERROR_OK)
            return ret;
        tb = tbu;
        tb <<= 32;
        tb |= tbl;
        command_print(CMD, "%" PRIu64 , tb);
    }


    return flush_registers(target);
}

COMMAND_HANDLER(dcr_command) {
    if ( (CMD_ARGC == 0) || (CMD_ARGC > 2) )
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t addr;
    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);
    int ret;

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);

    if ( CMD_ARGC == 2 ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);
        ret = write_DCR(target, addr, data );
        if (ret != ERROR_OK) {
            return ret;
        }
    }else{
        ret = read_DCR(target, addr, &data);
        if (ret != ERROR_OK) {
            return ret;
        }
        command_print_sameline(CMD, "0x%08" PRIx32 , data);
    }

    return flush_registers(target);
}

COMMAND_HANDLER(spr_command) {
    if ( (CMD_ARGC == 0) || (CMD_ARGC > 2) )
        return ERROR_COMMAND_SYNTAX_ERROR;

    uint32_t data;
    struct target *target = get_current_target(CMD_CTX);
    int ret;

    if ( target->state != TARGET_HALTED ){
        LOG_ERROR("Target not halted");
        return ERROR_TARGET_NOT_HALTED;
    }

    uint32_t addr = decode_spr(CMD_ARGV[0]);
    if ( addr == 0xffffffff ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], addr);
    }

    if ( CMD_ARGC == 2 ){
        COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], data);
        ret = write_spr_u32(target, addr, data );
        if (ret != ERROR_OK) {
            return ret;
        }
    }else{
        ret = read_spr_u32(target, addr, &data);
        if (ret != ERROR_OK) {
            return ret;
        }
        command_print_sameline(CMD, "0x%08" PRIx32 , data);
    }

    return flush_registers(target);
}

static const struct command_registration ppc476fp_tlb_drop_command_handlers[] =
    {{.name = "all",
      .handler = ppc476fp_handle_tlb_drop_all_command,
      .mode = COMMAND_EXEC,
      .usage = "",
      .help = "delete all UTLB records"},
     {.name = "shadow",
      .handler = ppc476fp_handle_tlb_drop_shadow_command,
      .mode = COMMAND_EXEC,
      .usage = "",
      .help = "delete shadow tlb entryes"},
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
    ppc476fp_use_resident_exec_command_handlers[] = {
        {.name = "on",
         .handler = ppc476fp_handle_use_resident_on_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "enable using resident in openocd"},
        {.name = "off",
         .handler = ppc476fp_handle_use_resident_off_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "disable using resident in openocd"},
        {.name = "get",
         .handler = ppc476fp_handle_use_resident_get_command,
         .mode = COMMAND_EXEC,
         .usage = "",
         .help = "using resident in openocd enabled?"},
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
    {.name = "dcbz",
    .handler = ppc476fp_code_dcbz_command,
    .mode = COMMAND_EXEC,
    .usage = "<addr>",
    .help = "Data Cache Block Zero"},
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

static const struct command_registration ppc475fp_cache_l2_write_exec_command_handlers[] = {
    {.name = "lru",
    .handler = ppc476fp_cache_l2_write_lru_command,
    .mode = COMMAND_EXEC,
    .usage = "<set> <data32>",
    .help = "Write into l2c lru array"},
    {.name = "tag",
    .handler = ppc476fp_cache_l2_write_tag_command,
    .mode = COMMAND_EXEC,
    .usage = "<set> <way> <data32> [<ecc>]",
    .help = "Write into l2c tag array"},
    {.name = "data",
    .handler = ppc476fp_cache_l2_write_data_command,
    .mode = COMMAND_EXEC,
    .usage = "<set> <way> <shift_in_uint64_t> <data32h> <data32l> [<ecc>]",
    .help = "Write into l2c data array"},
    COMMAND_REGISTRATION_DONE};

static const struct command_registration ppc475fp_cache_l2_exec_command_handlers[] = {
    {.name = "read",
    .mode = COMMAND_EXEC,
    .usage = "<set> <way>",
    .handler = ppc476fp_cache_l2_read_command,
    .help = "Print l2c line"},
    {.name = "write",
    .mode = COMMAND_EXEC,
    .usage = "",
    .chain = ppc475fp_cache_l2_write_exec_command_handlers,
    .help = "Write into l2c arrays"},
    {.name = "info",
    .mode = COMMAND_EXEC,
    .usage = "",
    .handler = ppc475fp_cache_l2_info_command,
    .help = "Print cache info"},
    {.name = "reg",
    .mode = COMMAND_EXEC,
    .usage = "<num> [value]",
    .handler = ppc475fp_cache_l2_reg_command,
    .help = "Access to l2c regs"},
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
    .usage = "[ecc] [invalid] [addr=addr1 [addr=addr2 [.. addr=addr32]]]",
    .chain = ppc475fp_cache_l2_exec_command_handlers,
    .help = "Dump l2 entryes"},
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
    {.name = "use_resident",
     .chain = ppc476fp_use_resident_exec_command_handlers,
     .mode = COMMAND_EXEC,
     .usage = "",
     .help = "use or not fp regs in openocd"},
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
    {.name= "tb",
     .handler = ppc476fp_tb_command,
     .usage = "[new_value]",
     .help = "read or write TBU/TBL register pare"},
    COMMAND_REGISTRATION_DONE};

const struct command_registration ppc476fp_command_handlers[] = {
    {.name = "ppc476fp",
     .mode = COMMAND_ANY,
     .help = "ppc476fp command group",
     .usage = "",
     .chain = ppc476fp_exec_command_handlers},
    {.name = "dcr",
     .mode = COMMAND_EXEC,
     .handler = dcr_command,
     .help = "read/write dcr registers",
     .usage = "<num> [value]"},
    {.name = "spr",
     .mode = COMMAND_EXEC,
     .handler = spr_command,
     .help = "read/write dcr registers",
     .usage = "<num> [value]"},
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
    .target_jim_configure = ppc476fp_jim_configure,

    .virt2phys = ppc476fp_virt2phys,
    .read_phys_memory = ppc476fp_read_phys_memory,
    .write_phys_memory = ppc476fp_write_phys_memory,
    .mmu = ppc476fp_mmu};
