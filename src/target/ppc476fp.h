#ifndef __PPC_476FP_H__
#define __PPC_476FP_H__

#include <helper/bits.h>
#include <helper/time_support.h>
#include <jtag/jtag.h>
#include <target/breakpoints.h>
#include <target/register.h>
#include <target/target.h>
#include <target/target_type.h>

/**
 * \defgroup ppc476 PowerPC 476fp
 * Эта группа создана специально для описания функций в файле ppc476fp.c
 * @{
 */

enum JDSR_bits{
    JDSR_MCSR1DWE_MASK = BIT(31-5),
    JDSR_UDE_MASK = BIT(31-6),
    JDSR_DE_MASK = BIT(31-7),
    JDSR_CSSR1DWE_MASK = BIT(31-8),
    JDSR_SSR1DWE_MASK = BIT(31-9),
    JDSR_MSRDWE_MASK = BIT(31-10),
    JDSR_ICB_MASK = BIT(31-11),
    JDSR_SFP_MASK = BIT(31-12),
    JDSR_SPP_MASK = BIT(31-13),
    JDSR_SUP_MASK = BIT(31-14),
    JDSR_FPU_MASK = BIT(31-15),
    JDSR_APU_MASK = BIT(31-16),
    JDSR_CCO_MASK = BIT(31-17),
    JDSR_ISE_MASK = BIT(31-18),
    JDSR_DTM_MASK = BIT(31-19),
    JDSR_ITM_MASK = BIT(31-20),
    JDSR_RMCE_MASK = BIT(31-21),
    JDSR_DSE_MASK = BIT(31-22),
    JDSR_AE_MASK = BIT(31-23),
    JDSR_PE_MASK = BIT(31-24),
    JDSR_SC_MASK = BIT(31-25),
    JDSR_RFI_MASK = BIT(31-26),
    JDSR_RCFI_MASK = BIT(31-27),
    JDSR_IMC_MASK = BIT(31-28),
    JDSR_ISO_MASK = BIT(31-30),
    JDSR_PSP_MASK = BIT(31-31),

    JDSR_SER_MASK = JDSR_FPU_MASK | JDSR_APU_MASK | JDSR_ISE_MASK
	    | JDSR_DTM_MASK | JDSR_ITM_MASK | JDSR_RMCE_MASK | JDSR_DSE_MASK
	    | JDSR_AE_MASK | JDSR_PE_MASK | JDSR_SC_MASK | JDSR_RFI_MASK
	    | JDSR_RCFI_MASK | JDSR_IMC_MASK | JDSR_PSP_MASK,

    JDSR_DWE_MASK = JDSR_CSSR1DWE_MASK | JDSR_SSR1DWE_MASK | JDSR_MSRDWE_MASK,
};

enum JDCR_bits{
    JDCR_STO_MASK = BIT(31 - 0),
    JDCR_BFL_MASK = BIT(31-1),
    JDCR_SS_MASK = BIT(31 - 2),
    JDCR_RESET_MASK = (3 << (31 - 4)), /* reset bits */
    JDCR_RESET_CORE = (1 << (31 - 4)), /* core reset */
    JDCR_RESET_CHIP = (2 << (31 - 4)), /* chip reset */
    JDCR_RESET_SYS = (3 << (31 - 4)),  /* system reset */
    JDCR_UDE_MASK = BIT(31-5),
    JDCR_FT_MASK = BIT(31-6),
    JDCR_DPO_MASK = BIT(31-7),
    JDCR_RSDBSR_MASK = BIT(31 - 8),
    JDCR_DWS_MASK = BIT(31-9),
};

enum SPR_REG_NUM {
    SPR_REG_NUM_LR = 8,
    SPR_REG_NUM_CTR = 9,
    SPR_REG_NUM_XER = 1,
    SPR_REG_NUM_PID = 48,
    SPR_REG_NUM_DBCR0 = 308,
    SPR_REG_NUM_DBCR1 = 309,
    SPR_REG_NUM_DBCR2 = 310,
    SPR_REG_NUM_DBSR = 304,
    SPR_REG_NUM_IAC_BASE = 312, /* IAC1..IAC4 */
    SPR_REG_NUM_DAC_BASE = 316, /* DAC1..DAC2 */
    SPR_REG_NUM_SSPCR = 830,
    SPR_REG_NUM_USPCR = 831,
    SPR_REG_NUM_ISPCR = 829,
    SPR_REG_NUM_MMUCR = 946,
    SPR_REG_NUM_MMUBE0 = 820,
    SPR_REG_NUM_MMUBE1 = 821,
    SPR_REG_NUM_DBDR = 1011,
    SPR_REG_NUM_DCRIPR = 891,
    SPR_REG_NUM_SRR0 = 26,
    SPR_REG_NUM_SRR1 = 27,
    SPR_REG_NUM_CSRR0 = 58,
    SPR_REG_NUM_CSRR1 = 59,
    SPR_REG_NUM_MCSRR0 = 570,
    SPR_REG_NUM_MCSRR1 = 571,
    SPR_REG_NUM_TBL_R = 268,
    SPR_REG_NUM_TBL_W = 284,
    SPR_REG_NUM_TBU_R = 269,
    SPR_REG_NUM_TBU_W = 285,
};

enum DCR_bits {
    DCRIPR_MASK = 0xfffffc00,
    DCR_LSB_MASK = 0x3ff,
    DCR_L2_BASE_ADDR = 0x80000600,
};

enum DBCR_bits {
    DBCR0_EDM_MASK = BIT(63 - 32),
    DBCR0_TRAP_MASK = BIT(63 - 39),
    DBCR0_IAC1_MASK = BIT(63 - 40),
    DBCR0_IACX_MASK = (0xF << (63 - 43)),
    DBCR0_DAC1R_MASK = BIT(63 - 44),
    DBCR0_DAC1W_MASK = BIT(63 - 45),
    DBCR0_DACX_MASK = (0xF << (63 - 47)),
    DBCR0_FT_MASK = BIT(63 - 63),
};

enum DBSR_bits{
    DBSR_IAC1_MASK = BIT(63 - 40),
    DBSR_IAC2_MASK = BIT(63 - 41),
    DBSR_IAC3_MASK = BIT(63 - 42),
    DBSR_IAC4_MASK = BIT(63 - 43),
    DBSR_DAC1R_MASK = BIT(63 - 44),
    DBSR_DAC1W_MASK = BIT(63 - 45),
    DBSR_DAC2R_MASK = BIT(63 - 46),
    DBSR_DAC2W_MASK = BIT(63 - 47),
    DBSR_TRAP_MASK = BIT(63-39),

    DBSR_IAC_ALL_MASK =
    (DBSR_IAC1_MASK | DBSR_IAC2_MASK | DBSR_IAC3_MASK | DBSR_IAC4_MASK),
    DBSR_DAC_ALL_MASK =
    (DBSR_DAC1R_MASK | DBSR_DAC1W_MASK | DBSR_DAC2R_MASK | DBSR_DAC2W_MASK),
};

enum MSR_bits{
    MSR_WE_MASK = BIT(63 - 45),
    MSR_CE_MASK = BIT(63 - 46),
    MSR_EE_MASK = BIT(63 - 48),
    MSR_PR_MASK = BIT(63 - 49),
    MSR_FP_MASK = BIT(63 - 50),
    MSR_ME_MASK = BIT(63 - 51),
    MSR_FE0_MASK = BIT(63 - 52),
    MSR_DWE_MASK = BIT(63 - 53),
    MSR_DE_MASK = BIT(63 - 54),
    MSR_FE1_MASK = BIT(63 - 55),
    MSR_IS_MASK = BIT(63 - 58),
    MSR_DS_MASK = BIT(63 - 59),
    MSR_PMM_MASK = BIT(63 - 61),
};

enum DCDBTRH{
    DCDBTRH_ADDR_MASK = 0xffffe000,
    DCDBTRH_VALID_MASK = 0x1000,
    DCDBTRH_TAGP_MASK = 0xffffe000,
    DCDBTRH_EXTADDR_MASK = 0x3ff,
};

static const uint32_t MMUCR_STID_MASK = (0xFFFF << 0);
enum reg_counts{
    ALL_REG_COUNT = 71,
    GDB_REG_COUNT = 71,
    GEN_CACHE_REG_COUNT = 38,
    FPU_CACHE_REG_COUNT = 33,
    GPR_REG_COUNT = 32,
    FPR_REG_COUNT = 32,
};

#define PHYS_MEM_MAGIC_PID 0xEFCDu
#define PHYS_MEM_BASE_ADDR 0x00000000u
#define PHYS_MEM_TLB_INDEX (PHYS_MEM_MAGIC_PID & 0xFF) /* if PHYS_MEM_BASE_ADDR == 0x00000000 */
#define PHYS_MEM_TLB_WAY 2
static const uint32_t PHYS_MEM_TLB_INDEX_WAY =
    ((PHYS_MEM_TLB_INDEX << 2) | PHYS_MEM_TLB_WAY);

#define ERROR_MEMORY_AT_STACK (-99)

#define HW_BP_NUMBER 4
#define WP_NUMBER 2

enum tlb_fields{
    TLB_NUMBER = 1024,
    TLB_0_EPN_BIT_POS = 12,
    TLB_0_EPN_BIT_LEN = 20,
    TLB_0_V_MASK = BIT(11),
    TLB_0_TS_MASK = BIT(10),
    TLB_0_DSIZ_BIT_POS = 4,
    TLB_0_DSIZ_BIT_LEN = 6,
    TLB_0_BLTD_MASK = BIT(3),

    TLB_1_RPN_BIT_POS = 12,
    TLB_1_RPN_BIT_LEN = 20,
    TLB_1_ERPN_BIT_POS = 0,
    TLB_1_ERPN_BIT_LEN = 10,

    TLB_2_IL1I_MASK = BIT(17),
    TLB_2_IL1D_MASK = BIT(16),
    TLB_2_U_BIT_POS = 12,
    TLB_2_U_BIT_LEN = 4,
    TLB_2_WIMG_BIT_POS = 8,
    TLB_2_WIMG_BIT_LEN = 4,
    TLB_2_EN_MASK = BIT(7),
    TLB_2_UXWR_BIT_POS = 3,
    TLB_2_UXWR_BIT_LEN = 3,
    TLB_2_SXWR_BIT_POS = 0,
    TLB_2_SXWR_BIT_LEN = 3,

    TLB_PARAMS_MASK_EPN = BIT(0),
    TLB_PARAMS_MASK_RPN = BIT(1),
    TLB_PARAMS_MASK_ERPN = BIT(2),
    TLB_PARAMS_MASK_TID = BIT(3),
    TLB_PARAMS_MASK_TS = BIT(4),
    TLB_PARAMS_MASK_DSIZ = BIT(5),
    TLB_PARAMS_MASK_WAY = BIT(6),
    TLB_PARAMS_MASK_IL1I = BIT(7),
    TLB_PARAMS_MASK_IL1D = BIT(8),
    TLB_PARAMS_MASK_U = BIT(9),
    TLB_PARAMS_MASK_WIMG = BIT(10),
    TLB_PARAMS_MASK_EN = BIT(11),
    TLB_PARAMS_MASK_UXWR = BIT(12),
    TLB_PARAMS_MASK_SXWR = BIT(13),
    TLB_PARAMS_MASK_BLTD = BIT(14),
};

enum reg_numbers {
    reg_sp = 1,
    tmp_reg_addr = 30,
    tmp_reg_data = 31,
};

enum memory_access_size {
    memory_access_size_byte = 1,
    memory_access_size_half_word = 2,
    memory_access_size_word = 4
};

enum dsiz {
    DSIZ_4K = 0x00,
    DSIZ_16K = 0x01,
    DSIZ_64K = 0x03,
    DSIZ_1M = 0x07,
    DSIZ_16M = 0x0F,
    DSIZ_256M = 0x1F,
    DSIZ_1G = 0x3F
};

// jtag instruction codes without core ids
enum jtag_instr {
    JTAG_INSTR_WRITE_JDCR_READ_JDSR = 0x28, /* 0b0101000 */
    JTAG_INSTR_WRITE_JISB_READ_JDSR = 0x38, /* 0b0111000 */
    JTAG_INSTR_WRITE_READ_DBDR = 0x58,      /* 0b1011000 */
    JTAG_INSTR_CORE_RELOAD = 0x78, /* 0b1111000, is used for preventing a JTAG
                                      bug with the core swintching */
    JTAG_INSTR_UNKNOW = 0
};

enum reg_action { reg_action_error, reg_action_flush, reg_action_ignore };
enum bltd{
    bltd0 = 0,
    bltd1 = 1,
    bltd2 = 2,
    bltd3 = 3,
    bltd4 = 4,
    bltd5 = 5,
    bltd_auto = 6,
    bltd_no = 7
};

struct tlb_hw_record {
    uint32_t
        data[3];   // if the 'valid' bit is zero, all other data are undefined
    uint32_t tid;  // if the 'valid' bit is zero, the field is undefined
    uint32_t bltd; // 6 for none bolted, 7 for auto
};

struct tlb_cached_record {
    bool loaded;
    struct tlb_hw_record hw;
};

struct tlb_sort_record {
    int index_way;
    struct tlb_hw_record hw;
};

struct tlb_command_params {
    unsigned mask; // TLB_PARAMS_MASK*
    uint32_t epn;
    uint32_t rpn;
    uint32_t erpn;
    uint32_t tid;
    uint32_t ts;
    uint32_t dsiz; // DSIZ*
    uint32_t way;       // -1 for 'auto'
    uint32_t il1i;
    uint32_t il1d;
    uint32_t u;
    uint32_t wimg;
    uint32_t en; // 0-BE, 1-LE
    uint32_t uxwr;
    uint32_t sxwr;
    uint32_t bltd; // 6 for 'no', 7 for 'auto'
};

struct ppc476fp_common {
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
    struct tlb_cached_record tlb_cache[TLB_NUMBER];
    bool use_fpu;
    enum target_endianness use_stack;
    uint32_t use_static_mem;
    enum target_endianness use_static_mem_endianness;
    bool memory_checked;
    uint32_t current_gpr_values[GPR_REG_COUNT];
    uint32_t current_gpr_values_valid[GPR_REG_COUNT];
    bool DWE;
};

struct ppc476fp_tap_ext {
    int last_coreid; // -1 if the last core id is unknown
};

// used for save/restore/setup pysh memory access
struct phys_mem_state {
    uint32_t saved_MSR;
    uint32_t saved_MMUCR;
    uint32_t saved_PID;
    uint32_t saved_USPCR;
};

/**
 * \defgroup local Не задействующие таргет
 * Функции внутри этой группы никак не задействуют таргет, только внутренние
 * ресурсы OpenOCD
 * @{
 */

/// @brief Получить поле из uint32_t
/// @param[in] value исходное слово
/// @param[in] pos положение младшего бита интересующего поля
/// @param[in] len длина поля
/// @return Значение искомого поля
static inline uint32_t get_bits_32(uint32_t value, unsigned pos, unsigned len);

/// @brief Получить значение регистра (из кэша)
/// @param[in] reg Указатель на регистр
/// @return значение регистра
static inline uint32_t get_reg_value_32(const struct reg *reg);

/// @brief Записать значение в регистр (в кэш)
/// @param[out] reg Указатель на целевой регистр
/// @param[in] value Целевое значение
static inline void set_reg_value_32(struct reg *reg, uint32_t value);

/// @brief Получить объект ppc476fp_common
/// @param[in] target Указатель на объект target
/// @return Указатель на @link ppc476fp_common ppc476fp_common @endlink
static inline struct ppc476fp_common *target_to_ppc476fp(struct target *target);

/// @brief Получить объект ppc476fp_tap_ext
/// @param[in] target Указатель на объект target
/// @return Указатель на @link ppc476fp_tap_ext ppc476fp_tap_ext @endlink
static inline struct ppc476fp_tap_ext *
target_to_ppc476fp_tap_ext(struct target *target);

/**
 * @brief Анализ JDSR
 * @param[in] JDSR Значение JDSR
 * @return ERROR_OK - успешно, иначе - ошибка
 * 
 * Анализирует биты JDSR SER на наличие исключений, выводит текстовое описание
 * ошибки и возвращает ошибку при наличии
*/
static int jdsr_log_ser(uint32_t JDSR);

/**
 * @brief Анализ JDSR на остановленность таргета
 * @param[in] jdsr Значение JDSR
 * @return true - таргет остановлен, false - не остановлен
*/
static bool is_halted(uint32_t jdsr);

/**
 * @brief Возвращает строку, в которую записан arch_state
 * @param[in] target Указатель на объект target
 * @param[out] st Указатель на буфер
 * @param[in] l максимальная длина буфера
*/
static void arch_state(struct target *target, char *st, size_t l);

/**
 * @}
 * \defgroup config Функции конфигурирования обмена
 * Некоторые из этих Функций имеют только локальное действие,
 * некоторые при определённых параметрах условиях могут инициировать обмен
 */

/// @brief Считать значение параметра use_fpu
/// @param[in] target Указатель на объект target
/// @return true - активен
/// @return false - не активен
static bool use_fpu_get(struct target *target);

/// @brief Включить use_fpu
/// @param[in] target Указатель на объект target
/// @warning Проверяет наличие use_stack и use_static_mem. Может быть включён
/// только когда включён use_stack, use_static_mem или оба
/// @return ERROR_OK - успешно, иначе - ошибка
static int use_fpu_on(struct target *target);

/**
 * @brief Выключить use_fpu
 * @param[in] target Указатель на объект target
 * @param[in] action Определяет как будет вести себя OpenOCD, если есть
 * регистры fpu, помеченные как dirty.
 * @return ERROR_OK - успешно, иначе - ошибка
 *
 *
 * reg_action_error - вернуть ошибку
 * reg_action_flush - отправить в таргет
 * reg_action_ignore - игнорировать и пометить чистыми
 */
static int use_fpu_off(struct target *target, enum reg_action action);

/// @brief Считать значение параметра use_stack
/// @param[in] target Указатель на объект target
/// @return true - активен
/// @return false - не активен
static bool use_stack_get(struct target *target);

/**
 * @brief Считать ендианность области стека
 * @param[in] target Указатель на объект target
 * @return тип ендианности
*/
static enum target_endianness use_stack_endianness(struct target *target);

/// @brief Включить use_stack
/// @param[in] target Указатель на объект target
/// @return ERROR_OK - успешно, иначе - ошибка
/// @warning Проверяет доступ к стеку при включении
/// @warning Может быть включен только когда таргет остановлен
static int use_stack_on(struct target *target);

/**
 * @brief Выключить use_stack
 * @param[in] target Указатель на объект target
 * @param[in] action Определяет как будет вести себя OpenOCD, если есть
 * ресурсы, помеченные как dirty и требующие работу памяти для сброса
 * на таргет, если static_mem так же выключен
 *
 *
 * reg_action_error - вернуть ошибку
 * reg_action_flush - отправить в таргет
 * reg_action_ignore - игнорировать и пометить чистыми
 * @return ERROR_OK - успешно, иначе - ошибка
 */
static int use_stack_off(struct target *target, enum reg_action action);

/// @brief Разрешено ли использование статической памяти?
/// @param[in] target Указатель на объект target
/// @return true - активен
/// @return false - не активен
static bool use_static_mem_get(struct target *target);

/**
 * @brief Считать ендианность области стека
 * @param[in] target Указатель на объект target
 * @return тип ендианности
*/
static enum target_endianness use_static_mem_endianness(struct target *target);

/**
 * @brief Получить адрес разрешённого участка статической памяти
 * @param[in] target Указатель на объект target
 * @result адрес
 */
static uint32_t use_static_mem_addr(struct target *target);

/// @brief Включить static_mem
/// @param[in] target Указатель на объект target
/// @param[in] base_addr Базовый адрес (эффективный) для внутренних задач
/// OpenOCD
/// @return ERROR_OK - успешно, иначе - ошибка
/// @warning Базовый адрес должен быть выровнен на 8, доступный размер не менее
/// 1024 байт
/// @warning Проверяет доступ к региону памяти при включении
/// @warning Может быть включен только когда таргет остановлен
static int use_static_mem_on(struct target *target, uint32_t base_addr);

/**
 * @brief Выключить static_mem
 * @param[in] target Указатель на объект target
 * @param[in] action Определяет как будет вести себя OpenOCD, если есть
 * ресурсы, помеченные как dirty и требующие работу памяти для сброса
 * на таргет, и use_stack так же выключен
 *
 *
 * reg_action_error - вернуть ошибку
 * reg_action_flush - отправить в таргет
 * reg_action_ignore - игнорировать и пометить чистыми
 * @return ERROR_OK - успешно, иначе - ошибка
 */
static int use_static_mem_off(struct target *target, enum reg_action action);

/**
 * @brief Инициализирует структуру reg, добавляет её в target->arch_info
 *
 * @param[in,out] target Указатель на объект target
 * @param[in] all_index Количетсво регистров, которые уже помещены в target
 * @param[out] reg Указатель на уже созданную структуру reg, которую нужно
 * инициализировать
 * @param[in] reg_name Отображаемое имя регистра
 * @param[in] reg_type Тип данных регистра
 * @param[in] bit_size Размер регистра в битах
 * @param[in] arch_type Указатель на структуру reg_arch_type, описывающий способ
 * доступа к регистру
 * @param[in] feature_name Имя группы регистров, используется для xml-описания
 */
static struct reg *fill_reg(struct target *target, int all_index,
                            struct reg *reg, const char *reg_name,
                            enum reg_type reg_type, int bit_size,
                            const struct reg_arch_type *arch_type,
                            const char *feature_name);

/**
 * @brief Создание кэша регистров
 *
 * @param[in,out] target Указатель на объект target
 * @warning Используется только при первичной инициализации
 */
static void build_reg_caches(struct target *target);

/**
 * @brief Помечает локальный кэш регистров как не валидный
 * @param[in] target Указатель на объект target
 *
 * @warning dirty регистры так же начинают считаться не валидными и их
 * значения полностью исчезают
 */
static void invalidate_regs_status(struct target *target);

/**
 * @brief Пометка локального кэша TLB как не валидного
 * @param[in] target Указатель на объект target
 */
static void invalidate_tlb_cache(struct target *target);

/**
 * @brief Сравнение 2 записей в кэше tlb
 * @param[in] p1 - левый аргумент сравнения
 * @param[in] p2 - правый аргумент сравнения
 * @result *p1 < *p2
 *
 * @warning p1 и p2 должны ссылаться на структуры tlb_sort_record
 */
static int compare_tlb_record(const void *p1, const void *p2);

/**
 * @brief Строковый размер по константе
 * @param[in] dsiz Размер в виде константы, как она передаётся в tlbwe
 * @result Размер в виде человекочитаемой строки
 */
static const char *dsiz_to_string(unsigned dsiz);

/**
 * @brief Печать заголовка таблицы tlb
 * @param[out] cmd Структура command_invocation, передаваемая из обработчика
 * команды
 *
 * Печатает заголовок к таблице, которая отображает состояние tlb
 */
static void print_tlb_table_header(struct command_invocation *cmd);

/**
 * @brief Печать отдельной записи в tlb
 * @param[out] cmd Структура command_invocation, передаваемая из обработчика
 * команды
 * @param[in] index_way Индекс записи. Считается как Set * 4 + way
 * @param[out] hw Структура, из которой читается информация о записи
 */
static void print_tlb_table_record(struct command_invocation *cmd,
                                   int index_way, struct tlb_hw_record *hw);

/**
 * @brief Разбор параметра, тип которого ожидается uint32_t
 * @param[in] param_mask Маска параметра. Нужна для определения, был ли
 * параметр установлен
 * @param[in] max_value Максимальное допустимое значение параметра
 * @param[in] param Текстовое представление параметра
 * @param[in,out] current_mask В этой переменной проверяется, что параметр
 * выставлен впервые, и выставляется в случае удачного разбора
 * @param[out] dest Результат разбора
 * @result ERROR_OK - успешно, иначе - код ошибки
 */
static inline int parse_uint32_params(unsigned param_mask, uint32_t max_value,
                                      const char *param, unsigned *current_mask,
                                      uint32_t *dest);

/**
 * @brief Разбор параметра размера tlb-страницы
 * @param[in] param_mask Маска параметра. Нужна для определения, был ли
 * параметр установлен
 * @param[in] param Текстовое представление параметра
 * @param[in,out] current_mask В этой переменной проверяется, что параметр
 * выставлен впервые, и выставляется в случае удачного разбора
 * @param[out] dest Результат разбора
 * @result ERROR_OK - успешно, иначе - код ошибки
 */
static inline int parse_dsiz_params(unsigned param_mask, const char *param,
                                    unsigned *current_mask, uint32_t *dest);

/**
 * @brief Разбор параметров в командах, связанных с tlb
 * @param[in] argc Количество параметров команды
 * @param[in] argv Массив указателей на строки параметров команды
 * @param[out] params Структура, в которую будет записан результат
 * @result ERROR_OK - успешно, иначе - код ошибки
 */
static int parse_tlb_command_params(unsigned argc, const char *argv[],
                                    struct tlb_command_params *params);

/**
 * @}
 * \defgroup JTAG Непосредственная работа с TAP-контроллером через JTAG
 *
 * @{
 */

/// @brief Чтение/запись регистров TAP-контроллера
/// @param[in] target Указатель на объект target
/// @param[in] instr_without_coreid код инструкции для IR_SCAN TAP-контроллера
/// ядра
/// @param[in] valid_bit Если true, то отправленное значение через DR_SCAN
/// защёлкнется в TAP-контроллере
/// @param[in] write_data Значение регистра для отправки
/// @param[out] read_data Буфер для входных данных. В буфер должно быть возможно
/// записать 32 бита, либо указатель NULL
/// @return ERROR_OK - успешно, иначе - код ошибки
static int jtag_read_write_register(struct target *target,
                                    uint32_t instr_without_coreid,
                                    bool valid_bit, uint32_t write_data,
                                    uint8_t *read_data);

/// @brief Чтение значения DBDR
/// @param[in] target Указатель на объект target
/// @param[out] data Указатель на буфер, куда записать результат
/// @return ERROR_OK - успешно, иначе - код ошибки
static int read_DBDR(struct target *target, uint8_t *data);

/// @brief Запись значения DBDR
/// @param[in] target Указатель на объект target
/// @param[in] data Значение для записи
/// @return ERROR_OK - успешно, иначе - код ошибки
static int write_DBDR(struct target *target, uint32_t data);

/// @brief Чтение значения JDSR
/// @param[in] target Указатель на объект target
/// @param[out] data Указатель на буфер, куда записать результат
/// @return ERROR_OK - успешно, иначе - код ошибки
static int read_JDSR(struct target *target, uint8_t *data);

/// @brief Запись значения в JDCR
/// @param[in] target Указатель на объект target
/// @param[in] data Значение для записи
/// @return ERROR_OK - успешно, иначе - код ошибки
static int write_JDCR(struct target *target, uint32_t data);

/// @brief Отправить код команды в конвеер
/// @param[in] target Указатель на объект target
/// @param[in] data Значение для записи
/// @return ERROR_OK - успешно, иначе - код ошибки
static int stuff_code(struct target *target, uint32_t code);

/**
 * @}
 * \defgroup REG_MEM Доступ к ресурсам таргета
 *
 * @warning Многие из этих функций, как побочные действия, меняют значения
 * регистров на таргете, оставляя их грязными.
 * @{
 */

/**
 * @brief Прочитать значение РОН из таргета
 * @param[in] target Указатель на объект target
 * @param[out] data Указатель на буфер, куда записать результат
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @warning значение в кэше OpenOCD остаётся неизменным, и регистр не помечается
 * грязным. Использует DBDR
 * В data записывается буфер, который может быть напрямую помещён в структуру
 * reg
 */
static int read_gpr_buf(struct target *target, int reg_num, uint8_t *data);

/**
 * @brief Прочитать значение РОН из таргета
 * @param[in] target Указатель на объект target
 * @param[out] data Указатель на буфер, куда записать результат
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @warning значение в кэше OpenOCD остаётся неизменным, и регистр не помечается
 * грязным. Использует DBDR
 * В data записывается число в порядке байт хоста
 */
static int read_gpr_u32(struct target *target, int reg_num, uint32_t *data);

/**
 * @brief Записать значение в РОН таргета
 * @param[in] target Указатель на объект target
 * @param[in] data Значение для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @warning значение в кэше OpenOCD остаётся неизменным и регистр помечается
 * грязным
 *
 * Не использует DBDR, записывает значение через инструкции lis, li и ori
 * Принимает на вход массив, прочитанный с помощью read_gpr_buf
 */
static int write_gpr_buf(struct target *target, int reg_num, const uint8_t *data);

/**
 * @brief Записать значение в РОН таргета
 * @param[in] target Указатель на объект target
 * @param[in] data Значение для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @warning значение в кэше OpenOCD остаётся неизменным и регистр помечается
 * грязным
 *
 * Не использует DBDR, записывает значение через инструкции lis, li и ori
 * Принимает на вход число
 */
static int write_gpr_u32(struct target *target, int reg_num, uint32_t data);

/**
 * @brief Обёртка над инструкциями lbz, lhz, lwz
 *
 * Выполняет чтение, используя указанные регистры, сдвиг и размер. Если buffer
 * не NULL, заполняет его значением rt после чтения
 *
 * @param[in] target Указатель на объект target
 * @param[in] rt Номер регистра rt, используемого для данных
 * @param[in] ra Номер регистра ra, используемого для адреса
 * @param[in] d Размер сдвига, относительно адреса в ra
 * @param[in] size Размер слова данных
 * @param[in] buffer Область, куда нужно положить данные из rt (может быть NULL)
*/
static int read_virt_mem_raw(struct target *target, uint32_t rt, uint32_t ra, int16_t d, enum memory_access_size size, uint8_t *buffer);

/**
 * @brief Обёртка над инструкциями stb, sth, stw
 *
 * Выполняет запись, используя указанные регистры, сдвиг и размер. Если buffer
 * не NULL, заполняет rt перед записью
 *
 * @param[in] target Указатель на объект target
 * @param[in] rt Номер регистра rt, используемого для данных
 * @param[in] ra Номер регистра ra, используемого для адреса
 * @param[in] d Размер сдвига, относительно адреса в ra
 * @param[in] size Размер слова данных
 * @param[in] buffer Данные, которые нужно положить в rt (может быть NULL)
*/
static int write_virt_mem_raw(struct target *target, uint32_t rt, uint32_t ra, int16_t d, enum memory_access_size size, const uint8_t *buffer);

/**
 * @brief Проверка работоспособности области стека
 *
 * Выполняет test_memory_at_addr, передавая в качестве адреса указатель стека-8
 *
 * @param[in] target Указатель на объект target
 * @param[out] endianness Определение порядка байт в области стека
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int test_memory_at_stack(struct target *target, enum target_endianness *endianness);

/**
 * @brief Проверка работоспособности области статической памяти
 *
 * Выполняет test_memory_at_addr, устанавливая адрес, переданный в
 * use_static_mem_on
 *
 * @param[in] target Указатель на объект target
 * @param[out] endianness Определение порядка байт в области стека
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int test_memory_at_static_mem(struct target *target, enum target_endianness *endianness);

/**
 * @brief Проверяет работоспособности произвольного адреса памяти
 *
 * Выполняет 2 записи эталонов по 4 байта по указанному адресу,
 * (всего 8 байт), после чего считывает и сверяет с эталоном. После
 * этого считывает ещё один байт для определения ендианности области
 * памяти.
 *
 * @warning Адрес должен быть выровнен на 8
 * @warning Функция не заносит адрес в ra, это нужно сделать до вызова
 *
 * @param[in] target Указатель на объект target
 * @param[in] ra Базовый регистр адреса
 * @param[in] shift Смещение начала области относительно бащового адреса
 * @param[out] endianness Определение порядка байт в области стека
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int test_memory_at_addr(struct target *target, uint32_t ra, int16_t shift, enum target_endianness *endianness);

/**
 * @brief Чтение  регистра SPR
 *
 * @param[in] target Указатель на объект target
 * @param[in] spr_num Номер регистра
 * @param[out] data Буфер для результата
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int read_spr_buf(struct target *target, int spr_num, uint8_t *data);

/**
 * @brief Чтение  регистра SPR
 *
 * @param[in] target Указатель на объект target
 * @param[in] spr_num Номер регистра
 * @param[out] data Буфер для результата
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int read_spr_u32(struct target *target, int spr_num, uint32_t *data);

/**
 * @brief Запись  регистра SPR
 *
 * @param[in] target Указатель на объект target
 * @param[in] spr_num Номер регистра
 * @param[in] data Данные для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int write_spr_buf(struct target *target, int spr_num, const uint8_t* data);

/**
 * @brief Запись  регистра SPR
 *
 * @param[in] target Указатель на объект target
 * @param[in] spr_num Номер регистра
 * @param[in] data Данные для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int write_spr_u32(struct target *target, int spr_num, uint32_t data);

/**
 * @brief Прочитать значение регистра fpu из таргета
 *
 * @param[in] target Указатель на объект target
 * @param[in] reg_num Номер регистра
 * @param[out] value Буфер для результата
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @warning значение в кэше OpenOCD остаётся неизменным, и регистр не помечается
 * грязным. Использует DBDR и память
 */
static int read_fpr_reg(struct target *target, int reg_num, uint64_t *value);

/**
 * @brief Записать значение регистра fpu в таргет
 *
 * @param[in] target Указатель на объект target
 * @param[in] reg_num Номер регистра
 * @param[in] value Значение для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @warning значение в кэше OpenOCD остаётся неизменным, и регистр помечается
 * грязным. Использует память, не использует DBDR
 */
static int write_fpr_reg(struct target *target, int reg_num, uint64_t value);

/***
 * @brief Запись регистра DBCR0
 *
 * Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual 8.5.1 с. 235
 *
 * @param[in] target Указатель на объект target
 * @param[in] data Значение для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @warning Обновляет кэш OpenOCD
 */
static int write_DBCR0(struct target *target, uint32_t data);

/**
 * @brief Чтение MSR
 *
 * Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual 7.4.1 с. 173
 *
 * @param[in] target Указатель на объект target
 * @param[out] data Буфер для результата
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int read_MSR_u32(struct target *target, uint32_t *data);

/**
 * @brief Чтение MSR
 *
 * Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual 7.4.1 с. 173
 *
 * @param[in] target Указатель на объект target
 * @param[out] data Буфер для результата
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int read_MSR_buf(struct target *target, uint8_t *data);

/**
 * @brief Запись MSR
 *
 * Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual 7.4.1 с. 173
 *
 * @param[in] target Указатель на объект target
 * @param[in] data Значение для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int write_MSR_buf(struct target *target, const uint8_t *data);

/**
 * @brief Запись MSR
 *
 * Подробнее: PowerPC 476FP Embedded Processor Core User’s Manual 7.4.1 с. 173
 *
 * @param[in] target Указатель на объект target
 * @param[in] data Значение для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int write_MSR_u32(struct target *target, uint32_t data);

/**
 * @brief Чтение DCR
 *
 * DCR - регистры управление периферией, их описание смотреть в описании
 * соответствующей СНК или ПЛИС
 *
 * @param[in] target Указатель на объект target
 * @param[out] value Буфер для результата
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int read_DCR(struct target *target, uint32_t addr, uint32_t *value);

/**
 * @brief Запись DCR
 *
 * DCR - регистры управление периферией, их описание смотреть в описании
 * соответствующей СНК или ПЛИС
 *
 * @param[in] target Указатель на объект target
 * @param[in] value Значение для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int write_DCR(struct target *target, uint32_t addr, uint32_t value);

/**
 * @brief Считывание всех основных регистров ядра
 *
 * Считываются R0-R31, LR, CTR, XER, MSR, CR, PC
 *
 * По факту, актуализирует кэш регистров OpenOCD
 *
 * После остановки может вызываться несколько раз, каждый раз считывает
 * только те регистры, которые помечены как не валидные
 *
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int read_required_gen_regs(struct target *target);

/**
 * @brief Сброс кэша основных регистров ядра
 *
 * Записываются только грязные (dirty) регистры из следующего набора:
 * R0-R31, LR, CTR, XER, MSR, CR, PC
 *
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int write_dirty_gen_regs(struct target *target);

/**
 * @brief Чтение регистров FPU
 *
 * Считываются F0-F31, FPSCR
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int read_required_fpu_regs(struct target *target);

/**
 * @brief Сброс кэша регистров FPU
 *
 * Записываются только грязные (dirty) регистры из следующего набора:
 * F0-F31, FPSCR
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int write_dirty_fpu_regs(struct target *target);

/**
 * @brief Установка аппаратной точки останова
 * @param[in] target Указатель на объект target
 * @param[in,out] bp метаинформация о точке останова, созданная OpenOCD
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Непосредственно записывает информацию о точке останова в регистры таргета.
 */
static int set_hw_breakpoint(struct target *target, struct breakpoint *bp);

/**
 * @brief Снятие ранее установленной аппаратной точки останова
 * @param[in] target Указатель на объект target
 * @param[in,out] bp метаинформация о точке останова, созданная OpenOCD
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Снимает флаг валидности из DBCR0 таргета
 */
static int unset_hw_breakpoint(struct target *target, struct breakpoint *bp);

/**
 * @brief Установка программной точки останова
 * @param[in] target Указатель на объект target
 * @param[in,out] bp метаинформация о точке останова, созданная OpenOCD
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Подменяет указанную инструкцию на trap
 */
static int set_soft_breakpoint(struct target *target, struct breakpoint *bp);

/**
 * @brief Проверяет, возможно ли добавить ещё одну аппаратную точку останова
 * @param[in] target Указатель на объект target
 * @param[in,out] breakpoint метаинформация о точке останова, созданная OpenOCD
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int check_add_hw_breakpoint(struct target *target,
                                   struct breakpoint *breakpoint);

/**
 * @brief Снятие программной точки останова
 * @param[in] target Указатель на объект target
 * @param[in,out] bp метаинформация о точке останова, созданная OpenOCD
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Восстанавливат ранее установленный trap изначальной командой
 */
static int unset_soft_breakpoint(struct target *target, struct breakpoint *bp);

/**
 * @brief Снятие всех программных точек останова
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Снимает все программные точки останова. В случае ошибки выдаёт предупреждение
 * и перехдит к следующей, а не завершает работу.
 */
static int unset_all_soft_breakpoints(struct target *target);

/**
 * @brief Пометка аппаратных точек останова как не установленных
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static void invalidate_hw_breakpoints(struct target *target);

/**
 * @brief Установка всех точек останова
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Устанавливат все точки останова, как программные, так и аппаратные.
 * Используется перед восстановлением исполнения.
 */
static int enable_breakpoints(struct target *target);

/**
 * @brief Установка точки останова по совпадению адреса данных
 * @param[in] target Указатель на объект target
 * @param[in,out] wp метаинформация о точке останова, созданная OpenOCD
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int set_watchpoint(struct target *target, struct watchpoint *wp);

/**
 * @brief Снятие точки останова по совпадению адреса данных
 * @param[in] target Указатель на объект target
 * @param[in,out] wp метаинформация о точке останова, созданная OpenOCD
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int unset_watchpoint(struct target *target, struct watchpoint *wp);

/**
 * @brief Установка ранее созданных точек останова по совпадению адреса данных
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int enable_watchpoints(struct target *target);

/**
 * @brief Пометка всех точек останова по совпадению адреса данных как не
 * установленных
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Используется при инициализации отладочного режима
 */
static void invalidate_watchpoints(struct target *target);

/**
 * @brief Сохранение контекста после остановки процессора
 * @param[in] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @warning процессор обязан быть остановлен
 *
 * Помечает весь кэш OpenOCD как не валидный и сохраняет регистры в кэш OpenOCD
 */
static int save_state(struct target *target);

/**
 * @brief Инвалидация l1 кэша инструкций
 * @param[in] target Указатель на объект target
 * @param[in] addr Адрес начала изменённого региона
 * @param[in] len Размер изменённого региона
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Последовательность isinc, msync, ici, dci 0, isync, msync.
 *
 * Используется для обеспечения когерентности L1I и L2.
 * Кэш L1D является Write-through, тем самым первый msync гарантирут окончание
 * операции записи в L2. Далее выполняется сброс всего кэша L1I,
 * тем самым убираются все данные в L1I, которые могут отличаться от L2.
 * Необходимо для работы модифицируемого кода, в том числе точек останова.
 */
static int cache_l1i_invalidate(struct target *target, uint32_t addr, uint32_t len);

/**
 * @brief Подготовка таргета к запуску
 * @param[in] target Указатель на объект target
 * @param[in] handle_breakpoints Если 0 - запуск без точек останова,
 * 		если !=0 - запуск с точками останова
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Запись на таргет регастров запись основных и FPU регистров в таргет,
 * активация точек останова, инвалидация L1I.
 */
static int restore_state(struct target *target, int handle_breakpoints);

/**
 * @brief Восстановление контекста перед запуском
 * @param[in,out] target Указатель на объект target
 * @param[in] current Если 1 - старт с текущего места, иначе - с address
 * @param[in] address Указание адреса старта
 * @param[in] handle_breakpoints Если 0 - запуск без точек останова,
 * 		если !=0 - запуск с точками останова
 * @param[in] debug_reason Информация и причине возобновления исполнения
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int restore_state_before_run(struct target *target, int current,
                                    target_addr_t address, int handle_breakpoints,
                                    enum target_debug_reason debug_reason);

/**
 * @brief Инициализация отладки
 * @param[in,out] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Выполняет кэширование регистров и устанавливает значения DBCR0, DBCR1, DBCR2
 * в состояние DBCR0_EDM_MASK | DBCR0_TRAP_MASK | DBCR0_FT_MASK, 0, 0; после
 * чего вызваеет функции invalidate_hw_breakpoint и invalidate_watchpoints
 */
static int save_state_and_init_debug(struct target *target);

/**
 * @brief Остановить процессор
 * @param[in,out] target Указатель на объект таргет
 * @param[in] count Количество попыток опроса в процессе ожиданя останова
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Отправляет команду на останов процессора, после чего читает состояние, ожидая
 * флаг о остановке процессора. Если не дожидается, возвращает ошибку
*/
static int halt_and_wait(struct target *target, int count);

/**
 * @brief Сброс и остановка процессора
 * @param[in,out] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Выполняет chip reset, устанавливая при этом бит STO. В теории, должен
 * сбросить процессор и остановить его на первой инструкции.
 */
static int reset_and_halt(struct target *target);

/**
 * @brief Внутренняя функция проверки таргета
 * @param[in,out] target Указатель на объект target
 * @retur ERROR_OK - успешно, иначе - код ошибки
 */
static int examine_internal(struct target *target);

/**
 * @brief Непосредственно запрос записи из tlb
 * @param[in] target Указатель на объект target
 * @param[in] index_way Индекс записи. Считается как Set * 4 + way
 * @param[out] hw Структура, в которую будет записан результат
 * @return ERROR_OK - успешно, иначе - ошибка
 */
static int load_tlb(struct target *target, int index_way,
                    struct tlb_hw_record *hw);

/**
 * @brief Непосредственная запись в tlb
 * @param[in] target Указатель на объект target
 * @param[in] index_way Индекс записи. Считается как Set * 4 + way
 * @param[in] hw Структура, из которой будет считаны параметры для записи
 * @return ERROR_OK - успешно, иначе - ошибка
 */
static int write_tlb(struct target *target, int index_way,
                     struct tlb_hw_record *hw);

/**
 * @brief Чтение строки из tlb, если её нет в кэше
 * @param[in,out] target Указатель на объект target
 * @param[in] index_way Индекс записи. Считается как Set * 4 + way
 * @return ERROR_OK - успешно, иначе - ошибка
 *
 * @warning загрузка происходит в таблицу, которая находится в target
 */
static int load_uncached_tlb(struct target *target, int index_way);

/**
 * @brief Инициализация доступа к памяти по физическому адресу
 * @param[in,out] target Указатель на объект target
 * @param[out] state Указатель на структуру, в которой хранится контекст
 * @return ERROR_OK - успешно, иначе - ошибка
 *
 * Сохраняет регистровый контекст, который будет испорчен для организации
 * доступа, после чего настраивает доступ.
 *
 * Т.к. во время работы доступа по физическим адресам остальная TLB нас не
 * интересует, функция сохраняет строго конкретную запись, которую
 * перезаписывает. Ненулевой way гарантирует, что запись не была bolted.
 * Позже, эта запись восстановится в неизменном виде в функции
 * restore_phys_mem
 *
 * @warning Реализация от Астрософта выставляет problem state, после чего
 * начинает активно обращаться к привиллигированным регистрам. Понятия не имею
 * почему оно хоть как-то работает, но, подозреваю, просто не ловит ошибку.
 */
static int init_phys_mem(struct target *target, struct phys_mem_state *state);

/**
 * @brief Восстановление контекста, который был испорчен в init_phys_mem
 * @param[in,out] target Указатель на объект target
 * @param[out] state Указатель на структуру, в которой хранится контекст
 * @return ERROR_OK - успешно, иначе - ошибка
 */
static int restore_phys_mem(struct target *target,
                            struct phys_mem_state *state);

/**
 * @brief Создание конкретной страницы в TLB
 * @param[in,out] target Указатель на объект target
 * @param[in] new_ERPN_RPN Номер страницы в физической памяти
 *
 * Т.к. физический адрес больше эффективного, для обеспечения доступа к
 * произвольному адресу может потребоваться несколько раз перенастраивать TLB.
 * Эта функция создаёт запись для "текущего окна" физических адресов.
 */
static int access_phys_mem(struct target *target, uint32_t new_ERPN_RPN);

/**
 * @brief Запись всех dirty регистров в память
 * @param[in] target Указатель на объект target
 * 
 * @warning Должна вызываться в конце каждой интерфейсной функции
*/
static int flush_registers(struct target* target);

/**
 * @}
 * @defgroup openocd_interfaces Интерфейсные функции OpenOCD
 *
 * Эти функции вызываются непосредственно из ядра OpenOCD, всё остальное -
 * обеспечение работы этих функций
 */

/**
 * @brief Чтение указанного регистра
 * @param[in,out] reg Указатель на регистр, который требуется прочитать
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Подразумевается, что при её вызове функция всегда выполняет чтение из
 * таргета, даже если регистр считался валидным.
 */
static int ppc476fp_get_gen_reg(struct reg *reg);

/**
 * @brief Запись указанного регистра
 * @param[in,out] reg Указатель на регистр, который требуется записать
 * @param[out] buf Буфер с новым значением
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Подразумевается, что побочные действия, которые оказывает запись этого
 * регистра, наступают сразу. Для РОН пишется только в кэш, потому что они
 * регулярно используются
 */
static int ppc476fp_set_gen_reg(struct reg *reg, uint8_t *buf);

/**
 * @brief Чтение MSR
 * @param[in,out] reg Указатель на регистр, который требуется прочитать
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Аналогично ppc476fp_get_gen_reg, но читиает MSR.
 */
static int ppc476fp_get_msr(struct reg *reg);

/**
 * @brief Запись MSR
 * @param[in,out] reg Указатель на регистр, который требуется записать
 * @param[out] buf Буфер с новым значением
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Записывает в MSR новое значение. Если меняется бит FP, выполняет действия
 * с регистрами FPU: инвалидирует либо актуализирует кэш регистров FPU.
 */
static int ppc476fp_set_msr(struct reg *reg, uint8_t *buf);
/**
 * @brief Чтение указанного регистра FPU
 * @param[in,out] reg Указатель на регистр, который требуется прочитать
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Аналогично ppc476fp_get_gen_reg, но для FPU
 */
static int ppc476fp_get_fpu_reg(struct reg *reg);

/**
 * @brief Запись указанного регистра FPU
 * @param[in,out] reg Указатель на регистр, который требуется прочитать
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Аналогично ppc476fp_set_gen_reg, но для FPU
 */
static int ppc476fp_set_fpu_reg(struct reg *reg, uint8_t *buf);

/**
 * @brief Опрос состояния таргета
 * @param[in,out] reg Указатель на регистр, который требуется прочитать
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Вызывается с некоторым интервалом всё время, пока не выполняются никакие
 * команды
 */
static int ppc476fp_poll(struct target *target);

/**
 * @brief Архитектурно-зависимое состояние
 * @param[in,out] reg Указатель на регистр, который требуется прочитать
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Вызывется только когда процессор в состоянии halt. Печатает состояние в
 * консоль.
 */
static int ppc476fp_arch_state(struct target *target);

/**
 * @brief Запрос на остановку процессора
 * @param[in,out] reg Указатель на регистр, который требуется прочитать
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Отправляет команду для остановки процессора, не дожидается результата.
 */
static int ppc476fp_halt(struct target *target);

/**
 * @brief Возобновление исполнения
 * @param[in,out] target Указатель на объект target
 * @param[in] current Если 1 - старт с текущего места, иначе - с address
 * @param[in] address Указание адреса старта
 * @param[in] handle_brealpoints Игнорируется, назначение в API не ясно
 * @param[in] debug_reason Информация и причине возобновления исполнения
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Восстанавливет контекст исполнения и отправляет команду на снятие halt
 */
static int ppc476fp_resume(struct target *target, int current,
                           target_addr_t address, int handle_breakpoints,
                           int debug_execution);

/**
 * @brief Выполнение одиночной инструкции
 * @param[in,out] target Указатель на объект target
 * @param[in] current Если 1 - старт с текущего места, иначе - с address
 * @param[in] address Указание адреса старта
 * @param[in] handle_brealpoints Игнорируется, назначение в API не ясно
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Восстанавливает контекст исполнения и отправляет команду single step
 */
static int ppc476fp_step(struct target *target, int current,
                         target_addr_t address, int handle_breakpoints);

/**
 * @brief Установить сигнал SRST
 * @param[in,out] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Из реализации для ARM стало понятно, что функция должна устанавливать SRST
 * в активное состояние. На PPC вывод SRST не предусмотрен на разъёме, потому
 * принято решение, чтобы эта функция делала RESET-HALT, а deassert_reset
 * уже отпускала halt при необходимости
 */
static int ppc476fp_assert_reset(struct target *target);

/**
 * @brief Снять сигнал SRST
 * @param[in,out] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Из реализации для ARM стало понятно, что функция должна устанавливать SRST
 * в активное состояние. На PPC вывод SRST не предусмотрен на разъёме, потому
 * принято решение, чтобы функция assert_reset делала RESET-HALT, а эта
 * уже отпускала halt при необходимости
 */
static int ppc476fp_deassert_reset(struct target *target);

/**
 * @brief Программный сброс
 * @param[in,out] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Реализация для ARM выполняет переход на стартовый адрес и восстанавливает
 * регистры. Переход на стартовый адрес не всегда допустим, потому как это
 * будет работать в принципе не очень понятно, но сделано именно так.
 */
static int ppc476fp_soft_reset_halt(struct target *target);

/**
 * @brief Возвращает название архитектуры
 * @param[in] target Указатель на объект target
 * @return Имя архитектуры
 *
 * Возвращает строку, которая в неизменном виде передаётся клиенту gdb для
 * определения архитектуры таргета
 */
static const char *ppc476fp_get_gdb_arch(struct target *target);

/**
 * @brief Список регистров, доступных для gdb
 * @param[in,out] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int ppc476fp_get_gdb_reg_list(struct target *target,
                                     struct reg **reg_list[],
                                     int *reg_list_size,
                                     enum target_register_class reg_class);

/**
 * @brief Чтение из области памяти
 * @param[in,out] target Указатель на объект target
 * @param[in] address Эффективный адрес начала области
 * @param[in] address Адрес в памяти таргета
 * @param[in] size Размер обращений (1,2,4 байт)
 * @param[in] count Количество последовательных обращений
 * @param[out] buffer Буфер, куда будут сложены данные
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int ppc476fp_read_memory(struct target *target, target_addr_t address,
                                uint32_t size, uint32_t count, uint8_t *buffer);

/**
 * @brief Запись в область памяти
 * @param[in,out] target Указатель на объект target
 * @param[in] address Эффективный адрес начала области
 * @param[in] size Размер обращений (1,2,4 байт)
 * @param[in] count Количество последовательных обращений
 * @param[in] buffer Буфер, где находятся данные для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int ppc476fp_write_memory(struct target *target, target_addr_t address,
                                 uint32_t size, uint32_t count,
                                 const uint8_t *buffer);

/**
 * @brief Расчёт контрольной суммы области памяти
 * @param[in,out] target Указатель на объект target
 * @param[in] address Адрес в памяти таргета
 * @param[in] count количество байт, от которых нужно посчитать контрольную
 * сумму
 * @param[out] checksum сюда будет помещён результат
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @todo По факту не реализована
 */
static int ppc476fp_checksum_memory(struct target *target,
                                    target_addr_t address, uint32_t count,
                                    uint32_t *checksum);

/**
 * @brief Добавление точки останова
 * @param[in,out] target Указатель на объект target
 * @param[in,out] breakpoint Метаинформация о точке останова
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Не выставляет реальную точку останова на таргете, а только проверяет, что
 * такая точка останова может быть выставлена.
 */
static int ppc476fp_add_breakpoint(struct target *target,
                                   struct breakpoint *breakpoint);

/**
 * @brief Удаление точки останова
 * @param[in,out] target Указатель на объект target
 * @param[in,out] breakpoint Метаинформация о точке останова
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Снимает точку останова, после чего ядро OpenOCD удаляет её из списка
 */
static int ppc476fp_remove_breakpoint(struct target *target,
                                      struct breakpoint *breakpoint);

/**
 * @brief Добавление точки останова по совпадению адреса данных
 * @param[in,out] target Указатель на объект target
 * @param[in,out] watchpoint Метаинформация о точке останова
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Не устанавливает точку останова, а только проверяет возможность её установки
 */
static int ppc476fp_add_watchpoint(struct target *target,
                                   struct watchpoint *watchpoint);

/**
 * @brief Удаление точки останова по совпадению адреса данных
 * @param[in,out] target Указатель на объект target
 * @param[in,out] watchpoint Метаинформация о точке останова
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * Снимает точку останова, после чего ядро OpenOCD удаляет её из списка
 */
static int ppc476fp_remove_watchpoint(struct target *target,
                                      struct watchpoint *watchpoint);

/**
 * @brief Выполняет выделение памяти для архитектурно-зависимой части
 * @param[in,out] target Указатель на объект target
 * @param[in] Jim_Interp Назначение не понятно, игнорируется
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 */
static int ppc476fp_target_create(struct target *target, Jim_Interp *interp);

/**
 * @brief Выполняет инициализацию объекта target
 * @param[in,out] cmd_ctx Контекст команды, игнорируется
 * @param[in,out] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int ppc476fp_init_target(struct command_context *cmd_ctx,
                                struct target *target);

/**
 * @brief Проверка таргета
 * @param[in,out] target Указатель на объект target
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int ppc476fp_examine(struct target *target);

/**
 * @brief Преобразование виртуального адреса в физический
 * @param[in,out] target Указатель на объект target
 * @param[in] address Виртуальный (эффективный?) адрес
 * @param[out] physical Физический адрес
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * @todo По факту, не реализована
 */
static int ppc476fp_virt2phys(struct target *target, target_addr_t address,
                              target_addr_t *physical);

/**
 * @brief Чтение чтение области памяти по указанному физическому адресу
 * @param[in,out] target Указатель на объект target
 * @param[in] address Физический адрес начала области
 * @param[in] size Размер обращений (1,2,4 байт)
 * @param[in] count Количество последовательных обращений
 * @param[in] buffer Буфер, где находятся данные для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 */
static int ppc476fp_read_phys_memory(struct target *target,
                                     target_addr_t address, uint32_t size,
                                     uint32_t count, uint8_t *buffer);

/**
 * @brief Запись в область памяти по указанному физическому адресу
 * @param[in,out] target Указатель на объект target
 * @param[in] address Физический адрес начала области
 * @param[in] size Размер обращений (1,2,4 байт)
 * @param[in] count Количество последовательных обращений
 * @param[in] buffer Буфер, где находятся данные для записи
 * @return ERROR_OK - успешно, иначе - код ошибки
 */
static int ppc476fp_write_phys_memory(struct target *target,
                                      target_addr_t address, uint32_t size,
                                      uint32_t count, const uint8_t *buffer);

/**
 * @brief Доступно ли MMU?
 * @param[out] target Указатель на объект target
 * @param[out] enabled Результат
 * @return ERROR_OK - успешно, иначе - код ошибки
 *
 * MMU неотключаем, потому оно всегда доступно.
 */
static int ppc476fp_mmu(struct target *target, int *enabled);

/**
 * @}
 */

#endif // __PPC_476FP_H____PPC_476FP_H__
