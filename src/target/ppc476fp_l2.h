#include "ppc476fp_stuffs.h"

#ifndef __PPC476FP_L2_H__
#define __PPC476FP_L2_H__

#include "ppc476fp.h"

enum L2C_L2REG {
    L2C_L2ISTAT = 0x000,
    L2C_L2PNCR = 0x004,
    L2C_L2REVID = 0x00C,
    L2C_L2CNFG0 = 0x010,
    L2C_L2CNFG1 = 0x014,
    L2C_L2DBGSEL = 0x020,
    L2C_L2DBGDATA0 = 0x024,
    L2C_L2DBGDATA1 = 0x028,
    L2C_L2SLEEPSTAT = 0x080,
    L2C_L2SLEEPREQ = 0x084,
    L2C_L2MCK = 0x120,
    L2C_L2MCKEN = 0x130,
    L2C_L2FERR = 0x140,
    L2C_L2INT = 0x150,
    L2C_L2INTEN = 0x160,
    L2C_L2LOG0 = 0x180,
    L2C_L2LOG1 = 0x184,
    L2C_L2LOG2 = 0x188,
    L2C_L2LOG3 = 0x18C,
    L2C_L2LOG4 = 0x190,
    L2C_L2LOG5 = 0x194,
    L2C_L2PLBCFG = 0x210,
    L2C_L2PLBDBG = 0x220,
    L2C_L2PLBERAP = 0x230,
    L2C_L2PLBSTAT0 = 0x300,
    L2C_L2PLBSTAT1 = 0x304,
    L2C_L2PLBFRC0 = 0x310,
    L2C_L2PLBFRC1 = 0x314,
    L2C_L2PLBMCKEN0 = 0x330,
    L2C_L2PLBMCKEN1 = 0x334,
    L2C_L2PLBFERR0 = 0x340,
    L2C_L2PLBFERR1 = 0x344,
    L2C_L2PLBINTEN0 = 0x360,
    L2C_L2PLBINTEN1 = 0x364,
    L2C_L2ARRCFG = 0x410,
    L2C_L2ARRDBG0 = 0x420,
    L2C_L2ARRDBG1 = 0x424,
    L2C_L2ARRDBG2 = 0x428,
    L2C_L2ARRDBG3 = 0x42C,
    L2C_L2ARRACCCTL = 0x480,
    L2C_L2ARRACCADR = 0x484,
    L2C_L2ARRACCDI0 = 0x490,
    L2C_L2ARRACCDI1 = 0x494,
    L2C_L2ARRACCDI2 = 0x498,
    L2C_L2ARRACCDO0 = 0x4A0,
    L2C_L2ARRACCDO1 = 0x4A4,
    L2C_L2ARRACCDO2 = 0x4A8,
    L2C_L2ARRSTAT0 = 0x500,
    L2C_L2ARRSTAT1 = 0x504,
    L2C_L2ARRSTAT2 = 0x508,
    L2C_L2ARRFRC0 = 0x510,
    L2C_L2ARRFRC1 = 0x514,
    L2C_L2ARRFRC2 = 0x518,
    L2C_L2ARRMCKEN0 = 0x530,
    L2C_L2ARRMCKEN1 = 0x534,
    L2C_L2ARRMCKEN2 = 0x538,
    L2C_L2ARRFERR0 = 0x540,
    L2C_L2ARRFERR1 = 0x544,
    L2C_L2ARRFERR2 = 0x548,
    L2C_L2ARRINTEN0 = 0x560,
    L2C_L2ARRINTEN1 = 0x564,
    L2C_L2ARRINTEN2 = 0x568,
    L2C_L2CPUCFG = 0x610,
    L2C_L2CPUDBG = 0x620,
    L2C_L2CPUSTAT = 0x700,
    L2C_L2CPUFRC = 0x710,
    L2C_L2CPUMCKEN = 0x730,
    L2C_L2CPUFERR = 0x740,
    L2C_L2CPUINTEN = 0x760,
    L2C_L2RACCFG = 0x810,
    L2C_L2RACDBG0 = 0x820,
    L2C_L2RACDBG1 = 0x824,
    L2C_L2RACSTAT0 = 0x900,
    L2C_L2RACFRC0 = 0x910,
    L2C_L2RACMCKEN0 = 0x930,
    L2C_L2RACFERR0 = 0x940,
    L2C_L2RACINTEN0 = 0x960,
    L2C_L2WACCFG = 0xC10,
    L2C_L2WACDBG0 = 0xC20,
    L2C_L2WACDBG1 = 0xC24,
    L2C_L2WACDBG2 = 0xC28,
    L2C_L2WACSTAT0 = 0xD00,
    L2C_L2WACSTAT1 = 0xD04,
    L2C_L2WACSTAT2 = 0xD08,
    L2C_L2WACFRC0 = 0xD10,
    L2C_L2WACFRC1 = 0xD14,
    L2C_L2WACFRC2 = 0xD18,
    L2C_L2WACMCKEN0 = 0xD30,
    L2C_L2WACMCKEN1 = 0xD34,
    L2C_L2WACMCKEN2 = 0xD38,
    L2C_L2WACFERR0 = 0xD40,
    L2C_L2WACFERR1 = 0xD44,
    L2C_L2WACFERR2 = 0xD48,
    L2C_L2WACINTEN0 = 0xD60,
    L2C_L2WACINTEN1 = 0xD64,
    L2C_L2WACINTEN2 = 0xD68,
    L2C_L2BAD_REG = 0xffff
};

uint32_t decode_l2_reg(const char *name){
#define REGNAME(x) if (strcmp(name,#x)==0){return L2C_##x;}
    REGNAME(L2ISTAT)
    REGNAME(L2PNCR)
    REGNAME(L2REVID)
    REGNAME(L2CNFG0)
    REGNAME(L2CNFG1)
    REGNAME(L2DBGSEL)
    REGNAME(L2DBGDATA0)
    REGNAME(L2DBGDATA1)
    REGNAME(L2SLEEPSTAT)
    REGNAME(L2SLEEPREQ)
    REGNAME(L2MCK)
    REGNAME(L2MCKEN)
    REGNAME(L2FERR)
    REGNAME(L2INT)
    REGNAME(L2INTEN)
    REGNAME(L2LOG0)
    REGNAME(L2LOG1)
    REGNAME(L2LOG2)
    REGNAME(L2LOG3)
    REGNAME(L2LOG4)
    REGNAME(L2LOG5)
    REGNAME(L2PLBCFG)
    REGNAME(L2PLBDBG)
    REGNAME(L2PLBERAP)
    REGNAME(L2PLBSTAT0)
    REGNAME(L2PLBSTAT1)
    REGNAME(L2PLBFRC0)
    REGNAME(L2PLBFRC1)
    REGNAME(L2PLBMCKEN0)
    REGNAME(L2PLBMCKEN1)
    REGNAME(L2PLBFERR0)
    REGNAME(L2PLBFERR1)
    REGNAME(L2PLBINTEN0)
    REGNAME(L2PLBINTEN1)
    REGNAME(L2ARRCFG)
    REGNAME(L2ARRDBG0)
    REGNAME(L2ARRDBG1)
    REGNAME(L2ARRDBG2)
    REGNAME(L2ARRDBG3)
    REGNAME(L2ARRACCCTL)
    REGNAME(L2ARRACCADR)
    REGNAME(L2ARRACCDI0)
    REGNAME(L2ARRACCDI1)
    REGNAME(L2ARRACCDI2)
    REGNAME(L2ARRACCDO0)
    REGNAME(L2ARRACCDO1)
    REGNAME(L2ARRACCDO2)
    REGNAME(L2ARRSTAT0)
    REGNAME(L2ARRSTAT1)
    REGNAME(L2ARRSTAT2)
    REGNAME(L2ARRFRC0)
    REGNAME(L2ARRFRC1)
    REGNAME(L2ARRFRC2)
    REGNAME(L2ARRMCKEN0)
    REGNAME(L2ARRMCKEN1)
    REGNAME(L2ARRMCKEN2)
    REGNAME(L2ARRFERR0)
    REGNAME(L2ARRFERR1)
    REGNAME(L2ARRFERR2)
    REGNAME(L2ARRINTEN0)
    REGNAME(L2ARRINTEN1)
    REGNAME(L2ARRINTEN2)
    REGNAME(L2CPUCFG)
    REGNAME(L2CPUDBG)
    REGNAME(L2CPUSTAT)
    REGNAME(L2CPUFRC)
    REGNAME(L2CPUMCKEN)
    REGNAME(L2CPUFERR)
    REGNAME(L2CPUINTEN)
    REGNAME(L2RACCFG)
    REGNAME(L2RACDBG0)
    REGNAME(L2RACDBG1)
    REGNAME(L2RACSTAT0)
    REGNAME(L2RACFRC0)
    REGNAME(L2RACMCKEN0)
    REGNAME(L2RACFERR0)
    REGNAME(L2RACINTEN0)
    REGNAME(L2WACCFG)
    REGNAME(L2WACDBG0)
    REGNAME(L2WACDBG1)
    REGNAME(L2WACDBG2)
    REGNAME(L2WACSTAT0)
    REGNAME(L2WACSTAT1)
    REGNAME(L2WACSTAT2)
    REGNAME(L2WACFRC0)
    REGNAME(L2WACFRC1)
    REGNAME(L2WACFRC2)
    REGNAME(L2WACMCKEN0)
    REGNAME(L2WACMCKEN1)
    REGNAME(L2WACMCKEN2)
    REGNAME(L2WACFERR0)
    REGNAME(L2WACFERR1)
    REGNAME(L2WACFERR2)
    REGNAME(L2WACINTEN0)
    REGNAME(L2WACINTEN1)
    REGNAME(L2WACINTEN2)
#undef REGNAME
    return L2C_L2BAD_REG;
}

enum l2_direct_dcr{
    L2CDCRAI = 0,
    L2CDCRDI = 4,
};

enum l2_size{
    l2_size_128k = 0x3,
    l2_size_256k = 0x0,
    l2_size_512k = 0x1,
    l2_size_1m = 0x2,
    l2_size_msk = 0x3
};

enum l2_cache_state{
    l2_cache_state_shift = 29,
    l2_cache_state_invalid = 0<<l2_cache_state_shift,
    l2_cache_state_undefined = 1<<l2_cache_state_shift,
    l2_cache_state_shared = 2<<l2_cache_state_shift,
    l2_cache_state_shared_last = 3<<l2_cache_state_shift,
    l2_cache_state_exclusive = 4<<l2_cache_state_shift,
    l2_cache_state_tagged = 5<<l2_cache_state_shift,
    l2_cache_state_modified = 6<<l2_cache_state_shift,
    l2_cache_state_modified_unsolicited = 7<<l2_cache_state_shift,
    l2_cache_state_mask = 7<<l2_cache_state_shift,
};

enum l2_arracc{
    l2_arraccadr_bad = 0xffffffff,
    l2_arraccctl_req = 1<<22,
    l2_arraccctl_rrc = 1<<21,
    l2_arraccctl_wrc = 1<<20,
    l2_arraccctl_bid_lru = 1<<18,
    l2_arraccctl_bid_tag = 1<<17,
    l2_arraccctl_bid_data = 1<<16,
    l2_arraccctl_rt_r = 0xf<<12,
    l2_arraccctl_rt_we = 0x6<<12,
    l2_arraccctl_rt_wne = 0x7<<12,
    l2_arraccctl_way_msk = 0x300,
    l2_arraccctl_way_ind = 8,
    l2_arraccctl_mask_dw_msk = 0xff,
};

struct l2_context{
    struct target * target;
    uint32_t prev_DCRIPR;
    uint32_t prev_L2CDCRAI;
    uint32_t prev_l2arraccadr;
    uint32_t rai;
    uint32_t rdi;
    uint32_t ra;
    uint32_t rd;
    enum l2_size size;
    uint32_t tag_n;
    uint32_t lru_n;
    uint32_t data_n;
    uint32_t ra_arraccctl;
    uint32_t ra_arraccadr;
    uint32_t ra_arraccdo0;
    uint32_t ra_arraccdo1;
    uint32_t ra_arraccdo2;
    uint32_t pncr;
    uint32_t rev_id;
    uint32_t cfg0;
};

struct l2_line{
    uint64_t base_addr;
    uint32_t data[16][2];
    uint32_t tag_info;
    enum l2_cache_state line_state;
    uint8_t ecc_data[16];
    uint8_t ecc_tag;
};
static inline int l2_write_complete(struct l2_context *context, enum L2C_L2REG reg){
    int ret = ERROR_OK;
    uint32_t code;
    uint32_t ra;
    switch ( reg ){
        case L2C_L2ARRACCCTL:
            ra = context->ra_arraccctl;
            break;
        case L2C_L2ARRACCADR:
            ra = context->ra_arraccadr;
            break;
        case L2C_L2ARRACCDO0:
            ra = context->ra_arraccdo0;
            break;
        case L2C_L2ARRACCDO1:
            ra = context->ra_arraccdo1;
            break;
        case L2C_L2ARRACCDO2:
            ra = context->ra_arraccdo2;
            break;
        default:
            ra = context->ra;
            break;
    }
    if (reg!=context->prev_L2CDCRAI){
        ret = write_gpr_u32(context->target,ra,reg);
        if (ret!=ERROR_OK){
            return ret;
        }
        code = mtdcr(context->rai,ra);
        ret = stuff_code(context->target,code);
        if (ret!=ERROR_OK){
            context->prev_L2CDCRAI = L2C_L2BAD_REG;
            return ret;
        }
        context->prev_L2CDCRAI = reg;
    }
    code = mtdcr(context->rdi,context->rd);
    ret = stuff_code(context->target,code);
    return ret;
}

static inline int l2_write_buf(struct l2_context *context, enum L2C_L2REG reg, const uint8_t *data){
    int ret = write_gpr_buf(context->target,context->rd,data);
    if (ret!=ERROR_OK){
        return ret;
    }
    ret = l2_write_complete ( context, reg );
    return ret;
}

static inline int l2_write_u32(struct l2_context *context, enum L2C_L2REG reg, uint32_t data){
    int ret = write_gpr_u32(context->target,context->rd,data);
    if (ret!=ERROR_OK){
        return ret;
    }
    ret = l2_write_complete ( context, reg );
    return ret;
}

static inline int l2_read_prepare(struct l2_context *context, enum L2C_L2REG reg){
    int ret = ERROR_OK;
    uint32_t code;
    uint32_t ra;
    switch ( reg ){
        case L2C_L2ARRACCCTL:
            ra = context->ra_arraccctl;
            break;
        case L2C_L2ARRACCADR:
            ra = context->ra_arraccadr;
            break;
        case L2C_L2ARRACCDO0:
            ra = context->ra_arraccdo0;
            break;
        case L2C_L2ARRACCDO1:
            ra = context->ra_arraccdo1;
            break;
        case L2C_L2ARRACCDO2:
            ra = context->ra_arraccdo2;
            break;
        default:
            ra = context->ra;
            break;
    }
    if (reg!=context->prev_L2CDCRAI){
        ret = write_gpr_u32(context->target,ra,reg);
        if (ret!=ERROR_OK)
            return ret;
        code = mtdcr(context->rai,ra);
        ret = stuff_code(context->target,code);
        if (ret!=ERROR_OK){
            context->prev_L2CDCRAI = L2C_L2BAD_REG;
            return ret;
        }
        context->prev_L2CDCRAI = reg;
    }
    code = mfdcr(context->rd,context->rdi);
    target_to_ppc476fp(context->target)->gpr_regs[context->rd]->dirty = true;
    target_to_ppc476fp(context->target)->current_gpr_values_valid[context->rd] = false;
    ret = stuff_code(context->target,code);
    return ret;
}

static inline int l2_read_buf(struct l2_context *context, enum L2C_L2REG reg, uint8_t *data){
    int ret = l2_read_prepare(context, reg);
    if ( ret != ERROR_OK ){
        return ret;
    }
    ret = read_gpr_buf(context->target, context->rd, data);
    return ret;
}

static inline int l2_read_u32(struct l2_context *context, enum L2C_L2REG reg, uint32_t *data){
    int ret = l2_read_prepare(context, reg);
    if ( ret != ERROR_OK ){
        return ret;
    }
    ret = read_gpr_u32(context->target, context->rd, data);
    return ret;
}

static inline int l2_restore_context(struct l2_context const *context){
    return write_spr_u32(context->target,SPR_REG_NUM_DCRIPR,context->prev_DCRIPR);
}

static inline int l2_init_context(struct target *target, struct l2_context *context, uint32_t ra, uint32_t rd,
        uint32_t ra_arraccctl, uint32_t ra_arraccadr, uint32_t ra_arraccdo0, uint32_t ra_arraccdo1, uint32_t ra_arraccdo2){
    int ret = read_spr_u32(target,SPR_REG_NUM_DCRIPR,&context->prev_DCRIPR);
    if (ret!=ERROR_OK){
        return ret;
    }
    assert ( rd != ra );
    assert ( rd != ra_arraccctl );
    assert ( rd != ra_arraccadr );
    assert ( rd != ra_arraccdo0 );
    assert ( rd != ra_arraccdo1 );
    assert ( rd != ra_arraccdo2 );
    uint32_t l2_base = ((struct ppc476fp_prv_conf*)target->private_config)->cache_base;
    context->target = target;
    context->prev_L2CDCRAI = L2C_L2BAD_REG;
    context->prev_l2arraccadr = l2_arraccadr_bad;
    context->ra = ra;
    context->rd = rd;
    context->ra_arraccctl = ra_arraccctl;
    context->ra_arraccadr = ra_arraccadr;
    context->ra_arraccdo0 = ra_arraccdo0;
    context->ra_arraccdo1 = ra_arraccdo1;
    context->ra_arraccdo2 = ra_arraccdo2;
    context->rai = l2_base & DCR_LSB_MASK;
    context->rdi = (l2_base+4) & DCR_LSB_MASK;
    context->size = 0;
    context->tag_n = 0;
    context->lru_n = 0;
    context->data_n = 0;
    do{
        ret = write_spr_u32(target,SPR_REG_NUM_DCRIPR,l2_base&DCRIPR_MASK);
        if (ret!=ERROR_OK){
            break;
        }
        ret = l2_read_u32(context,L2C_L2REVID,&context->rev_id);
        if (ret!=ERROR_OK){
            break;
        }
        if (context->rev_id == 0){
            LOG_ERROR("incorrect REVID reg. may be error");
            ret = ERROR_FAIL;
            break;
        }
        ret = l2_read_u32(context,L2C_L2PNCR,&context->pncr);
        if (ret!=ERROR_OK){
            break;
        }
        ret = l2_read_u32(context,L2C_L2CNFG0,&context->cfg0);
        if (ret!=ERROR_OK){
            break;
        }
        context->size = (enum l2_size)(context->cfg0&l2_size_msk);
        switch (context->size)
        {
        case l2_size_128k:
            context->tag_n = 8;
            context->lru_n = 8;
            context->data_n = 12;
            break;
        case l2_size_256k:
            context->tag_n = 9;
            context->lru_n = 9;
            context->data_n = 13;
            break;
        case l2_size_512k:
            context->tag_n = 10;
            context->lru_n = 10;
            context->data_n = 14;
            break;
        case l2_size_1m:
            context->tag_n = 11;
            context->lru_n = 11;
            context->data_n = 15;
            break;
        }
    }while(0);
    if (ret!=ERROR_OK){
        l2_restore_context(context);
    }
    return ret;
}

static inline int l2_arracc_set_arraccadr(struct l2_context *context, uint32_t array_addr){
    int ret = ERROR_OK;
    if(context->prev_l2arraccadr!=array_addr){
        ret = l2_write_u32(context,L2C_L2ARRACCADR,array_addr);
        if(ret!=ERROR_OK){
            context->prev_l2arraccadr = l2_arraccadr_bad;
            return ret;
        }
    }
    return ret;
}

static inline int l2_arracc_read(struct l2_context *context, uint32_t array_addr, uint32_t arraccctl){
    int ret = ERROR_OK;
    ret = l2_arracc_set_arraccadr(context,array_addr);
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_write_u32(context,L2C_L2ARRACCCTL,(arraccctl|l2_arraccctl_req|l2_arraccctl_rt_r));
    if(ret!=ERROR_OK)
        return ret;
    uint32_t data;
    bool valid = false;
    unsigned t = 10;
    while ((!valid) && ((t--)>0)){
        ret = l2_read_u32(context, L2C_L2ARRACCCTL, &data);
        if (ret!=ERROR_OK)
            return ret;
        valid = (data&(l2_arraccctl_rrc))!=0;
    }
    return valid?ERROR_OK:ERROR_FAIL;
}

static inline int l2_arracc_write(struct l2_context *context, uint32_t array_addr, uint32_t arraccctl, bool ecc_calc){
    int ret = ERROR_OK;
    ret = l2_arracc_set_arraccadr(context,array_addr);
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_write_u32(context,L2C_L2ARRACCCTL,(arraccctl|l2_arraccctl_req|(ecc_calc?l2_arraccctl_rt_we:l2_arraccctl_rt_wne)));
    if(ret!=ERROR_OK)
        return ret;
    uint32_t data;
    bool valid = false;
    unsigned t = 10;
    while ((!valid) && ((t--)>0)){
        ret = l2_read_u32(context, L2C_L2ARRACCCTL, &data);
        if (ret!=ERROR_OK)
            return ret;
        valid = (data&(l2_arraccctl_wrc))!=0;
    }
    return valid?ERROR_OK:ERROR_FAIL;
}

static inline int l2_read_lru(struct l2_context *context, uint32_t set, uint32_t *lru_info){
    int ret = ERROR_OK;
    ret = l2_arracc_read(context,set<<1,l2_arraccctl_bid_lru);
    if(ret!=ERROR_OK)
        return ret;
    if (lru_info){
        ret = l2_read_u32(context,L2C_L2ARRACCDO0, lru_info);
        if(ret!=ERROR_OK)
            return ret;
    }
    return ret;
}

static inline int l2_write_lru(struct l2_context *context, uint32_t set, uint32_t lru_info){
    int ret = ERROR_OK;
    ret = l2_write_u32(context,L2C_L2ARRACCDI0, lru_info);
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_arracc_write(context,set<<1,l2_arraccctl_bid_lru,false);
    if(ret!=ERROR_OK)
        return ret;
    return ret;
}

static inline int l2_write_tag(struct l2_context *context, uint32_t set, uint32_t cache_way, uint32_t tag_info, uint32_t tag_ecc){
    int ret = ERROR_OK;
    bool ecc_calc = true;
    ret = l2_write_u32(context,L2C_L2ARRACCDI0, tag_info);
    if(ret!=ERROR_OK)
        return ret;
    if ( tag_ecc != 0xffffffff ) {
        ecc_calc = false;
        ret = l2_write_u32(context,L2C_L2ARRACCDI2, tag_ecc << 1);
        if(ret!=ERROR_OK)
            return ret;
    }
    ret = l2_arracc_write(context,set<<1,l2_arraccctl_bid_tag|(cache_way<<l2_arraccctl_way_ind),ecc_calc);
    return ret;
}

static inline int l2_read_tag(struct l2_context *context, uint32_t set, uint32_t cache_way, uint32_t *tag_info, uint32_t *tag_ecc){
    int ret = ERROR_OK;
    ret = l2_arracc_read(context,set<<1,l2_arraccctl_bid_tag|(cache_way<<l2_arraccctl_way_ind));
    if(ret!=ERROR_OK){
        return ret;
    }
    if (tag_info){
        ret = l2_read_u32(context,L2C_L2ARRACCDO0, tag_info);
        if(ret!=ERROR_OK)
            return ret;
    }
    if (tag_ecc){
        ret = l2_read_u32(context,L2C_L2ARRACCDO2, tag_ecc);
        if(ret!=ERROR_OK)
            return ret;
    }
    return ret;
}

static inline int l2_write_data(struct l2_context *context, uint32_t set, uint32_t cache_way, uint32_t dw_ind, uint32_t data_h, uint32_t data_l, uint32_t data_ecc){
    int ret = ERROR_OK;
    bool ecc_calc = true;
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_write_u32(context,L2C_L2ARRACCDI0, data_h);
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_write_u32(context,L2C_L2ARRACCDI1, data_l);
    if(ret!=ERROR_OK)
        return ret;
    if(data_ecc != 0xffffffff){
        ecc_calc = false;
        ret = l2_write_u32(context,L2C_L2ARRACCDI2, data_ecc);
        if(ret!=ERROR_OK)
            return ret;
    }
    ret = l2_arracc_write(context,(set<<1)|(dw_ind>>3),l2_arraccctl_bid_data|(cache_way<<l2_arraccctl_way_ind)|(0x80>>(dw_ind&0x7)),ecc_calc);
    return ret;
}

static inline int l2_read_data(struct l2_context *context, uint32_t set, uint32_t cache_way, uint32_t dw_ind, uint32_t *data_h, uint32_t *data_l, uint32_t *data_ecc){
    int ret = ERROR_OK;
    ret = l2_arracc_read(context,(set<<1)|(dw_ind>>3),l2_arraccctl_bid_data|(cache_way<<l2_arraccctl_way_ind)|(0x80>>(dw_ind&0x7)));
    if(ret!=ERROR_OK)
        return ret;
    if (data_h){
        ret = l2_read_u32(context,L2C_L2ARRACCDO0, data_h);
        if(ret!=ERROR_OK)
            return ret;
    }
    if(data_l){
        ret = l2_read_u32(context,L2C_L2ARRACCDO1, data_l);
        if(ret!=ERROR_OK)
            return ret;
    }
    if(data_ecc){
        ret = l2_read_u32(context,L2C_L2ARRACCDO2, data_ecc);
        if(ret!=ERROR_OK)
            return ret;
    }
    return ret;
}

static inline int l2_read_line(struct l2_context *context, uint32_t set, uint32_t way, int ecc, int read_invalid, int filtred, uint64_t filtring_addr, struct l2_line *line){
    uint32_t info;

    int ret = ERROR_OK;
    uint32_t ecc_value = 0;
    uint32_t *pecc = ecc?&ecc_value:NULL;
    ret = l2_read_tag(context,set,way,&info,pecc);
    if (ret != ERROR_OK){
        LOG_ERROR("Can't read tag %i",set);
        return ret;
    }
    line->tag_info = info;
    line->ecc_tag = ecc_value>>1;
    line->line_state = info&l2_cache_state_mask;
    bool valid = true;
    uint32_t eaddr = (info>>19)&0x3ff;
    uint32_t addr = (info<<13)|(set<<7);
    line->base_addr = eaddr;
    line->base_addr <<=32;
    line->base_addr |= addr;
    if ((line->line_state == l2_cache_state_invalid)||(line->line_state == l2_cache_state_undefined))
        valid = false;
    if (
            ( !filtred || ( (filtring_addr & 0xffffffffffffff80ull) == line->base_addr ) )
            && (valid||read_invalid)
    ){
        for(uint32_t i=0;i<16;++i){
            l2_read_data(context,set,way,i,&line->data[i][0],&line->data[i][1],pecc);
            line->ecc_data[i]=ecc_value;
        }
    }
    return ret;
}

#endif // __PPC476FP_L2_H__
