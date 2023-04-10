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
    l2_cache_state_invalid = 0<<29,
    l2_cache_state_undefined = 1<<29,
    l2_cache_state_shared = 2<<29,
    l2_cache_state_shared_last = 3<<29,
    l2_cache_state_exclusive = 4<<29,
    l2_cache_state_tagged = 5<<29,
    l2_cache_state_modified = 6<<29,
    l2_cache_state_modified_unsolicited = 7<<29,
    l2_cache_state_mask = 7<<29,
};

enum l2_arracc{
    l2_arraccadr_bad = 0xffffffff,
    l2_arraccctl_req = 1<<22,
    l2_arraccctl_rrc = 1<<21,
    l2_arraccctl_wrc = 1<<20,
    l2_arraccctl_bid_ltu = 1<<18,
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
};

static inline int l2_write(struct l2_context *context, enum L2C_L2REG reg, uint32_t data){
    int ret = ERROR_OK;
    uint32_t code;
    if (reg!=context->prev_L2CDCRAI){
        ret = write_gpr_reg(context->target,context->ra,reg);
        if (ret!=ERROR_OK){
            return ret;
        }
        code = mtdcr(context->rai,context->ra);
        ret = stuff_code(context->target,code);
        if (ret!=ERROR_OK){
            context->prev_L2CDCRAI = L2C_L2BAD_REG;
            return ret;
        }
        context->prev_L2CDCRAI = reg;
    }
    ret = write_gpr_reg(context->target,context->rd,data);
    if (ret!=ERROR_OK){
        return ret;
    }
    code = mtdcr(context->rdi,context->rd);
    ret = stuff_code(context->target,code);
    return ret;
}

static inline int l2_read(struct l2_context *context, enum L2C_L2REG reg, uint32_t *data){
    int ret = ERROR_OK;
    uint32_t code;
    if (reg!=context->prev_L2CDCRAI){
        ret = write_gpr_reg(context->target,context->ra,reg);
        if (ret!=ERROR_OK){
            return ret;
        }
        code = mtdcr(context->rai,context->ra);
        ret = stuff_code(context->target,code);
        if (ret!=ERROR_OK){
            context->prev_L2CDCRAI = L2C_L2BAD_REG;
            return ret;
        }
        context->prev_L2CDCRAI = reg;
    }
    code = mfdcr(context->rd,context->rdi);
    ret = stuff_code(context->target,code);
    if (ret!=ERROR_OK){
        return ret;
    }
    ret = read_gpr_reg(context->target, context->rd, (uint8_t*)data);
    return ret;
}

static inline int l2_restore_context(struct l2_context const *context){
    return write_spr_reg(context->target,SPR_REG_NUM_DCRIPR,context->prev_DCRIPR);
}

static inline int l2_init_context(struct target *target, struct l2_context *context, uint32_t ra, uint32_t rd){
    int ret = read_spr_reg(target,SPR_REG_NUM_DCRIPR,(uint8_t*)&context->prev_DCRIPR);
    if (ret!=ERROR_OK){
        return ret;
    }
    do{
        ret = write_spr_reg(target,SPR_REG_NUM_DCRIPR,DCR_L2_BASE_ADDR&DCRIPR_MASK);
        if (ret!=ERROR_OK){
            break;
        }
        uint32_t context_size;
        context->target = target;
        context->prev_L2CDCRAI = L2C_L2BAD_REG;
        context->prev_l2arraccadr = l2_arraccadr_bad;
        context->ra = ra;
        context->rd = rd;
        context->rai = DCR_L2_BASE_ADDR & DCR_LSB_MASK;
        context->rdi = (DCR_L2_BASE_ADDR+4) & DCR_LSB_MASK;
        ret = l2_read(context,L2C_L2CNFG0,&context_size);
        if (ret!=ERROR_OK){
            break;
        }
        context->size = (enum l2_size)(context_size&l2_size_msk);
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

static inline int l2_arracc_read(struct l2_context *context, uint32_t array_addr, uint32_t arraccctl){
    int ret = ERROR_OK;
    if(context->prev_l2arraccadr!=array_addr){
        ret = l2_write(context,L2C_L2ARRACCADR,array_addr);
        if(ret!=ERROR_OK){
            context->prev_l2arraccadr = l2_arraccadr_bad;
            return ret;
        }
    }
    ret = l2_write(context,L2C_L2ARRACCCTL,(arraccctl|l2_arraccctl_req|l2_arraccctl_rt_r));
    if(ret!=ERROR_OK)
        return ret;
    bool valid = false;
    unsigned t = 10;
    uint32_t data;
    while ((!valid) && ((t--)>0)){
        ret = l2_read(context, L2C_L2ARRACCCTL, &data);
        if (ret!=ERROR_OK)
            break;
        valid = (data&l2_arraccctl_rrc)!=0;
    }
    if ((ret==ERROR_OK) && (!valid))
        ret = ERROR_FAIL;
    return ret;
}

static inline int l2_read_tag(struct l2_context *context, uint32_t tag_addr, uint32_t cache_way, uint32_t *tag_info, uint32_t *tag_ecc){
    int ret = ERROR_OK;
    ret = l2_arracc_read(context,tag_addr<<1,l2_arraccctl_bid_tag|(cache_way<<l2_arraccctl_way_ind));
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_read(context,L2C_L2ARRACCDO0, tag_info);
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_read(context,L2C_L2ARRACCDO2, tag_ecc);
    if(ret!=ERROR_OK)
        return ret;
    return ret;
}

static inline int l2_read_data(struct l2_context *context, uint32_t data_addr, uint32_t cache_way, uint32_t *data_h, uint32_t *data_l, uint32_t *data_ecc){
    int ret = ERROR_OK;
    ret = l2_arracc_read(context,data_addr>>3,l2_arraccctl_bid_data|(cache_way<<l2_arraccctl_way_ind)|(0x80>>(data_addr&0x7)));
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_read(context,L2C_L2ARRACCDO0, data_h);
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_read(context,L2C_L2ARRACCDO1, data_l);
    if(ret!=ERROR_OK)
        return ret;
    ret = l2_read(context,L2C_L2ARRACCDO2, data_ecc);
    if(ret!=ERROR_OK)
        return ret;
    return ret;
}

#endif // __PPC476FP_L2_H__
