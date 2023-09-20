#include <stdint.h>

#ifndef __PPC476FP_STUFFS_H__
#define __PPC476FP_STUFFS_H__

enum stuff_codes{
    // tlb
    STUFF_CODE_TLBRE = 0x7c000764,
    STUFF_CODE_TLBWE = 0x7c0007a4,
    STUFF_CODE_TLBSX = 0x7c000724,
    // cache
    STUFF_CODE_ICBI = 0x7c0007ac,
    STUFF_CODE_ICBT = 0x7c00002c,
    STUFF_CODE_ICI = 0x7c00078c,
    STUFF_CODE_DCI = 0x7c00038c,
    STUFF_CODE_DCBF = 0x7c0000ac,
    STUFF_CODE_DCBT = 0x7c00022c,
    STUFF_CODE_DCREAD = 0x7c00028c,
    STUFF_CODE_ICREAD = 0x7c0007cc,
    // gpr
    STUFF_CODE_ADDIS = 0x3c000000,
    STUFF_CODE_ADDI = 0x38000000,
    STUFF_CODE_ORI = 0x60000000,
    STUFF_CODE_XORI = 0x68000000,
    STUFF_CODE_XORIS = 0x6c000000,
    // jump
    STUFF_CODE_B = 0x48000000,
    STUFF_CODE_BCLR = 0x4c000020,
    // spr/dcr
    STUFF_CODE_MTSPR = 0x7c0003a6,
    STUFF_CODE_MFSPR = 0x7c0002a6,
    STUFF_CODE_MTMSR = 0x7c000124,
    STUFF_CODE_MFMSR = 0x7c0000a6,
    STUFF_CODE_MTDCRX = 0x7c000306,
    STUFF_CODE_MFDCRX = 0x7c000206,
    STUFF_CODE_MTCRF = 0x7c000120,
    STUFF_CODE_MFCR = 0x7c000026,
    STUFF_CODE_MTDCR = 0x7c000386,
    STUFF_CODE_MFDCR = 0x7c000286,
    // fpu
    STUFF_CODE_MTFSF = 0xfc00058e,
    STUFF_CODE_MFFS = 0xfc00048e,
    STUFF_CODE_STFD = 0xd8000000,
    STUFF_CODE_LFD = 0xc8000000,
    // mem
    STUFF_CODE_LWZ = 0x80000000,
    STUFF_CODE_LHZ = 0xa0000000,
    STUFF_CODE_LBZ = 0x88000000,
    STUFF_CODE_STW = 0x90000000,
    STUFF_CODE_STH = 0xb0000000,
    STUFF_CODE_STB = 0x98000000,
    STUFF_CODE_ISYNC = 0x4c00012c,
    STUFF_CODE_MSYNC = 0x7c0004ac,
    // trap
    STUFF_CODE_TW = 0x7c000008,
};

static inline uint32_t reg_num_10_bits (uint32_t reg_num){
    return ((reg_num&0x1f)<<5) | ((reg_num>>5)&0x1f);   
}

static inline uint32_t lwz (uint32_t rt, uint32_t ra, int16_t d){
    return (((uint32_t)STUFF_CODE_LWZ) | (rt<<21) | (ra << 16) | ((uint16_t)d));
}

static inline uint32_t lhz (uint32_t rt, uint32_t ra, int16_t d){
    return (((uint32_t)STUFF_CODE_LHZ) | (rt<<21) | (ra << 16) | ((uint16_t)d));
}

static inline uint32_t lbz (uint32_t rt, uint32_t ra, int16_t d){
    return (((uint32_t)STUFF_CODE_LBZ) | (rt<<21) | (ra << 16) | ((uint16_t)d));
}

static inline uint32_t stw (uint32_t rt, uint32_t ra, int16_t d){
    return (((uint32_t)STUFF_CODE_STW) | (rt<<21) | (ra << 16) | ((uint16_t)d));
}

static inline uint32_t sth (uint32_t rt, uint32_t ra, int16_t d){
    return (((uint32_t)STUFF_CODE_STH) | (rt<<21) | (ra << 16) | ((uint16_t)d));
}

static inline uint32_t stb (uint32_t rt, uint32_t ra, int16_t d){
    return (((uint32_t)STUFF_CODE_STB) | (rt<<21) | (ra << 16) | ((uint16_t)d));
}

static inline uint32_t mtfsf(uint8_t flm, uint32_t frb){
    return (((uint32_t)STUFF_CODE_MTFSF) | (((uint32_t)flm)<<17) | (frb<<11) );
}

static inline uint32_t mffs(uint32_t frt){
    return (((uint32_t)STUFF_CODE_MFFS) | (frt<<21) );
}

static inline uint32_t isync(void){
    return STUFF_CODE_ISYNC;
}

static inline uint32_t msync(void){
    return STUFF_CODE_MSYNC;
}

static inline uint32_t icbi(uint32_t ra, uint32_t rb){
    return (((uint32_t)STUFF_CODE_ICBI) | (ra<<16) | (rb<<11));
}

static inline uint32_t tlbre(uint32_t rt, uint32_t ra, uint32_t ws){
    return (((uint32_t)STUFF_CODE_TLBRE) | (rt<<21) | (ra<<16) | (ws<<11));
}

static inline uint32_t tlbwe(uint32_t rt, uint32_t ra, uint32_t ws){
    return (((uint32_t)STUFF_CODE_TLBWE) | (rt<<21) | (ra<<16) | (ws<<11));
}

static inline uint32_t ici(void){
    return STUFF_CODE_ICI;
}

static inline uint32_t dci(uint32_t ct){
    return (((uint32_t)STUFF_CODE_DCI) | (ct<<21));
}

static inline uint32_t dcbf(uint32_t ra, uint32_t rb){
    return (((uint32_t)STUFF_CODE_DCBF) | (ra<<16) | (rb<<11));
}

static inline uint32_t dcbt(uint32_t ra, uint32_t rb){
    return (((uint32_t)STUFF_CODE_DCBT) | (ra<<16) | (rb<<11));
}

static inline uint32_t dcread(uint32_t rt, uint32_t ra, uint32_t rb){
    return (((uint32_t)STUFF_CODE_DCREAD) | (rt<<21) | (ra<<16) | (rb<<11));
}

static inline uint32_t icread(uint32_t ra, uint32_t rb){
    return (((uint32_t)STUFF_CODE_ICREAD) | (ra<<16) | (rb<<11));
}

static inline uint32_t icbt(uint32_t ra, uint32_t rb){
    return (((uint32_t)STUFF_CODE_ICBT) | (ra<<16) | (rb<<11));
}

static inline uint32_t mtspr(uint32_t spr_n, uint32_t rs){
    return (((uint32_t)STUFF_CODE_MTSPR) | (rs<<21) | (reg_num_10_bits(spr_n)<<11));
}

static inline uint32_t mfspr(uint32_t rt, uint32_t spr_n){
    return (((uint32_t)STUFF_CODE_MFSPR) | (rt<<21) | (reg_num_10_bits(spr_n)<<11));
}

static inline uint32_t mtmsr(uint32_t rs, uint32_t l){
    return (((uint32_t)STUFF_CODE_MTMSR) | (rs<<21) | (((uint32_t)(l!=0?1:0))<<16));
}

static inline uint32_t mfmsr(uint32_t rt){
    return (((uint32_t)STUFF_CODE_MFMSR) | (rt<<21));
}

static inline uint32_t mtdcrx(uint32_t ra, uint32_t rs){
    return (((uint32_t)STUFF_CODE_MTDCRX) | (rs<<21) | (ra<<16));
}

static inline uint32_t mfdcrx(uint32_t rt, uint32_t ra){
    return (((uint32_t)STUFF_CODE_MFDCRX) | (rt<<21) | (ra<<16));
}

static inline uint32_t addis(uint32_t rt, uint32_t ra, uint16_t si){
    return (((uint32_t)STUFF_CODE_ADDIS) | (rt<<21) | (ra<<16) | si );
}

static inline uint32_t lis(uint32_t rx, uint16_t value){
    return addis(rx,0,value);
}

static inline uint32_t addi(uint32_t rt, uint32_t ra, int16_t si){
    return (((uint32_t)STUFF_CODE_ADDI) | (rt<<21) | (ra<<16) | ((uint16_t)si) );
}

static inline uint32_t li(uint32_t rx, int16_t value){
    return addi(rx,0,value);
}

static inline uint32_t ori(uint32_t ra, uint32_t rs, uint16_t si){
    return (((uint32_t)STUFF_CODE_ORI) | (rs<<21) | (ra<<16) | si );
}

static inline uint32_t xori(uint32_t ra, uint32_t rs, uint16_t si){
    return (((uint32_t)STUFF_CODE_XORI) | (rs<<21) | (ra<<16) | si );
}

static inline uint32_t xoris(uint32_t ra, uint32_t rs, uint16_t si){
    return (((uint32_t)STUFF_CODE_XORIS) | (rs<<21) | (ra<<16) | si );
}

static inline uint32_t stfd(uint32_t frs, uint32_t ra, int16_t d){
    return (((uint32_t)STUFF_CODE_STFD) | (frs<<21) | (ra<<16) | (uint16_t)d);
}

static inline uint32_t lfd(uint32_t frt, uint32_t ra, int16_t d){
    return (((uint32_t)STUFF_CODE_LFD) | (frt<<21) | (ra<<16) | (uint16_t)d);
}

static inline uint32_t b(uint32_t li, uint32_t aa, uint32_t lk){
    return (((uint32_t)STUFF_CODE_B) | (li<<2) | (aa<<1) | lk);
}

static inline uint32_t bl(uint32_t li){
    return b(li,0,1);
}

static inline uint32_t bclr(uint32_t bo, uint32_t bi, uint32_t bh, uint32_t lk){
    return (((uint32_t)STUFF_CODE_BCLR) | (bo<<21) | (bi<<16) | (bh<<11) | lk);
}

static inline uint32_t blr(void){
    return bclr(0x14,0,0,0);
}

static inline uint32_t mtcrf(uint8_t fxm, uint32_t rs){
    return (((uint32_t)STUFF_CODE_MTCRF) | (((uint32_t)fxm)<<12) | (rs<<21));
}

static inline uint32_t mtcr(uint32_t rs){
    return mtcrf(0xff,rs);
}

static inline uint32_t mfcr(uint32_t rt){
    return (((uint32_t)STUFF_CODE_MFCR) | (rt<<21));
}

static inline uint32_t mtdcr(uint32_t dcrn, uint32_t rs){
    return (((uint32_t)STUFF_CODE_MTDCR) | (rs<<21) | (reg_num_10_bits(dcrn)<<11));
}

static inline uint32_t mfdcr(uint32_t rt, uint32_t dcrn){
    return (((uint32_t)STUFF_CODE_MFDCR) | (rt<<21) | (reg_num_10_bits(dcrn)<<11));
}

static inline uint32_t tw(uint32_t to, uint32_t ra, uint32_t rb){
    return (((uint32_t)STUFF_CODE_TW) | (to<<21) | (ra<<16) | (rb<<11));
}

static inline uint32_t trap(void){
    return tw(31,0,0);
}

static inline uint32_t tlbsx(uint32_t rt, uint32_t ra, uint32_t rb){
    return (((uint32_t)STUFF_CODE_TLBSX)|(rt<<21)|(ra<<16)|(rb<<11));
}

// tlbsx.
static inline uint32_t tlbsx_(uint32_t rt, uint32_t ra, uint32_t rb){
    return (((uint32_t)STUFF_CODE_TLBSX)|(rt<<21)|(ra<<16)|(rb<<11)|1u);
}

#endif // __PPC476FP_STUFFS_H__
