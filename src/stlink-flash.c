#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "stlink-common.h"
#include "stlink-flash.h"
#define LOG_TAG __FILE__
#include "uglylogging.h"

/* todo: stm32l15xxx flash memory, pm0062 manual */

/* stm32f FPEC flash controller interface, pm0063 manual */
/* TODO - all of this needs to be abstracted out....  STM32F05x is
 *  identical, based on RM0091 (DM00031936, Doc ID 018940 Rev 2,
 *  August 2012)
 */
#define FLASH_REGS_ADDR 0x40022000
#define FLASH_REGS_SIZE 0x28

#define FLASH_ACR (FLASH_REGS_ADDR + 0x00)
#define FLASH_KEYR (FLASH_REGS_ADDR + 0x04)
#define FLASH_SR (FLASH_REGS_ADDR + 0x0c)
#define FLASH_CR (FLASH_REGS_ADDR + 0x10)
#define FLASH_AR (FLASH_REGS_ADDR + 0x14)
#define FLASH_OBR (FLASH_REGS_ADDR + 0x1c)
#define FLASH_WRPR (FLASH_REGS_ADDR + 0x20)

// For STM32F05x, the RDPTR_KEY may be wrong, but as it is not used anywhere...
#define FLASH_RDPTR_KEY 0x00a5
#define FLASH_KEY1 0x45670123
#define FLASH_KEY2 0xcdef89ab

#define FLASH_SR_BSY 0
#define FLASH_SR_EOP 5

#define FLASH_CR_PG 0
#define FLASH_CR_PER 1
#define FLASH_CR_MER 2
#define FLASH_CR_STRT 6
#define FLASH_CR_LOCK 7

//32L = 32F1 same CoreID as 32F4!
#define STM32L_FLASH_REGS_ADDR ((uint32_t)0x40023c00)
#define STM32L_FLASH_ACR (STM32L_FLASH_REGS_ADDR + 0x00)
#define STM32L_FLASH_PECR (STM32L_FLASH_REGS_ADDR + 0x04)
#define STM32L_FLASH_PDKEYR (STM32L_FLASH_REGS_ADDR + 0x08)
#define STM32L_FLASH_PEKEYR (STM32L_FLASH_REGS_ADDR + 0x0c)
#define STM32L_FLASH_PRGKEYR (STM32L_FLASH_REGS_ADDR + 0x10)
#define STM32L_FLASH_OPTKEYR (STM32L_FLASH_REGS_ADDR + 0x14)
#define STM32L_FLASH_SR (STM32L_FLASH_REGS_ADDR + 0x18)
#define STM32L_FLASH_OBR (STM32L_FLASH_REGS_ADDR + 0x1c)
#define STM32L_FLASH_WRPR (STM32L_FLASH_REGS_ADDR + 0x20)
#define FLASH_L1_FPRG 10
#define FLASH_L1_PROG 3

//STM32F4
#define FLASH_F4_REGS_ADDR ((uint32_t)0x40023c00)
#define FLASH_F4_KEYR (FLASH_F4_REGS_ADDR + 0x04)
#define FLASH_F4_OPT_KEYR (FLASH_F4_REGS_ADDR + 0x08)
#define FLASH_F4_SR (FLASH_F4_REGS_ADDR + 0x0c)
#define FLASH_F4_CR (FLASH_F4_REGS_ADDR + 0x10)
#define FLASH_F4_OPT_CR (FLASH_F4_REGS_ADDR + 0x14)
#define FLASH_F4_CR_STRT 16
#define FLASH_F4_CR_LOCK 31
#define FLASH_F4_CR_SER 1
#define FLASH_F4_CR_SNB 3
#define FLASH_F4_CR_SNB_MASK 0x38
#define FLASH_F4_SR_BSY 16

static int write_loader_to_sram(stlink_t *sl, stm32_addr_t* addr, size_t* size);
static int run_flash_loader(stlink_t *sl, flash_loader_t* fl, stm32_addr_t target, const uint8_t* buf, size_t size);
static int write_buffer_to_sram(stlink_t *sl, flash_loader_t* fl, const uint8_t* buf, size_t size);

static st_error_t
read_flash_cr(stlink_t *sl, uint32_t *res)
{
    st_error_t r;
    uint32_t addr;
    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        addr = FLASH_F4_CR;
    }
    else
    {
        addr = FLASH_CR;
    }

    r = stlink_read_debug32(sl, addr, res);

#if DEBUG_FLASH
    if (r == ST_SUCCESS)
    {
        fprintf(stdout, "CR:0x%x\n", *res);
    }
    else
    {
        fprintf(stdout, "CR:<error>\n");
    }
#endif

    return r;
}

static st_error_t
is_flash_locked(stlink_t *sl, bool *ret)
{
    /* return non zero for true */
    uint32_t cr;
    uint32_t mask;
    st_error_t r = read_flash_cr(sl, &cr);
    if (r != ST_SUCCESS)
    {
        return r;
    }
    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        mask = (1 << FLASH_F4_CR_LOCK);
    }
    else
    {
        mask = (1 << FLASH_CR_LOCK);
    }

    *ret = cr & mask;
    return ST_SUCCESS;
}

static st_error_t
unlock_flash(stlink_t *sl)
{
    /* the unlock sequence consists of 2 write cycles where
       2 key values are written to the FLASH_KEYR register.
       an invalid sequence results in a definitive lock of
       the FPEC block until next reset.
     */
    st_error_t r;
    uint32_t addr;
    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        addr = FLASH_F4_KEYR;
    } else {
        addr = FLASH_KEYR;
    }

    r = stlink_write_debug32(sl, addr, FLASH_KEY1);
    if (r != ST_SUCCESS)
    {
        return r;
    }
    r = stlink_write_debug32(sl, addr, FLASH_KEY2);
    if (r != ST_SUCCESS)
    {
        return r;
    }

    return ST_SUCCESS;
}

static int
unlock_flash_if(stlink_t *sl)
{
    /* unlock flash if already locked */
    bool locked;
    st_error_t r;

    r = is_flash_locked(sl, &locked);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    if (locked)
    {
        r = unlock_flash(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        r = is_flash_locked(sl, &locked);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        if (locked)
        {
            WLOG("Failed to unlock flash!\n");
            return -1;
        }
    }

    DLOG("Successfully unlocked flash\n");
    return 0;
}

static st_error_t
lock_flash(stlink_t *sl)
{
    uint32_t cr;
    uint32_t new_cr;
    uint32_t addr;
    uint32_t lock_mask;
    st_error_t r;

    r = read_flash_cr(sl, &cr);
    if (r != ST_SUCCESS)
    {
        return r;
    }
    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        lock_mask =  (1 << FLASH_F4_CR_LOCK);
        addr = FLASH_F4_CR;
    }
    else
    {
        /* write to 1 only. reset by hw at unlock sequence */
        lock_mask = (1 << FLASH_CR_LOCK);
        addr = FLASH_CR;
    }

    new_cr = cr | lock_mask;
    return stlink_write_debug32(sl, addr, new_cr);
}

static st_error_t
set_flash_cr_pg(stlink_t *sl)
{
    st_error_t r;
    uint32_t addr;
    uint32_t val;
    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        r = read_flash_cr(sl, &val);
        if (r != ST_SUCCESS)
        {
            return r;
        }
        val |= (1 << FLASH_CR_PG);
        addr = FLASH_F4_CR;
    } else {
        val = 1 << FLASH_CR_PG;
        addr = FLASH_CR;
    }

    return stlink_write_debug32(sl, addr, val);
}

static st_error_t
set_flash_cr_per(stlink_t *sl)
{
    const uint32_t n = 1 << FLASH_CR_PER;
    return stlink_write_debug32(sl, FLASH_CR, n);
}

static st_error_t
set_flash_cr_mer(stlink_t *sl)
{
    uint32_t addr;
    uint32_t val;
    st_error_t r;

    r = read_flash_cr(sl, &val);
    if (r != ST_SUCCESS)
    {
        return r;
    }
    val |= (1 << FLASH_CR_MER);

    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        addr = FLASH_F4_CR;
    }
    else
    {
        addr = FLASH_CR;
    }

    return stlink_write_debug32(sl, addr, val);

}

static st_error_t
set_flash_cr_strt(stlink_t *sl)
{
    st_error_t r;
    uint32_t addr;
    uint32_t val;

    r = read_flash_cr(sl, &val);
    if (r != ST_SUCCESS)
    {
        return r;
    }

    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        val |= (1 << FLASH_F4_CR_STRT);
        addr = FLASH_F4_CR;
    }
    else
    {
        val |= (1 << FLASH_CR_STRT);
        addr = FLASH_CR;
    }

    return stlink_write_debug32(sl, addr, val);

}

static st_error_t
read_flash_sr(stlink_t *sl, uint32_t *sr)
{
    uint32_t addr;
    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        addr = FLASH_F4_SR;
    }
    else
    {
        addr = FLASH_SR;
    }

    return stlink_read_debug32(sl, addr, sr);
}

static st_error_t
is_flash_busy(stlink_t *sl, bool *busy)
{
    uint32_t mask;
    uint32_t sr;
    st_error_t r = read_flash_sr(sl, &sr);
    if (r != ST_SUCCESS)
    {
        return r;
    }
    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        mask = 1 << FLASH_F4_SR_BSY;
    }
    else
    {
        mask = 1 << FLASH_SR_BSY;
    }

    *busy = (sr & mask) != 0;
    return ST_SUCCESS;
}

static st_error_t
wait_flash_busy(stlink_t *sl)
{
    st_error_t r;
    for (;;)
    {
        bool busy;
        r = is_flash_busy(sl, &busy);
        if (r != ST_SUCCESS)
        {
            return r;
        }

        if (!busy)
        {
            break;
        }
        /* todo: add some delays here */
    }

    return ST_SUCCESS;
}

static st_error_t
wait_flash_busy_progress(stlink_t *sl)
{
    int i = 0;
    st_error_t r;
    fprintf(stdout, "Mass erasing");
    fflush(stdout);
    for (;;)
    {
        bool busy;
        r = is_flash_busy(sl, &busy);
        if (r != ST_SUCCESS)
        {
            return r;
        }

        if (!busy)
        {
            fprintf(stdout, "\n");
            break;
        }

        usleep(10000);
        i++;
        if (i % 100 == 0) {
            fprintf(stdout, ".");
            fflush(stdout);
        }
    }

    return ST_SUCCESS;
}

static st_error_t
write_flash_ar(stlink_t *sl, uint32_t n)
{
    return stlink_write_debug32(sl, FLASH_AR, n);
}

static st_error_t
write_flash_cr_psiz(stlink_t *sl, uint32_t n)
{
    uint32_t x;
    st_error_t r;
    r = read_flash_cr(sl, &x);
    if (r != ST_SUCCESS)
    {
        return r;
    }
    x &= ~(0x03 << 8);
    x |= (n << 8);
#if DEBUG_FLASH
    fprintf(stdout, "PSIZ:0x%x 0x%x\n", x, n);
#endif
    return stlink_write_debug32(sl, FLASH_F4_CR, x);
}

static st_error_t
write_flash_cr_snb(stlink_t *sl, uint32_t n)
{
    uint32_t x;
    st_error_t r;
    r = read_flash_cr(sl, &x);
    x &= ~FLASH_F4_CR_SNB_MASK;
    x |= (n << FLASH_F4_CR_SNB);
    x |= (1 << FLASH_F4_CR_SER);
#if DEBUG_FLASH
    fprintf(stdout, "SNB:0x%x 0x%x\n", x, n);
#endif
    return stlink_write_debug32(sl, FLASH_F4_CR, x);
}

static uint32_t
calculate_F4_sectornum(uint32_t flashaddr)
{
    flashaddr &= ~STM32_FLASH_BASE;	//Page now holding the actual flash address
    if (flashaddr<0x4000) return (0);
    else if(flashaddr<0x8000) return(1);
    else if(flashaddr<0xc000) return(2);
    else if(flashaddr<0x10000) return(3);
    else if(flashaddr<0x20000) return(4);
    else return(flashaddr/0x20000)+4;

}

uint32_t
stlink_calculate_pagesize(stlink_t *sl, uint32_t flashaddr)
{
    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4)) {
        uint32_t sector = calculate_F4_sectornum(flashaddr);
        if (sector < 4) sl->flash_pgsz = 0x4000;
        else if(sector < 5) sl->flash_pgsz = 0x10000;
        else sl->flash_pgsz = 0x20000;
    }

    return (sl->flash_pgsz);
}

/**
 * Erase a page of flash, assumes sl is fully populated with things like chip/core ids
 * @param sl stlink context
 * @param flashaddr an address in the flash page to erase
 * @return 0 on success -ve on failure
 */
int
stlink_erase_flash_page(stlink_t *sl, stm32_addr_t flashaddr)
{
    st_error_t r;
    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        /* wait for ongoing op to finish */
        r = wait_flash_busy(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* unlock if locked */
        if (unlock_flash_if(sl) != 0)
        {
            return -1;
        }

        /* select the page to erase */
        // calculate the actual page from the address
        uint32_t sector = calculate_F4_sectornum(flashaddr);

        fprintf(stderr, "EraseFlash - Sector:0x%x Size:0x%x\n", sector, stlink_calculate_pagesize(sl, flashaddr));
        r = write_flash_cr_snb(sl, sector);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* start erase operation */
        r = set_flash_cr_strt(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* wait for completion */
        r = wait_flash_busy(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* relock the flash */
        r = lock_flash(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
  }

  else if (sl->chip_id == STM32_CHIPID_L1_MEDIUM)
  {

    uint32_t val;

    /* disable pecr protection */
    r = stlink_write_debug32(sl, STM32L_FLASH_PEKEYR, 0x89abcdef);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
    r = stlink_write_debug32(sl, STM32L_FLASH_PEKEYR, 0x02030405);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    /* check pecr.pelock is cleared */
    r = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
    if (val & (1 << 0)) {
      WLOG("pecr.pelock not clear (%#x)\n", val);
      return -1;
    }

    /* unlock program memory */
    r = stlink_write_debug32(sl, STM32L_FLASH_PRGKEYR, 0x8c9daebf);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    r = stlink_write_debug32(sl, STM32L_FLASH_PRGKEYR, 0x13141516);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    /* check pecr.prglock is cleared */
    r = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
    if (val & (1 << 1)) {
      WLOG("pecr.prglock not clear (%#x)\n", val);
      return -1;
    }

    /* unused: unlock the option byte block */
#if 0
    stlink_write_debug32(sl, STM32L_FLASH_OPTKEYR, 0xfbead9c8);
    stlink_write_debug32(sl, STM32L_FLASH_OPTKEYR, 0x24252627);

    /* check pecr.optlock is cleared */
    val = stlink_read_debug32(sl, STM32L_FLASH_PECR);
    if (val & (1 << 2)) {
      fprintf(stderr, "pecr.prglock not clear\n");
      return -1;
    }
#endif

    /* set pecr.{erase,prog} */
    val |= (1 << 9) | (1 << 3);
    r = stlink_write_debug32(sl, STM32L_FLASH_PECR, val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

#if 0 /* fix_to_be_confirmed */

    /* wait for sr.busy to be cleared
       MP: Test shows that busy bit is not set here. Perhaps, PM0062 is
       wrong and we do not need to wait here for clearing the busy bit.
       TEXANE: ok, if experience says so and it works for you, we comment
       it. If someone has a problem, please drop an email.
     */
    while ((stlink_read_debug32(sl, STM32L_FLASH_SR) & (1 << 0)) != 0)
        ;

#endif /* fix_to_be_confirmed */

    /* write 0 to the first word of the page to be erased */
    r = stlink_write_debug32(sl, flashaddr, 0);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    /* MP: It is better to wait for clearing the busy bit after issuing
    page erase command, even though PM0062 recommends to wait before it.
    Test shows that a few iterations is performed in the following loop
    before busy bit is cleared.*/
    for (;;)
    {
        r = stlink_read_debug32(sl, STM32L_FLASH_SR, &val);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        if ((val & (1 << 0)) == 0)
        {
            break;
        }
    }

    /* reset lock bits */
    r  = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
    val = val | (1 << 0) | (1 << 1) | (1 << 2);
    r = stlink_write_debug32(sl, STM32L_FLASH_PECR, val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
  }
  else if (sl->core_id == STM32VL_CORE_ID ||
           sl->core_id == STM32F0_CORE_ID ||
           sl->chip_id == STM32_CHIPID_F3 ||
           sl->chip_id == STM32_CHIPID_F37x)
  {
      /* wait for ongoing op to finish */
      r = wait_flash_busy(sl);
      if (r != ST_SUCCESS)
      {
          return -1;
      }

      /* unlock if locked */
      if (unlock_flash_if(sl) != 0)
      {
          return -1;
      }

    /* set the page erase bit */
    r = set_flash_cr_per(sl);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    /* select the page to erase */
    r = write_flash_ar(sl, flashaddr);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    /* start erase operation, reset by hw with bsy bit */
    r = set_flash_cr_strt(sl);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    /* wait for completion */
    r = wait_flash_busy(sl);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    /* relock the flash */
    r = lock_flash(sl);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
  }
  else
  {
    WLOG("unknown coreid %x, page erase failed\n", sl->core_id);
    return -1;
  }

  /* todo: verify the erased page */
  return 0;
}

int
stlink_erase_flash_mass(stlink_t *sl)
{
    st_error_t r;

    if (sl->chip_id == STM32_CHIPID_L1_MEDIUM)
    {
        /* erase each page */
        int i = 0, num_pages = sl->flash_size/sl->flash_pgsz;
        for (i = 0; i < num_pages; i++) {
            /* addr must be an addr inside the page */
            stm32_addr_t addr = sl->flash_base + i * sl->flash_pgsz;
            if (stlink_erase_flash_page(sl, addr) == -1) {
                WLOG("Failed to erase_flash_page(%#zx) == -1\n", addr);
                return -1;
            }
            fprintf(stdout,"\rFlash page at %5d/%5d erased", i, num_pages);
            fflush(stdout);
        }
        fprintf(stdout, "\n");
    }
    else
    {
        /* wait for ongoing op to finish */
        r = wait_flash_busy(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* unlock if locked */
        if (unlock_flash_if(sl) != 0)
        {
            return -1;
        }

        /* set the mass erase bit */
        r = set_flash_cr_mer(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* start erase operation, reset by hw with bsy bit */
        r = set_flash_cr_strt(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* wait for completion */
        r = wait_flash_busy_progress(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* relock the flash */
        r = lock_flash(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* todo: verify the erased memory */
    }
    return 0;
}

int
init_flash_loader(stlink_t *sl, flash_loader_t* fl) {
    size_t size;

    /* allocate the loader in sram */
    if (write_loader_to_sram(sl, &fl->loader_addr, &size) == -1) {
        WLOG("Failed to write flash loader to sram!\n");
        return -1;
    }

    /* allocate a one page buffer in sram right after loader */
    fl->buf_addr = fl->loader_addr + size;
    ILOG("Successfully loaded flash loader in sram\n");
    return 0;
}

static int
write_loader_to_sram(stlink_t *sl, stm32_addr_t* addr, size_t* size)
{
    st_error_t r;
    /* from openocd, contrib/loaders/flash/stm32.s */
    static const uint8_t loader_code_stm32vl[] = {
        0x08, 0x4c, /* ldr	r4, STM32_FLASH_BASE */
        0x1c, 0x44, /* add	r4, r3 */
        /* write_half_word: */
        0x01, 0x23, /* movs	r3, #0x01 */
        0x23, 0x61, /* str	r3, [r4, #STM32_FLASH_CR_OFFSET] */
        0x30, 0xf8, 0x02, 0x3b, /* ldrh	r3, [r0], #0x02 */
        0x21, 0xf8, 0x02, 0x3b, /* strh	r3, [r1], #0x02 */
        /* busy: */
        0xe3, 0x68, /* ldr	r3, [r4, #STM32_FLASH_SR_OFFSET] */
        0x13, 0xf0, 0x01, 0x0f, /* tst	r3, #0x01 */
        0xfb, 0xd0, /* beq	busy */
        0x13, 0xf0, 0x14, 0x0f, /* tst	r3, #0x14 */
        0x01, 0xd1, /* bne	exit */
        0x01, 0x3a, /* subs	r2, r2, #0x01 */
        0xf0, 0xd1, /* bne	write_half_word */
        /* exit: */
        0x00, 0xbe, /* bkpt	#0x00 */
        0x00, 0x20, 0x02, 0x40, /* STM32_FLASH_BASE: .word 0x40022000 */
    };

    /* flashloaders/stm32f0.s -- thumb1 only, same sequence as for STM32VL, bank ignored */
    static const uint8_t loader_code_stm32f0[] = {
#if 1
        /*
         * These two NOPs here are a safety precaution, added by Pekka Nikander
         * while debugging the STM32F05x support.  They may not be needed, but
         * there were strange problems with simpler programs, like a program
         * that had just a breakpoint or a program that first moved zero to register r2
         * and then had a breakpoint.  So, it appears safest to have these two nops.
         *
         * Feel free to remove them, if you dare, but then please do test the result
         * rigorously.  Also, if you remove these, it may be a good idea first to
         * #if 0 them out, with a comment when these were taken out, and to remove
         * these only a few months later...  But YMMV.
         */
        0x00, 0x30, //     nop     /* add r0,#0 */
        0x00, 0x30, //     nop     /* add r0,#0 */
#endif
        0x0A, 0x4C, //     ldr     r4, STM32_FLASH_BASE
        0x01, 0x25, //     mov     r5, #1            /*  FLASH_CR_PG, FLASH_SR_BUSY */
        0x04, 0x26, //     mov     r6, #4            /*  PGERR  */
                    // write_half_word:
        0x23, 0x69, //     ldr     r3, [r4, #16]     /*  FLASH->CR   */
        0x2B, 0x43, //     orr     r3, r5
        0x23, 0x61, //     str     r3, [r4, #16]     /*  FLASH->CR |= FLASH_CR_PG */
        0x03, 0x88, //     ldrh    r3, [r0]          /*  r3 = *sram */
        0x0B, 0x80, //     strh    r3, [r1]          /*  *flash = r3 */
                    // busy:
        0xE3, 0x68, //     ldr     r3, [r4, #12]     /*  FLASH->SR  */
        0x2B, 0x42, //     tst     r3, r5            /*  FLASH_SR_BUSY  */
        0xFC, 0xD0, //     beq     busy

        0x33, 0x42, //     tst     r3, r6            /*  PGERR  */
        0x04, 0xD1, //     bne     exit

        0x02, 0x30, //     add     r0, r0, #2        /*  sram += 2  */
        0x02, 0x31, //     add     r1, r1, #2        /*  flash += 2  */
        0x01, 0x3A, //     sub     r2, r2, #0x01     /*  count--  */
        0x00, 0x2A, //     cmp     r2, #0
        0xF0, 0xD1, //     bne     write_half_word
                    // exit:
        0x23, 0x69, //     ldr     r3, [r4, #16]     /*  FLASH->CR  */
        0xAB, 0x43, //     bic     r3, r5
        0x23, 0x61, //     str     r3, [r4, #16]     /*  FLASH->CR &= ~FLASH_CR_PG  */
        0x00, 0xBE, //     bkpt	#0x00
        0x00, 0x20, 0x02, 0x40, /* STM32_FLASH_BASE: .word 0x40022000 */
    };

    static const uint8_t loader_code_stm32l[] = {
        /* openocd.git/contrib/loaders/flash/stm32lx.S
           r0, input, dest addr
           r1, input, source addr
           r2, input, word count
           r3, output, word count
        */
        0x00, 0x23,
        0x04, 0xe0,

        0x51, 0xf8, 0x04, 0xcb,
        0x40, 0xf8, 0x04, 0xcb,
        0x01, 0x33,

        0x93, 0x42,
        0xf8, 0xd3,
        0x00, 0xbe
    };

    static const uint8_t loader_code_stm32f4[] = {
        // flashloaders/stm32f4.s
        0x07, 0x4b,

        0x62, 0xb1,
        0x04, 0x68,
        0x0c, 0x60,

        0xdc, 0x89,
        0x14, 0xf0, 0x01, 0x0f,
        0xfb, 0xd1,
        0x00, 0xf1, 0x04, 0x00,
        0x01, 0xf1, 0x04, 0x01,
        0xa2, 0xf1, 0x01, 0x02,
        0xf1, 0xe7,

        0x00, 0xbe,

        0x00, 0x3c, 0x02, 0x40,
    };

    const uint8_t* loader_code;
    size_t loader_size;

    if (sl->chip_id == STM32_CHIPID_L1_MEDIUM)
    {
        /* stm32l */
        loader_code = loader_code_stm32l;
        loader_size = sizeof(loader_code_stm32l);
    }
    else if (sl->core_id == STM32VL_CORE_ID ||
             sl->chip_id == STM32_CHIPID_F3  ||
             sl->chip_id == STM32_CHIPID_F37x)
    {
        loader_code = loader_code_stm32vl;
        loader_size = sizeof(loader_code_stm32vl);
    }
    else if (sl->chip_id == STM32_CHIPID_F2 ||
             sl->chip_id == STM32_CHIPID_F4)
    {
        loader_code = loader_code_stm32f4;
        loader_size = sizeof(loader_code_stm32f4);
    }
    else if (sl->chip_id == STM32_CHIPID_F0)
    {
        loader_code = loader_code_stm32f0;
        loader_size = sizeof(loader_code_stm32f0);
    }
    else
    {
        ELOG("unknown coreid, not sure what flash loader to use, aborting!: %x\n", sl->core_id);
        return -1;
    }

    memcpy(sl->q_buf, loader_code, loader_size);
    r = stlink_write_mem32(sl, sl->sram_base, loader_size);
    if (r != ST_SUCCESS)
    {
        ELOG("failed to write loader program\n");
        return -1;
    }

    *addr = sl->sram_base;
    *size = loader_size;

    return 0;
}

/**
 * Verify addr..addr+len is binary identical to base...base+len
 * @param sl stlink context
 * @param address stm device address
 * @param data host side buffer to check against
 * @param length how much
 * @return 0 for success, -ve for failure
 */
int
stlink_verify_write_flash(stlink_t *sl, stm32_addr_t address, uint8_t *data, unsigned length)
{
    st_error_t r;
    size_t off;
    size_t cmp_size = (sl->flash_pgsz > 0x1800) ? 0x1800 : sl->flash_pgsz;
    ILOG("Starting verification of write complete\n");
    for (off = 0; off < length; off += cmp_size)
    {
        size_t aligned_size;

        /* adjust last page size */
        if ((off + cmp_size) > length)
        {
            cmp_size = length - off;
        }

        aligned_size = cmp_size;
        if (aligned_size & (4 - 1))
        {
            aligned_size = (cmp_size + 4) & ~(4 - 1);
        }

        r = stlink_read_mem32(sl, address + off, aligned_size);
        if (r != ST_SUCCESS)
        {
            ELOG("Error reading memory during verification: %zd\n", off);
            return -1;
        }

        if (memcmp(sl->q_buf, data + off, cmp_size)) {
            ELOG("Verification of flash failed at offset: %zd\n", off);
            return -1;
        }
    }
    ILOG("Flash written and verified! jolly good!\n");
    return 0;

}

int
stm32l1_write_half_pages(stlink_t *sl, stm32_addr_t addr, uint8_t* base, unsigned num_half_pages)
{
    unsigned int count;
    uint32_t val;
    flash_loader_t fl;
    st_error_t r;
    ILOG("Starting Half page flash write for STM32L core id\n");
    /* flash loader initialization */
    if (init_flash_loader(sl, &fl) == -1) {
        WLOG("init_flash_loader() == -1\n");
        return -1;
    }
    /* Unlock already done */
    r = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
    val |= (1 << FLASH_L1_FPRG);
    r = stlink_write_debug32(sl, STM32L_FLASH_PECR, val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    val |= (1 << FLASH_L1_PROG);
    r = stlink_write_debug32(sl, STM32L_FLASH_PECR, val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
    for (;;)
    {
        r = stlink_read_debug32(sl, STM32L_FLASH_SR, &val);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        if ((val & (1 << 0)) == 0)
        {
            break;
        }
    }

#define L1_WRITE_BLOCK_SIZE 0x80
    for (count = 0; count  < num_half_pages; count ++) {
        if (run_flash_loader(sl, &fl, addr + count * L1_WRITE_BLOCK_SIZE, base + count * L1_WRITE_BLOCK_SIZE, L1_WRITE_BLOCK_SIZE) == -1) {
            WLOG("l1_run_flash_loader(%#zx) failed! == -1\n", addr + count * L1_WRITE_BLOCK_SIZE);
            r = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
            if (r != ST_SUCCESS)
            {
                return -1;
            }
            val &= ~((1 << FLASH_L1_FPRG) |(1 << FLASH_L1_PROG));
            r = stlink_write_debug32(sl, STM32L_FLASH_PECR, val);
            if (r != ST_SUCCESS)
            {
                return -1;
            }
            return -1;
        }
        /* wait for sr.busy to be cleared */
        if (sl->verbose >= 1) {
            /* show progress. writing procedure is slow
               and previous errors are misleading */
            fprintf(stdout, "\r%3u/%u halfpages written", count + 1, num_half_pages);
            fflush(stdout);
        }
        for (;;)
        {
            r = stlink_read_debug32(sl, STM32L_FLASH_SR, &val);
            if (r != ST_SUCCESS)
            {
                return -1;
            }
            if ((val & (1 << 0)) == 0)
            {
                break;
            }
        }
    }
    r = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
    val &= ~(1 << FLASH_L1_PROG);
    r = stlink_write_debug32(sl, STM32L_FLASH_PECR, val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
    r = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }
    val &= ~(1 << FLASH_L1_FPRG);
    r = stlink_write_debug32(sl, STM32L_FLASH_PECR, val);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

    return 0;
}

int
stlink_write_flash(stlink_t *sl, stm32_addr_t addr, uint8_t* base, unsigned len)
{
    st_error_t r;
    size_t off;
    flash_loader_t fl;

    ILOG("Attempting to write %d (%#x) bytes to stm32 address: %u (%#x)\n", len, len, addr, addr);
    /* check addr range is inside the flash */
    stlink_calculate_pagesize(sl, addr);

    if (addr < sl->flash_base)
    {
        ELOG("addr too low %#x < %#x\n", addr, sl->flash_base);
        return -1;
    }
    else if ((addr + len) < addr)
    {
        ELOG("addr overruns\n");
        return -1;
    }
    else if ((addr + len) > (sl->flash_base + sl->flash_size))
    {
        ELOG("addr too high\n");
        return -1;
    }
    else if (addr & 1)
    {
        ELOG("unaligned addr 0x%x\n", addr);
        return -1;
    }
    else if (len & 1)
    {
        WLOG("unaligned len 0x%x -- padding with zero\n", len);
        len += 1;
    }
    else if (addr & (sl->flash_pgsz - 1))
    {
        ELOG("addr not a multiple of pagesize, not supported\n");
        return -1;
    }

    // Make sure we've loaded the context with the chip details
    r = stlink_core_id(sl, NULL);
    if (r != ST_SUCCESS)
    {
        ELOG("Unable to load core details");
        return -1;
    }

    /* erase each page */
    int page_count = 0;
    for (off = 0; off < len; off += stlink_calculate_pagesize(sl, addr + off))
    {
        /* addr must be an addr inside the page */
        if (stlink_erase_flash_page(sl, addr + off) == -1)
        {
            ELOG("Failed to erase_flash_page(%#zx) == -1\n", addr + off);
            return -1;
        }
        fprintf(stdout,"\rFlash page at addr: 0x%08lx erased", (unsigned long)addr + off);
        fflush(stdout);
        page_count++;
    }
    fprintf(stdout,"\n");

    ILOG("Finished erasing %d pages of %d (%#x) bytes\n", page_count, sl->flash_pgsz, sl->flash_pgsz);

    if ((sl->chip_id == STM32_CHIPID_F2) || (sl->chip_id == STM32_CHIPID_F4))
    {
        /* todo: check write operation */
        ILOG("Starting Flash write for F2/F4\n");
        /* flash loader initialization */
        if (init_flash_loader(sl, &fl) == -1)
        {
            ELOG("init_flash_loader() == -1\n");
            return -1;
        }

        /* First unlock the cr */
        if (unlock_flash_if(sl) != 0)
        {
            return -1;
        }

        /* TODO: Check that Voltage range is 2.7 - 3.6 V */
        /* set parallelisim to 32 bit*/
        r = write_flash_cr_psiz(sl, 2);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* set programming mode */
        r = set_flash_cr_pg(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        for (off = 0; off < len;)
        {
            size_t size = len - off > 0x8000 ? 0x8000 : len - off;

            printf("size: %zu\n", size);

            if (run_flash_loader(sl, &fl, addr + off, base + off, size) == -1)
            {
                ELOG("run_flash_loader(%#zx) failed! == -1\n", addr + off);
                return -1;
            }

            off += size;
        }

        /* Relock flash */
        r = lock_flash(sl);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        /* STM32F4END */
    }
    else if (sl->chip_id == STM32_CHIPID_L1_MEDIUM)
    {
        /* use fast word write. todo: half page. */
        uint32_t val;

#if 0 /* todo: check write operation */
        uint32_t nwrites = sl->flash_pgsz;
    redo_write:
#endif /* todo: check write operation */

       /* disable pecr protection */
        r = stlink_write_debug32(sl, STM32L_FLASH_PEKEYR, 0x89abcdef);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        r = stlink_write_debug32(sl, STM32L_FLASH_PEKEYR, 0x02030405);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* check pecr.pelock is cleared */
        r = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        if (val & (1 << 0))
        {
            fprintf(stderr, "pecr.pelock not clear\n");
            return -1;
        }

        /* unlock program memory */
        r = stlink_write_debug32(sl, STM32L_FLASH_PRGKEYR, 0x8c9daebf);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        r = stlink_write_debug32(sl, STM32L_FLASH_PRGKEYR, 0x13141516);
        if (r != ST_SUCCESS)
        {
            return -1;
        }

        /* check pecr.prglock is cleared */
        r = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        if (val & (1 << 1))
        {
            fprintf(stderr, "pecr.prglock not clear\n");
            return -1;
        }

        off = 0;
        if (len > L1_WRITE_BLOCK_SIZE)
        {
            if (stm32l1_write_half_pages(sl, addr, base, len/L1_WRITE_BLOCK_SIZE) == -1)
            {
                /* This may happen on a blank device! */
                WLOG("\nwrite_half_pages failed == -1\n");
            }
            else
            {
                off = (len /L1_WRITE_BLOCK_SIZE)*L1_WRITE_BLOCK_SIZE;
            }
        }

        /* write remainingword in program memory */
        for ( ; off < len; off += sizeof(uint32_t))
        {
            uint32_t data;
            if (off > 254)
            {
                fprintf(stdout, "\r");
            }

            if ((off % sl->flash_pgsz) > (sl->flash_pgsz -5))
            {
                fprintf(stdout, "\r%3zd/%3zd pages written",
                        off/sl->flash_pgsz, len/sl->flash_pgsz);
                fflush(stdout);
            }

            write_uint32((unsigned char*) &data, *(uint32_t*) (base + off));
            stlink_write_debug32(sl, addr + off, data);

            /* wait for sr.busy to be cleared */
            for (;;)
            {
                r = stlink_read_debug32(sl, STM32L_FLASH_SR, &val);
                if (r != ST_SUCCESS)
                {
                    return -1;
                }
                if ((val & (1 << 0)) == 0)
                {
                    break;
                }
            }

#if 0 /* todo: check redo write operation */
            /* check written bytes. todo: should be on a per page basis. */
            data = stlink_read_debug32(sl, addr + off);
            if (data == *(uint32_t*)(base + off)) {
                /* re erase the page and redo the write operation */
                uint32_t page;
                uint32_t val;

                /* fail if successive write count too low */
                if (nwrites < sl->flash_pgsz) {
                    fprintf(stderr, "writes operation failure count too high, aborting\n");
                    return -1;
                }

                nwrites = 0;

                /* assume addr aligned */
                if (off % sl->flash_pgsz) off &= ~(sl->flash_pgsz - 1);
                page = addr + off;

                fprintf(stderr, "invalid write @0x%x(0x%x): 0x%x != 0x%x. retrying.\n",
                        page, addr + off, read_uint32(base + off, 0), read_uint32(sl->q_buf, 0));

                /* reset lock bits */
                val = stlink_read_debug32(sl, STM32L_FLASH_PECR)
                    | (1 << 0) | (1 << 1) | (1 << 2);
                stlink_write_debug32(sl, STM32L_FLASH_PECR, val);

                stlink_erase_flash_page(sl, page);

                goto redo_write;
            }

            /* increment successive writes counter */
            ++nwrites;

#endif /* todo: check redo write operation */
        }
        fprintf(stdout, "\n");
        /* reset lock bits */
        r = stlink_read_debug32(sl, STM32L_FLASH_PECR, &val);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        val = val | (1 << 0) | (1 << 1) | (1 << 2);
        r = stlink_write_debug32(sl, STM32L_FLASH_PECR, val);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
    }
    else if (sl->core_id == STM32VL_CORE_ID ||
             sl->core_id == STM32F0_CORE_ID ||
             sl->chip_id == STM32_CHIPID_F3  ||
             sl->chip_id == STM32_CHIPID_F37x) {
        ILOG("Starting Flash write for VL/F0 core id\n");
        /* flash loader initialization */
        if (init_flash_loader(sl, &fl) == -1) {
            ELOG("init_flash_loader() == -1\n");
            return -1;
        }

        int write_block_count = 0;
        for (off = 0; off < len; off += sl->flash_pgsz) {
            /* adjust last write size */
            size_t size = sl->flash_pgsz;
            if ((off + sl->flash_pgsz) > len) size = len - off;

            /* unlock and set programming mode */
            if (unlock_flash_if(sl) != 0)
            {
                return -1;
            }

            r = set_flash_cr_pg(sl);
            if (r != ST_SUCCESS)
            {
                return -1;
            }
            //DLOG("Finished setting flash cr pg, running loader!\n");
            if (run_flash_loader(sl, &fl, addr + off, base + off, size) == -1) {
                ELOG("run_flash_loader(%#zx) failed! == -1\n", addr + off);
                return -1;
            }
            r = lock_flash(sl);
            if (r != ST_SUCCESS)
            {
                return -1;
            }
            if (sl->verbose >= 1) {
                /* show progress. writing procedure is slow
                   and previous errors are misleading */
                fprintf(stdout, "\r%3u/%lu pages written", write_block_count++, (unsigned long)len/sl->flash_pgsz);
                fflush(stdout);
            }
        }
        fprintf(stdout, "\n");
    }
    else
    {
        ELOG("unknown coreid, not sure how to write: %x\n", sl->core_id);
        return -1;
    }

    return stlink_verify_write_flash(sl, addr, base, len);
}

/**
 * Write the given binary file into flash at address "addr"
 * @param sl
 * @param path readable file path, should be binary image
 * @param addr where to start writing
 * @return 0 on success, -ve on failure.
 */
int
stlink_fwrite_flash(stlink_t *sl, const char* path, stm32_addr_t addr)
{
    /* write the file in flash at addr */
    st_error_t r;
    int err = -1;
    unsigned int num_empty = 0, index;
    unsigned char erased_pattern = (sl->chip_id == STM32_CHIPID_L1_MEDIUM) ? 0 : 0xff;
    mapped_file_t mf = MAPPED_FILE_INITIALIZER;
    uint32_t sp, pc;

    if (stlink_map_file(&mf, path) == -1)
    {
        ELOG("stlink_map_file() == -1\n");
        return -1;
    }

    for (index = 0; index < mf.len; index ++)
    {
        if (mf.base[index] == erased_pattern)
        {
            num_empty++;
        }
        else
        {
            num_empty = 0;
        }
    }

    if (num_empty != 0)
    {
        ILOG("Ignoring %d bytes of Zeros at end of file\n",num_empty);
        mf.len -= num_empty;
    }

    err = stlink_write_flash(sl, addr, mf.base, mf.len);

    /* set stack*/
    r = stlink_read_debug32(sl, addr, &sp);
    if (r != ST_SUCCESS)
    {
        goto on_error;
    }
    r = stlink_write_reg(sl, sp, 13);
    if (r != ST_SUCCESS)
    {
        goto on_error;
    }

    /* Set PC to the reset routine*/
    r = stlink_read_debug32(sl, addr + 4, &pc);
    if (r != ST_SUCCESS)
    {
        goto on_error;
    }
    r = stlink_write_reg(sl, pc, 15);
    if (r != ST_SUCCESS)
    {
        goto on_error;
    }

    r = stlink_run(sl);
    if (r != ST_SUCCESS)
    {
        goto on_error;
    }

    err = 0;
on_error:
    stlink_unmap_file(&mf);
    return err;
}

static int
run_flash_loader(stlink_t *sl, flash_loader_t* fl, stm32_addr_t target, const uint8_t* buf, size_t size)
{
    st_error_t r;
    reg rr;
    int i = 0;

    DLOG("Running flash loader, write address:%#x, size: %zd\n", target, size);

    if (write_buffer_to_sram(sl, fl, buf, size) == -1)
    {
        ELOG("write_buffer_to_sram() == -1\n");
        return -1;
    }

    if (sl->chip_id == STM32_CHIPID_L1_MEDIUM)
    {
        size_t count = size / sizeof(uint32_t);
        if (size % sizeof(uint32_t))
        {
            ++count;
        }

        /* setup core */
        stlink_write_reg(sl, target, 0); /* target */
        stlink_write_reg(sl, fl->buf_addr, 1); /* source */
        stlink_write_reg(sl, count, 2); /* count (32 bits words) */
        stlink_write_reg(sl, fl->loader_addr, 15); /* pc register */

    }
    else if (sl->core_id == STM32VL_CORE_ID ||
             sl->core_id == STM32F0_CORE_ID ||
             sl->chip_id == STM32_CHIPID_F3 ||
             sl->chip_id == STM32_CHIPID_F37x)
    {
        size_t count = size / sizeof(uint16_t);
        if (size % sizeof(uint16_t))
        {
            ++count;
        }

        /* setup core */
        stlink_write_reg(sl, fl->buf_addr, 0); /* source */
        stlink_write_reg(sl, target, 1); /* target */
        stlink_write_reg(sl, count, 2); /* count (16 bits half words) */
        stlink_write_reg(sl, 0, 3); /* flash bank 0 (input) */
        stlink_write_reg(sl, fl->loader_addr, 15); /* pc register */

    }
    else if (sl->chip_id == STM32_CHIPID_F2 ||
             sl->chip_id == STM32_CHIPID_F4)
    {

        size_t count = size / sizeof(uint32_t);
        if (size % sizeof(uint32_t))
        {
            ++count;
        }

        /* setup core */
        stlink_write_reg(sl, fl->buf_addr, 0); /* source */
        stlink_write_reg(sl, target, 1); /* target */
        stlink_write_reg(sl, count, 2); /* count (32 bits words) */
        stlink_write_reg(sl, fl->loader_addr, 15); /* pc register */
    }
    else
    {
        fprintf(stderr, "unknown coreid 0x%x, don't know what flash loader to use\n", sl->core_id);
        return -1;
    }

    /* run loader */
    r = stlink_run(sl);
    if (r != ST_SUCCESS)
    {
        return -1;
    }

#define WAIT_ROUNDS 1000
    /* wait until done (reaches breakpoint) */
    for (i = 0; i < WAIT_ROUNDS; i++) {
        bool halted;
        r = stlink_is_core_halted(sl, &halted);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
        if (halted)
        {
            break;
        }
    }

    if (i >= WAIT_ROUNDS) {
        fprintf(stderr, "flash loader run error\n");
        return -1;
    }

    /* check written byte count */
    if (sl->chip_id == STM32_CHIPID_L1_MEDIUM)
    {
        size_t count = size / sizeof(uint32_t);
        if (size % sizeof(uint32_t))
        {
            ++count;
        }

        stlink_read_reg(sl, 3, &rr);
        if (rr.r[3] != count) {
            fprintf(stderr, "write error, count == %u\n", rr.r[3]);
            return -1;
        }

    }
    else if (sl->core_id == STM32VL_CORE_ID ||
             sl->core_id == STM32F0_CORE_ID ||
             sl->chip_id == STM32_CHIPID_F3  ||
             sl->chip_id == STM32_CHIPID_F37x)
    {
        stlink_read_reg(sl, 2, &rr);
        if (rr.r[2] != 0)
        {
            fprintf(stderr, "write error, count == %u\n", rr.r[2]);
            return -1;
        }
    }
    else if (sl->chip_id == STM32_CHIPID_F2 ||
             sl->chip_id == STM32_CHIPID_F4)
    {
        stlink_read_reg(sl, 2, &rr);
        if (rr.r[2] != 0)
        {
            fprintf(stderr, "write error, count == %u\n", rr.r[2]);
            return -1;
        }
    }
    else
    {
      fprintf(stderr, "unknown coreid 0x%x, can't check written byte count\n", sl->core_id);
      return -1;
    }

    return 0;
}

static int
write_buffer_to_sram(stlink_t *sl, flash_loader_t* fl, const uint8_t* buf, size_t size)
{
    /* write the buffer right after the loader */
    st_error_t r;
    size_t chunk = size & ~0x3;
    size_t rem  = size & 0x3;

    if (chunk)
    {
        memcpy(sl->q_buf, buf, chunk);
        r = stlink_write_mem32(sl, fl->buf_addr, chunk);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
    }

    if (rem)
    {
        memcpy(sl->q_buf, buf+chunk, rem);
        r = stlink_write_mem8(sl, (fl->buf_addr) + chunk, rem);
        if (r != ST_SUCCESS)
        {
            return -1;
        }
    }

    return 0;
}
