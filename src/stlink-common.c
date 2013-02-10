#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "stlink-common.h"
#define LOG_TAG __FILE__
#include "uglylogging.h"

/*
 * Endianness
 * http://www.ibm.com/developerworks/aix/library/au-endianc/index.html
 * const int i = 1;
 * #define is_bigendian() ( (*(char*)&i) == 0 )
 */
static inline unsigned int is_bigendian(void)
{
    static volatile const unsigned int i = 1;
    return *(volatile const char*) &i == 0;
}

void
write_uint32(unsigned char *buf, uint32_t ui)
{
/* le -> le (don't swap) */
    if (!is_bigendian())
    {
        buf[0] = ((unsigned char*) &ui)[0];
        buf[1] = ((unsigned char*) &ui)[1];
        buf[2] = ((unsigned char*) &ui)[2];
        buf[3] = ((unsigned char*) &ui)[3];
    }
    else
    {
        buf[0] = ((unsigned char*) &ui)[3];
        buf[1] = ((unsigned char*) &ui)[2];
        buf[2] = ((unsigned char*) &ui)[1];
        buf[3] = ((unsigned char*) &ui)[0];
    }
}

void
write_uint16(unsigned char *buf, uint16_t ui)
{
    /* le -> le (don't swap) */
    if (!is_bigendian())
    {
        buf[0] = ((unsigned char*) &ui)[0];
        buf[1] = ((unsigned char*) &ui)[1];
    }
    else
    {
        buf[0] = ((unsigned char*) &ui)[1];
        buf[1] = ((unsigned char*) &ui)[0];
    }
}

uint32_t
read_uint32(const unsigned char *c, const int pt)
{
    uint32_t ui;
    char *p = (char *) &ui;

    /* le -> le (don't swap) */
    if (!is_bigendian())
    {
        p[0] = c[pt + 0];
        p[1] = c[pt + 1];
        p[2] = c[pt + 2];
        p[3] = c[pt + 3];
    }
    else
    {
        p[0] = c[pt + 3];
        p[1] = c[pt + 2];
        p[2] = c[pt + 1];
        p[3] = c[pt + 0];
    }

    return ui;
}

uint16_t
read_uint16(const unsigned char *c, const int pt)
{
    uint32_t ui;
    char *p = (char *) &ui;

    /* le -> le (don't swap)*/
    if (!is_bigendian())
    {
        p[0] = c[pt + 0];
        p[1] = c[pt + 1];
    }
    else
    {
        p[0] = c[pt + 1];
        p[1] = c[pt + 0];
    }
    return ui;
}

/* Delegates to the backends... */
st_error_t
stlink_close(stlink_t *sl)
{
    st_error_t r;
    DLOG("*** stlink_close ***\n");
    r = sl->backend->close(sl);
    free(sl);
    return r;
}

st_error_t
stlink_exit_debug_mode(stlink_t *sl)
{
    st_error_t r;
    DLOG("*** stlink_exit_debug_mode ***\n");
    r = stlink_write_debug32(sl, DHCSR, DBGKEY);
    if (r != ST_SUCCESS)
    {
        return r;
    }
    return sl->backend->exit_debug_mode(sl);
}

st_error_t
stlink_enter_swd_mode(stlink_t *sl)
{
    DLOG("*** stlink_enter_swd_mode ***\n");
    return sl->backend->enter_swd_mode(sl);
}

/* Force the core into the debug mode -> halted state. */
st_error_t
stlink_force_debug_raw(stlink_t *sl)
{
    DLOG("*** stlink_force_debug_mode ***\n");
    return sl->backend->force_debug(sl);
}

/*
 * Force the core in to halted state. Check that it is actually
 * halted by reading the status.
 */
st_error_t
stlink_force_debug(stlink_t *sl)
{
    st_error_t r;
    uint16_t status;

    r = stlink_force_debug_raw(sl);
    if (r != ST_SUCCESS)
    {
        return r;
    }

    r = stlink_status(sl, &status);
    if (r != ST_SUCCESS)
    {
        return r;
    }

    if (status == STLINK_CORE_HALTED)
    {
        return ST_SUCCESS;
    }
    else
    {
        return ST_FAIL;
    }
}

st_error_t
stlink_force_debug_retry(stlink_t *sl, int num_retries)
{
    st_error_t r;
    int i;

    for (i = 0; i < num_retries; i++)
    {
        r = stlink_force_debug(sl);
        if (r != ST_FAIL)
        {
            return r;
        }
        usleep(1000000);
    }

    return ST_MAX_RETRIES;
}

st_error_t
stlink_exit_dfu_mode(stlink_t *sl)
{
    DLOG("*** stlink_exit_dfu_mode ***\n");
    return sl->backend->exit_dfu_mode(sl);
}

st_error_t
stlink_core_id(stlink_t *sl, uint32_t *core_id)
{
    st_error_t r;
    DLOG("*** stlink_core_id ***\n");
    r = sl->backend->core_id(sl);
    if (r != ST_SUCCESS)
    {
        return r;
    }
    if (sl->verbose > 2)
    {
        stlink_print_data(sl);
    }
    DLOG("core_id = 0x%08x\n", sl->core_id);
    if (core_id != NULL)
    {
        *core_id = sl->core_id;
    }
    return ST_SUCCESS;
}

st_error_t
stlink_chip_id(stlink_t *sl, uint32_t *chip_id)
{
    st_error_t r = stlink_read_debug32(sl, 0xE0042000, chip_id);
    if (r != ST_SUCCESS)
    {
        /* Try Corex M0 DBGMCU_IDCODE register address */
        r = stlink_read_debug32(sl, 0x40015800, chip_id);
    }

    return r;
}

/**
 * Cortex m3 tech ref manual, CPUID register description
 */
st_error_t
stlink_cpu_id(stlink_t *sl, cortex_m3_cpuid_t *cpuid)
{
    uint32_t raw;
    st_error_t r;
    r = stlink_read_debug32(sl, CM3_REG_CPUID, &raw);
    if (r != ST_SUCCESS)
    {
        return r;
    }

    cpuid->implementer_id = (raw >> 24) & 0x7f;
    cpuid->variant = (raw >> 20) & 0xf;
    cpuid->part = (raw >> 4) & 0xfff;
    cpuid->revision = raw & 0xf;

    return ST_SUCCESS;
}

/**
 * reads and decodes the flash parameters, as dynamically as possible
 * @param sl
 * @return 0 for success, or -1 for unsupported core type.
 */
st_error_t
stlink_load_device_params(stlink_t *sl)
{
    st_error_t r;
    const chip_params_t *params = NULL;
    uint32_t chip_id;

    ILOG("Loading device parameters....\n");

    r = stlink_core_id(sl, &sl->core_id);
    if (r != ST_SUCCESS)
    {
        printf("Unable to read core id\n");
        return r;
    }

    r = stlink_chip_id(sl, &chip_id);
    if (r != ST_SUCCESS)
    {
        printf("Unable to read chip id\n");
        return r;
    }

    sl->chip_id = chip_id & 0xfff;

    /* Fix chip_id for F4 rev A errata , Read CPU ID, as CoreID is the same for F2/F4*/
    if (sl->chip_id == 0x411) {
        uint32_t cpuid;
        r = stlink_read_debug32(sl, 0xE000ED00, &cpuid);
        if (r != ST_SUCCESS)
        {
            return r;
        }
        if ((cpuid  & 0xfff0) == 0xc240)
        {
            sl->chip_id = 0x413;
        }
    }

    for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
        if (devices[i].chip_id == sl->chip_id) {
            params = &devices[i];
            break;
        }
    }
    if (params == NULL) {
        WLOG("unknown chip id! %#x\n", chip_id);
        return ST_UNSUPPORTED_CHIP;
    }

    /* These are fixed... */
    sl->flash_base = STM32_FLASH_BASE;
    sl->sram_base = STM32_SRAM_BASE;

    /* read flash size from hardware, if possible... */
    uint32_t flash_size_kb;
    if (sl->chip_id == STM32_CHIPID_F2)
    {
        flash_size_kb = 1024;
    }
    else if (sl->chip_id == STM32_CHIPID_F4)
    {
        /* todo: RM0090 error; size register same address as unique ID */
        flash_size_kb = 1024;
    } else {
        r = stlink_read_debug32(sl, params->flash_size_reg, &flash_size_kb);
        if (r != ST_SUCCESS)
        {
            return r;
        }
        flash_size_kb &= 0xffff;
    }
    sl->flash_size = flash_size_kb * 1024;

    sl->flash_pgsz = params->flash_pagesize;
    sl->sram_size = params->sram_size;
    sl->sys_base = params->bootrom_base;
    sl->sys_size = params->bootrom_size;

    ILOG("Device connected is: %s, id %#x\n", params->description, chip_id);
    /* TODO make note of variable page size here..... */
    ILOG("SRAM size: %#x bytes (%d KiB), Flash: %#x bytes (%d KiB) in pages of %zd bytes\n",
        sl->sram_size, sl->sram_size / 1024, sl->flash_size, sl->flash_size / 1024,
        sl->flash_pgsz);
    return ST_SUCCESS;
}

st_error_t
stlink_reset(stlink_t *sl)
{
    DLOG("*** stlink_reset ***\n");
    return sl->backend->reset(sl);
}

/* stlink_reset_retry, will try num_retries to reset
the device. reties only occur in case of a real failure.
protocol errors will immediately return an error.
if not successful within num_retries, ST_MAX_RETRIES is
returned.
*/
st_error_t
stlink_reset_retry(stlink_t *sl, int num_retries)
{
    st_error_t r;
    int i;

    for (i = 0; i < num_retries; i++)
    {
        r = stlink_reset(sl);
        if (r != ST_FAIL)
        {
            return r;
        }
        usleep(1000000);
    }

    return ST_MAX_RETRIES;
}

st_error_t
stlink_jtag_reset(stlink_t *sl, int value)
{
    DLOG("*** stlink_jtag_reset ***\n");
    return sl->backend->jtag_reset(sl, value);
}

st_error_t
stlink_run(stlink_t *sl)
{
    DLOG("*** stlink_run ***\n");
    return sl->backend->run(sl);
}

st_error_t
stlink_status(stlink_t *sl, uint16_t *_status)
{
    st_error_t r;
    uint16_t status;
    DLOG("*** stlink_status ***\n");
    r = sl->backend->status(sl, &status);
    if (r != ST_SUCCESS)
    {
        return r;
    }

    sl->core_stat = status;

    switch (status)
    {
    case STLINK_CORE_RUNNING:
        DLOG("  core status: running\n");
        break;
    case STLINK_CORE_HALTED:
        DLOG("  core status: halted\n");
        break;
    default:
        fprintf(stderr, "  core status: unknown\n");
    }

    if (_status != NULL)
    {
        *_status = status;
    }
    return ST_SUCCESS;
}

/**
 * Decode the version bits, originally from -sg, verified with usb
 * @param sl stlink context, assumed to contain valid data in the buffer
 * @param slv output parsed version object
 */
static void
parse_version(stlink_t *sl, stlink_version_t *slv)
{
    uint32_t b0 = sl->q_buf[0]; //lsb
    uint32_t b1 = sl->q_buf[1];
    uint32_t b2 = sl->q_buf[2];
    uint32_t b3 = sl->q_buf[3];
    uint32_t b4 = sl->q_buf[4];
    uint32_t b5 = sl->q_buf[5]; //msb

    // b0 b1                       || b2 b3  | b4 b5
    // 4b        | 6b     | 6b     || 2B     | 2B
    // stlink_v  | jtag_v | swim_v || st_vid | stlink_pid

    slv->stlink_v = (b0 & 0xf0) >> 4;
    slv->jtag_v = ((b0 & 0x0f) << 2) | ((b1 & 0xc0) >> 6);
    slv->swim_v = b1 & 0x3f;
    slv->st_vid = (b3 << 8) | b2;
    slv->stlink_pid = (b5 << 8) | b4;
}

st_error_t
stlink_version(stlink_t *sl)
{
    st_error_t r;
    DLOG("*** looking up stlink version\n");
    r = sl->backend->version(sl);
    if (r != ST_SUCCESS)
    {
        return r;
    }
    parse_version(sl, &sl->version);

    DLOG("st vid         = 0x%04x (expect 0x%04x)\n", sl->version.st_vid, USB_ST_VID);
    DLOG("stlink pid     = 0x%04x\n", sl->version.stlink_pid);
    DLOG("stlink version = 0x%x\n", sl->version.stlink_v);
    DLOG("jtag version   = 0x%x\n", sl->version.jtag_v);
    DLOG("swim version   = 0x%x\n", sl->version.swim_v);
    if (sl->version.jtag_v == 0) {
        DLOG("    notice: the firmware doesn't support a jtag/swd interface\n");
    }
    if (sl->version.swim_v == 0) {
        DLOG("    notice: the firmware doesn't support a swim interface\n");
    }

    return ST_SUCCESS;
}

st_error_t
stlink_read_debug32(stlink_t *sl, uint32_t addr, uint32_t *val)
{
    DLOG("*** stlink_read_debug32 %x\n", addr);
    return sl->backend->read_debug32(sl, addr, val);
}

st_error_t
stlink_write_debug32(stlink_t *sl, uint32_t addr, uint32_t data)
{
    DLOG("*** stlink_write_debug32 %x to %#x\n", data, addr);
    return sl->backend->write_debug32(sl, addr, data);
}

st_error_t
stlink_write_mem32(stlink_t *sl, uint32_t addr, uint16_t len)
{
    DLOG("*** stlink_write_mem32 %u bytes to %#x\n", len, addr);
    if (len % 4 != 0)
    {
        fprintf(stderr, "Error: Data length doesn't have a 32 bit alignment: +%d byte.\n", len % 4);
        abort();
    }
    return sl->backend->write_mem32(sl, addr, len);
}

st_error_t
stlink_read_mem32(stlink_t *sl, uint32_t addr, uint16_t len)
{
    DLOG("*** stlink_read_mem32: 0x%08" PRIx32 ":%" PRId16 " ***\n", addr, len);
    if (len % 4 != 0)
    {
        /* !!! never ever: fw gives just wrong values */
        fprintf(stderr, "Error: Data length doesn't have a 32 bit alignment: +%d byte.\n",
                len % 4);
        abort();
    }
    return sl->backend->read_mem32(sl, addr, len);
}

st_error_t
stlink_write_mem8(stlink_t *sl, uint32_t addr, uint16_t len)
{
    DLOG("*** stlink_write_mem8 ***\n");
    if (len > 0x40)
    {
        /* !!! never ever: Writing more then 0x40 bytes gives unexpected behaviour */
        fprintf(stderr, "Error: Data length > 64: +%d byte.\n",
                len);
        abort();
    }
    return sl->backend->write_mem8(sl, addr, len);
}

st_error_t
stlink_read_all_regs(stlink_t *sl, reg *regp)
{
    DLOG("*** stlink_read_all_regs ***\n");
    return sl->backend->read_all_regs(sl, regp);
}

st_error_t
stlink_read_all_unsupported_regs(stlink_t *sl, reg *regp)
{
    DLOG("*** stlink_read_all_unsupported_regs ***\n");
    return sl->backend->read_all_unsupported_regs(sl, regp);
}

st_error_t
stlink_write_reg(stlink_t *sl, uint32_t reg, int idx)
{
    DLOG("*** stlink_write_reg\n");
    return sl->backend->write_reg(sl, reg, idx);
}

st_error_t
stlink_read_reg(stlink_t *sl, int r_idx, reg *regp)
{
    DLOG("*** stlink_read_reg\n");
    DLOG(" (%d) ***\n", r_idx);

    if (r_idx > 20 || r_idx < 0) {
        fprintf(stderr, "Error: register index must be in [0..20]\n");
        abort();
    }

    return sl->backend->read_reg(sl, r_idx, regp);
}

st_error_t
stlink_read_unsupported_reg(stlink_t *sl, int r_idx, reg *regp)
{
    int r_convert;

    DLOG("*** stlink_read_unsupported_reg\n");
    DLOG(" (%d) ***\n", r_idx);

    /* Convert to values used by DCRSR */
    if (r_idx >= 0x1C && r_idx <= 0x1F)
    {
        /* primask, basepri, faultmask, or control */
        r_convert = 0x14;
    }
    else if (r_idx == 0x40)
    {
        /* FPSCR */
        r_convert = 0x21;
    }
    else if (r_idx >= 0x20 && r_idx < 0x40)
    {
        r_convert = 0x40 + (r_idx - 0x20);
    }
    else
    {
        fprintf(stderr, "Error: register address must be in [0x1C..0x40]\n");
        abort();
    }

    return sl->backend->read_unsupported_reg(sl, r_convert, regp);
}

st_error_t
stlink_write_unsupported_reg(stlink_t *sl, uint32_t val, int r_idx, reg *regp)
{
    int r_convert;

    DLOG("*** stlink_write_unsupported_reg\n");
    DLOG(" (%d) ***\n", r_idx);

    /* Convert to values used by DCRSR */
    if (r_idx >= 0x1C && r_idx <= 0x1F)
    {
        /* primask, basepri, faultmask, or control */
        r_convert = r_idx;  /* The backend function handles this */
    }
    else if (r_idx == 0x40)
    {
        /* FPSCR */
        r_convert = 0x21;
    }
    else if (r_idx >= 0x20 && r_idx < 0x40)
    {
        r_convert = 0x40 + (r_idx - 0x20);
    }
    else
    {
        fprintf(stderr, "Error: register address must be in [0x1C..0x40]\n");
        abort();
    }

    return sl->backend->write_unsupported_reg(sl, val, r_convert, regp);
}

st_error_t
stlink_step(stlink_t *sl)
{
    DLOG("*** stlink_step ***\n");
    return sl->backend->step(sl);
}

st_error_t
stlink_current_mode(stlink_t *sl, uint8_t *mode)
{
    st_error_t r = sl->backend->current_mode(sl, mode);
    if (r != ST_SUCCESS)
    {
        return r;
    }

    switch (*mode)
    {
    case STLINK_DEV_DFU_MODE:
        DLOG("stlink current mode: dfu\n");
        break;
    case STLINK_DEV_DEBUG_MODE:
        DLOG("stlink current mode: debug (jtag or swd)\n");
        break;
    case STLINK_DEV_MASS_MODE:
        DLOG("stlink current mode: mass\n");
        break;
    default:
        DLOG("stlink mode: unknown!\n");
        *mode = STLINK_DEV_UNKNOWN_MODE;
    }

    return ST_SUCCESS;
}

st_error_t
stlink_is_core_halted(stlink_t *sl, bool *halted)
{
    st_error_t r;
    uint16_t status;
    /* return non zero if core is halted */
    r = stlink_status(sl, &status);
    if (r != ST_SUCCESS)
    {
        return r;
    }

    *halted = status == STLINK_CORE_HALTED;
    return ST_SUCCESS;
}

// same as above with entrypoint.
st_error_t
stlink_run_at(stlink_t *sl, stm32_addr_t addr)
{
    st_error_t r;
    r = stlink_write_reg(sl, addr, 15); /* pc register */
    if (r != ST_SUCCESS)
    {
        return r;
    }

    r = stlink_run(sl);
    if (r != ST_SUCCESS)
    {
        return r;
    }

    for (;;)
    {
        bool halted;
        r = stlink_is_core_halted(sl, &halted);
        if (r != ST_SUCCESS)
        {
            return r;
        }

        if (!halted)
        {
            break;
        }

        usleep(3000000);
    }

    return ST_SUCCESS;
}

void
stlink_print_data(stlink_t * sl)
{
    if (sl->q_len <= 0 || sl->verbose < UDEBUG)
    {
        return;
    }

    if (sl->verbose > 2)
    {
        fprintf(stdout, "data_len = %d 0x%x\n", sl->q_len, sl->q_len);
    }

    for (int i = 0; i < sl->q_len; i++)
    {
        if (i % 16 == 0) {
            /*
                                    if (sl->q_data_dir == Q_DATA_OUT)
                                            fprintf(stdout, "\n<- 0x%08x ", sl->q_addr + i);
                                    else
                                            fprintf(stdout, "\n-> 0x%08x ", sl->q_addr + i);
             */
        }
        fprintf(stdout, " %02x", (unsigned int) sl->q_buf[i]);
    }
    fputs("\n\n", stdout);
}

/* memory mapped file */
int
stlink_map_file(mapped_file_t* mf, const char* path)
{
    int error = -1;
    struct stat st;

    const int fd = open(path, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "open(%s) == -1\n", path);
        return -1;
    }

    if (fstat(fd, &st) == -1) {
        fprintf(stderr, "fstat() == -1\n");
        goto on_error;
    }

    mf->base = (uint8_t*) mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (mf->base == MAP_FAILED) {
        fprintf(stderr, "mmap() == MAP_FAILED\n");
        goto on_error;
    }

    mf->len = st.st_size;

    /* success */
    error = 0;

on_error:
    close(fd);

    return error;
}

void
stlink_unmap_file(mapped_file_t * mf)
{
    munmap((void*) mf->base, mf->len);
    mf->base = (unsigned char*) MAP_FAILED;
    mf->len = 0;
}

/* Limit the block size to compare to 0x1800
   Anything larger will stall the STLINK2
   Maybe STLINK V1 needs smaller value!*/
static int check_file(stlink_t* sl, mapped_file_t* mf, stm32_addr_t addr) {
    size_t off;
    size_t n_cmp = sl->flash_pgsz;
    if ( n_cmp > 0x1800)
        n_cmp = 0x1800;

    for (off = 0; off < mf->len; off += n_cmp) {
        size_t aligned_size;

        /* adjust last page size */
        size_t cmp_size = n_cmp;
        if ((off + n_cmp) > mf->len)
            cmp_size = mf->len - off;

        aligned_size = cmp_size;
        if (aligned_size & (4 - 1))
            aligned_size = (cmp_size + 4) & ~(4 - 1);

        stlink_read_mem32(sl, addr + off, aligned_size);

        if (memcmp(sl->q_buf, mf->base + off, cmp_size))
            return -1;
    }

    return 0;
}

int
stlink_fwrite_sram(stlink_t * sl, const char* path, stm32_addr_t addr)
{
    /* write the file in sram at addr */
    int error = -1;
    size_t off;
    mapped_file_t mf = MAPPED_FILE_INITIALIZER;
    st_error_t r;

    if (stlink_map_file(&mf, path) == -1)
    {
        fprintf(stderr, "stlink_map_file() == -1\n");
        return -1;
    }

    /* check addr range is inside the sram */
    if (addr < sl->sram_base)
    {
        fprintf(stderr, "addr too low\n");
        goto on_error;
    }
    else if ((addr + mf.len) < addr)
    {
        fprintf(stderr, "addr overruns\n");
        goto on_error;
    }
    else if ((addr + mf.len) > (sl->sram_base + sl->sram_size))
    {
        fprintf(stderr, "addr too high\n");
        goto on_error;
    }
    else if ((addr & 3) || (mf.len & 3))
    {
        /* todo */
        fprintf(stderr, "unaligned addr or size\n");
        goto on_error;
    }

    /* do the copy by 1k blocks */
    for (off = 0; off < mf.len; off += 1024)
    {
        size_t size = 1024;
        if ((off + size) > mf.len)
            size = mf.len - off;

        memcpy(sl->q_buf, mf.base + off, size);

        /* round size if needed */
        if (size & 3)
        {
            size += 2;
        }

        r = stlink_write_mem32(sl, addr + off, size);
        if (r != ST_SUCCESS)
        {
            goto on_error;
        }
    }

    /* check the file has been written */
    if (check_file(sl, &mf, addr) == -1) {
        fprintf(stderr, "check_file() == -1\n");
        goto on_error;
    }



    uint32_t sp, pc;
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

    /* success */
    error = 0;

on_error:
    stlink_unmap_file(&mf);
    return error;
}

int
stlink_fread(stlink_t* sl, const char* path, stm32_addr_t addr, size_t size)
{
    /* read size bytes from addr to file */
    int error = -1;
    size_t off;
    int num_empty = 0;
    unsigned char erased_pattern = (sl->chip_id == STM32_CHIPID_L1_MEDIUM)?0:0xff;

    const int fd = open(path, O_RDWR | O_TRUNC | O_CREAT, 00700);
    if (fd == -1) {
        fprintf(stderr, "open(%s) == -1\n", path);
        return -1;
    }

    if (size <1)
    {
        size = sl->flash_size;
    }

    if (size > sl->flash_size)
    {
        size = sl->flash_size;
    }

    /* do the copy by 1k blocks */
    for (off = 0; off < size; off += 1024)
    {
        size_t read_size = 1024;
        size_t rounded_size;
        size_t index;
        if ((off + read_size) > size)
        {
            read_size = size - off;
        }
        /* round size if needed */
        rounded_size = read_size;
        if (rounded_size & 3)
        {
            rounded_size = (rounded_size + 4) & ~(3);
        }

        stlink_read_mem32(sl, addr + off, rounded_size);

        for (index = 0; index < read_size; index ++)
        {
            if (sl->q_buf[index] == erased_pattern)
            {
                num_empty ++;
            }
            else
            {
                num_empty = 0;
            }
        }

        if (write(fd, sl->q_buf, read_size) != (ssize_t) read_size)
        {
            fprintf(stderr, "write() != read_size\n");
            goto on_error;
        }
    }

    /* Ignore NULL Bytes at end of file */
    if (!ftruncate(fd, size - num_empty))
    {
        error = -1;
    }

    /* success */
    error = 0;

on_error:
    close(fd);

    return error;
}
