#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <libusb.h>

#include "stlink-common.h"
#include "stlink-usb.h"
#define LOG_TAG __FILE__
#include "uglylogging.h"

#define STLINK_CMD_SIZE 16

/* code from bsd timersub.h
http://www.gnu-darwin.org/www001/src/ports/net/libevnet/work/libevnet-0.3.8/libnostd/bsd/sys/time/timersub.h.html
*/
#if !defined timersub
#define	timersub(a, b, r) do {					\
	(r)->tv_sec	= (a)->tv_sec - (b)->tv_sec;		\
	(r)->tv_usec	= (a)->tv_usec - (b)->tv_usec;		\
	if ((r)->tv_usec < 0) {					\
		--(r)->tv_sec;					\
		(r)->tv_usec += 1000000;			\
	}							\
} while (0)
#endif

#define TRANS_FLAGS_IS_DONE (1 << 0)
#define TRANS_FLAGS_HAS_ERROR (1 << 1)

struct trans_ctx {
    volatile unsigned long flags;
};

struct stlink_libusb
{
    libusb_context *libusb_ctx;
    libusb_device_handle *usb_handle;
    struct libusb_transfer *req_trans;
    struct libusb_transfer *rep_trans;
    unsigned int ep_req;
    unsigned int ep_rep;
    unsigned int cmd_len;
};

st_error_t
_stlink_usb_close(stlink_t* sl)
{
    struct stlink_libusb * const handle = sl->backend_data;

    if (handle != NULL)
    {
        if (handle->req_trans != NULL)
        {
            libusb_free_transfer(handle->req_trans);
        }
        if (handle->rep_trans != NULL)
        {
            libusb_free_transfer(handle->rep_trans);
        }
        if (handle->usb_handle != NULL)
        {
            libusb_close(handle->usb_handle);
        }

        libusb_exit(handle->libusb_ctx);
        free(handle);
    }

    return ST_SUCCESS;
}

#ifndef LIBUSB_CALL
# define LIBUSB_CALL
#endif

static void LIBUSB_CALL
on_trans_done(struct libusb_transfer *trans)
{
    struct trans_ctx *const ctx = trans->user_data;

    if (trans->status != LIBUSB_TRANSFER_COMPLETED)
    {
        ctx->flags |= TRANS_FLAGS_HAS_ERROR;
    }

    ctx->flags |= TRANS_FLAGS_IS_DONE;
}

static int
submit_wait(struct stlink_libusb *slu, struct libusb_transfer *trans)
{
    struct timeval start;
    struct timeval now;
    struct timeval diff;
    struct trans_ctx trans_ctx;
    enum libusb_error error;

    trans_ctx.flags = 0;

    /* brief intrusion inside the libusb interface */
    trans->callback = on_trans_done;
    trans->user_data = &trans_ctx;

    if ((error = libusb_submit_transfer(trans)))
    {
        WLOG("libusb_submit_transfer(%d)\n", error);
        return -1;
    }

    gettimeofday(&start, NULL);

    while (trans_ctx.flags == 0)
    {
        struct timeval timeout;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        if (libusb_handle_events_timeout(slu->libusb_ctx, &timeout)) {
            WLOG("libusb_handle_events()\n");
            return -1;
        }

        gettimeofday(&now, NULL);
        timersub(&now, &start, &diff);
        if (diff.tv_sec >= 3) {
            WLOG("libusb_handle_events() timeout\n");
            return -1;
        }
    }

    if (trans_ctx.flags & TRANS_FLAGS_HAS_ERROR) {
        WLOG("libusb_handle_events() | has_error\n");
        return -1;
    }

    return 0;
}

static ssize_t
send_recv(struct stlink_libusb* handle,
          unsigned char* txbuf, size_t txsize,
          unsigned char* rxbuf, size_t rxsize)
{
    /* note: txbuf and rxbuf can point to the same area */
    int res = 0;

    libusb_fill_bulk_transfer(handle->req_trans, handle->usb_handle, handle->ep_req,
                              txbuf, txsize, NULL, NULL, 0);

    if (submit_wait(handle, handle->req_trans)) {
        return -1;
    }

    if (rxsize != 0) {
        /* read the response */
        libusb_fill_bulk_transfer(handle->rep_trans, handle->usb_handle, handle->ep_rep,
                                  rxbuf, rxsize, NULL, NULL, 0);

        if (submit_wait(handle, handle->rep_trans)) {
            return -1;
        }
        res = handle->rep_trans->actual_length;
    }

    return handle->rep_trans->actual_length;
}

static inline int
send_recv_cmd(struct stlink_libusb* handle, unsigned char* txbuf, unsigned char* rxbuf, size_t rxsize)
{
    return send_recv(handle, txbuf, STLINK_CMD_SIZE, rxbuf, rxsize);
}

static inline int
send_only(struct stlink_libusb* handle, unsigned char* txbuf, size_t txsize)
{
    return send_recv(handle, txbuf, txsize, NULL, 0);
}

static void
prepare_command(stlink_t *sl)
{
    memset(sl->c_buf, 0, sizeof (sl->c_buf));
}

st_error_t
_stlink_usb_version(stlink_t *sl)
{
    struct stlink_libusb * const slu = sl->backend_data;
    unsigned char* const cmd  = sl->c_buf;
    unsigned char* const rdata = sl->q_buf;
    const uint32_t rep_len = 6;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_GET_VERSION;
    size = send_recv_cmd(slu, cmd, rdata, rep_len);

    if (size != rep_len)
    {
        WLOG("[!] %s: expected %d bytes. Got %zd bytes\n", __func__, rep_len, size);
        return ST_PROTOCOL_ERROR;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_read_debug32(stlink_t *sl, uint32_t addr, uint32_t *r)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd  = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    const int rep_len = 8;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_JTAG_READDEBUG_32BIT;
    write_uint32(&cmd[i], addr);
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len) {
        WLOG("[!] %s\n", __func__);
        return ST_PROTOCOL_ERROR;
    }

    DLOG("Read jtag @ 0x%08x: 0x%08x | 0x%08x\n", addr,
         read_uint32(rdata, 0),
         read_uint32(rdata, 4));

    *r = read_uint32(rdata, 4);
    return ST_SUCCESS;
}

st_error_t
_stlink_usb_write_debug32(stlink_t *sl, uint32_t addr, uint32_t data)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd  = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    const int rep_len = 2;
    ssize_t size;
    int i = 0;
    uint16_t ret;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_JTAG_WRITEDEBUG_32BIT;
    write_uint32(&cmd[i], addr);
    write_uint32(&cmd[i + 4], data);
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len)
    {
        WLOG("[!] %s (size != rep_len)\n", __func__);
        return ST_PROTOCOL_ERROR;
    }

    ret = read_uint16(rdata, 0);
    if (ret != 0x80)
    {
        WLOG("[!] %s (ret<0x%02x> != 0x80)\n", __func__, ret);
        return ST_PROTOCOL_ERROR;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_write_mem32(stlink_t *sl, uint32_t addr, uint16_t len)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const data = sl->q_buf;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_WRITEMEM_32BIT;
    write_uint32(&cmd[i], addr);
    write_uint16(&cmd[i + 4], len);

    send_only(slu, cmd, STLINK_CMD_SIZE);
    send_only(slu, data, len);

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_write_mem8(stlink_t *sl, uint32_t addr, uint16_t len)
{
    struct stlink_libusb  *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const data = sl->q_buf;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_WRITEMEM_8BIT;
    write_uint32(&cmd[i], addr);
    write_uint16(&cmd[i + 4], len);

    send_only(slu, cmd, STLINK_CMD_SIZE);
    send_only(slu, data, len);

    return ST_SUCCESS;
}


st_error_t
_stlink_usb_current_mode(stlink_t *sl, uint8_t *mode)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    const int rep_len = 2;
    ssize_t size;
    uint16_t ret;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_GET_CURRENT_MODE;
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len)
    {
        WLOG("[!] %s\n", __func__);
        return ST_GENERIC_ERROR;
    }
    ret = read_uint16(rdata, 0);
    DLOG("Current mode returned: 0x%04" PRIx16 "\n", ret);
    *mode = sl->q_buf[0];

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_core_id(stlink_t *sl)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    const int rep_len = 4;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_READCOREID;
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len)
    {
        WLOG("[!] %s\n", __func__);
        return ST_PROTOCOL_ERROR;
    }

    sl->core_id = read_uint32(rdata, 0);
    return ST_SUCCESS;
}

st_error_t
_stlink_usb_status(stlink_t *sl, uint16_t *status)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    const int rep_len = 2;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_GETSTATUS;
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len)
    {
        WLOG("[!] %s: expected %d bytes. Got %zd bytes\n", __func__, rep_len, size);
        return ST_PROTOCOL_ERROR;
    }

    *status = read_uint16(rdata, 0);
    DLOG("Status returned: 0x%04" PRIx16 "\n", *status);

    switch (*status)
    {
    case STLINK_CORE_RUNNING:
    case STLINK_CORE_HALTED:
        return ST_SUCCESS;
    default:
        return ST_PROTOCOL_ERROR;
    }
}

st_error_t
_stlink_usb_force_debug(stlink_t *sl)
{
    struct stlink_libusb *slu = sl->backend_data;
    unsigned char* const cmd  = sl->c_buf;
    unsigned char* const rdata = sl->q_buf;
    const int rep_len = 2;
    ssize_t size;
    int i = 0;
    uint16_t ret;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_FORCEDEBUG;
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len)
    {
        WLOG("%s: expected %d bytes. Got %zd bytes\n", __func__, rep_len, size);
        return ST_PROTOCOL_ERROR;
    }

    ret = read_uint16(rdata, 0);
    DLOG("Force debug returned: 0x%04" PRIx16 "\n", ret);

    switch (ret) {
    case STLINK_OK:
        return ST_SUCCESS;
    case STLINK_FALSE:
        return ST_FAIL;
    default:
        return ST_PROTOCOL_ERROR;
    }
}

st_error_t
_stlink_usb_enter_swd_mode(stlink_t  *sl)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd  = sl->c_buf;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_ENTER;
    cmd[i++] = STLINK_DEBUG_ENTER_SWD;
    size = send_only(slu, cmd, STLINK_CMD_SIZE);
    if (size == -1)
    {
        WLOG("%s\n", __func__);
        return ST_PROTOCOL_ERROR;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_exit_dfu_mode(stlink_t *sl)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DFU_COMMAND;
    cmd[i++] = STLINK_DFU_EXIT;
    size = send_only(slu, cmd, STLINK_CMD_SIZE);
    if (size == -1) {
        WLOG("%s\n", __func__);
        return ST_PROTOCOL_ERROR;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_reset(stlink_t *sl)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    const int rep_len = 2;
    ssize_t size;
    uint16_t ret;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_RESETSYS;

    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len)
    {
        WLOG("%s: Expected %d bytes, got %zd\n", __func__, rep_len, size);
        return ST_PROTOCOL_ERROR;
    }

    ret = read_uint16(rdata, 0);
    DLOG("Reset returned: 0x%04" PRIx16 "\n", ret);


    switch (ret) {
    case STLINK_OK:
        return ST_SUCCESS;
    case STLINK_FALSE:
        return ST_FAIL;
    default:
        return ST_PROTOCOL_ERROR;
    }
}


st_error_t
_stlink_usb_jtag_reset(stlink_t *sl, int value)
{
    struct stlink_libusb * const slu = sl->backend_data;
    unsigned char* const data = sl->q_buf;
    unsigned char* const cmd = sl->c_buf;
    ssize_t size;
    int rep_len = 2;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_JTAG_DRIVE_NRST;
    cmd[i++] = (value)?0:1;
    size = send_recv_cmd(slu, cmd, data, rep_len);
    if (size == -1) {
        WLOG("%s\n", __func__);
        return ST_PROTOCOL_ERROR;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_step(stlink_t *sl)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    const int rep_len = 2;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_STEPCORE;
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len) {
        WLOG("%s\n", __func__);
        return ST_PROTOCOL_ERROR;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_run(stlink_t *sl)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    const int rep_len = 2;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_RUNCORE;
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len)
    {
        WLOG("%s\n", __func__);
        return ST_PROTOCOL_ERROR;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_exit_debug_mode(stlink_t *sl)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_EXIT;
    size = send_only(slu, cmd, STLINK_CMD_SIZE);
    if (size == -1)
    {
        WLOG("[!] send_only\n");
        return ST_PROTOCOL_ERROR;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_read_mem32(stlink_t *sl, uint32_t addr, uint16_t len)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_READMEM_32BIT;
    write_uint32(&cmd[i], addr);
    write_uint16(&cmd[i + 4], len);
    size = send_recv_cmd(slu, cmd, rdata, len);
    if (size == -1)
    {
        WLOG("%s\n", __func__);
        return ST_PROTOCOL_ERROR;
    }

    sl->q_len = (size_t) size;
    stlink_print_data(sl);

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_read_all_regs(stlink_t *sl, reg *regp)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const cmd = sl->c_buf;
    unsigned char *const rdata = sl->q_buf;
    const uint32_t rep_len = 84;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_READALLREGS;
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len)
    {
        WLOG("%s: expected %d bytes. Got %zd bytes\n", __func__, rep_len, size);
        return ST_PROTOCOL_ERROR;
    }

    sl->q_len = (size_t) size;
    stlink_print_data(sl);
    for (i = 0; i < 16; i++)
    {
        regp->r[i]= read_uint32(sl->q_buf, i*4);
    }
    regp->xpsr = read_uint32(sl->q_buf, 64);
    regp->main_sp = read_uint32(sl->q_buf, 68);
    regp->process_sp = read_uint32(sl->q_buf, 72);
    regp->rw  = read_uint32(sl->q_buf, 76);
    regp->rw2 = read_uint32(sl->q_buf, 80);

    if (sl->verbose >= 2)
    {
        DLOG("xpsr       = 0x%08x\n", read_uint32(sl->q_buf, 64));
        DLOG("main_sp    = 0x%08x\n", read_uint32(sl->q_buf, 68));
        DLOG("process_sp = 0x%08x\n", read_uint32(sl->q_buf, 72));
        DLOG("rw         = 0x%08x\n", read_uint32(sl->q_buf, 76));
        DLOG("rw2        = 0x%08x\n", read_uint32(sl->q_buf, 80));
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_read_reg(stlink_t *sl, int r_idx, reg *regp)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const data = sl->q_buf;
    unsigned char *const cmd = sl->c_buf;
    const uint32_t rep_len = 4;
    ssize_t size;
    uint32_t r;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_READREG;
    cmd[i++] = (uint8_t) r_idx;
    size = send_recv_cmd(slu, cmd, data, rep_len);
    if (size != rep_len)
    {
        WLOG("%s: expected %d bytes. Got %zd bytes\n", __func__, rep_len, size);
        return ST_PROTOCOL_ERROR;
    }
    sl->q_len = (size_t) size;
    stlink_print_data(sl);
    r = read_uint32(sl->q_buf, 0);
    DLOG("r_idx (%2d) = 0x%08x\n", r_idx, r);

    switch (r_idx)
    {
    case 16:
        regp->xpsr = r;
        break;
    case 17:
        regp->main_sp = r;
        break;
    case 18:
        regp->process_sp = r;
        break;
    case 19:
        regp->rw = r; /* XXX ?(primask, basemask etc.) */
        break;
    case 20:
        regp->rw2 = r; /* XXX ?(primask, basemask etc.) */
        break;
    default:
        regp->r[r_idx] = r;
    }

    return ST_SUCCESS;
}

/* See section C1.6 of the ARMv7-M Architecture Reference Manual */
st_error_t
_stlink_usb_read_unsupported_reg(stlink_t *sl, int r_idx, reg *regp)
{
    uint32_t r;
    st_error_t ret;

    sl->q_buf[0] = (unsigned char) r_idx;
    for (int i = 1; i < 4; i++)
    {
        sl->q_buf[i] = 0;
    }

    ret = _stlink_usb_write_mem32(sl, DCRSR, 4);
    if (ret != ST_SUCCESS)
    {
        return ret;
    }

    ret = _stlink_usb_read_mem32(sl, DCRDR, 4);
    if (ret != ST_SUCCESS)
    {
        return ret;
    }

    r = read_uint32(sl->q_buf, 0);
    DLOG("r_idx (%2d) = 0x%08x\n", r_idx, r);

    switch (r_idx) {
        case 0x14:
            regp->primask = (uint8_t) (r & 0xFF);
            regp->basepri = (uint8_t) ((r>>8) & 0xFF);
            regp->faultmask = (uint8_t) ((r>>16) & 0xFF);
            regp->control = (uint8_t) ((r>>24) & 0xFF);
            break;
        case 0x21:
            regp->fpscr = r;
            break;
        default:
            regp->s[r_idx - 0x40] = r;
            break;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_read_all_unsupported_regs(stlink_t *sl, reg *regp)
{
    st_error_t ret;

    _stlink_usb_read_unsupported_reg(sl, 0x14, regp);
    _stlink_usb_read_unsupported_reg(sl, 0x21, regp);

    for (int i = 0; i < 32; i++) {
        ret = _stlink_usb_read_unsupported_reg(sl, 0x40+i, regp);
        if (ret != ST_SUCCESS)
        {
            return ret;
        }
    }

    return ST_SUCCESS;
}

/* See section C1.6 of the ARMv7-M Architecture Reference Manual */
st_error_t
_stlink_usb_write_unsupported_reg(stlink_t *sl, uint32_t val, int r_idx, reg *regp)
{
    st_error_t ret;

    if (r_idx >= 0x1C && r_idx <= 0x1F) /* primask, basepri, faultmask, or control */
    {
        /* These are held in the same register */
        ret = _stlink_usb_read_unsupported_reg(sl, 0x14, regp);
        if (ret != ST_SUCCESS)
        {
            return ret;
        }

        val = (uint8_t) (val>>24);

        switch (r_idx) {
            case 0x1C:  /* control */
                val = (((uint32_t) val) << 24) |
                    (((uint32_t) regp->faultmask) << 16) |
                    (((uint32_t) regp->basepri) << 8) |
                    ((uint32_t) regp->primask);
                break;
            case 0x1D:  /* faultmask */
                val = (((uint32_t) regp->control) << 24) |
                    (((uint32_t) val) << 16) |
                    (((uint32_t) regp->basepri) << 8) |
                    ((uint32_t) regp->primask);
                break;
            case 0x1E:  /* basepri */
                val = (((uint32_t) regp->control) << 24) |
                    (((uint32_t) regp->faultmask) << 16) |
                    (((uint32_t) val) << 8) |
                    ((uint32_t) regp->primask);
                break;
            case 0x1F:  /* primask */
                val = (((uint32_t) regp->control) << 24) |
                    (((uint32_t) regp->faultmask) << 16) |
                    (((uint32_t) regp->basepri) << 8) |
                    ((uint32_t) val);
                break;
        }

        r_idx = 0x14;
    }

    write_uint32(sl->q_buf, val);

    ret = _stlink_usb_write_mem32(sl, DCRDR, 4);
    if (ret != ST_SUCCESS)
    {
        return ret;
    }

    sl->q_buf[0] = (unsigned char) r_idx;
    sl->q_buf[1] = 0;
    sl->q_buf[2] = 0x01;
    sl->q_buf[3] = 0;

    ret = _stlink_usb_write_mem32(sl, DCRSR, 4);
    if (ret != ST_SUCCESS)
    {
        return ret;
    }

    return ST_SUCCESS;
}

st_error_t
_stlink_usb_write_reg(stlink_t *sl, uint32_t reg, int idx)
{
    struct stlink_libusb *const slu = sl->backend_data;
    unsigned char *const rdata = sl->q_buf;
    unsigned char *const cmd  = sl->c_buf;
    const uint32_t rep_len = 2;
    ssize_t size;
    int i = 0;

    prepare_command(sl);
    cmd[i++] = STLINK_DEBUG_COMMAND;
    cmd[i++] = STLINK_DEBUG_WRITEREG;
    cmd[i++] = idx;
    write_uint32(&cmd[i], reg);
    size = send_recv_cmd(slu, cmd, rdata, rep_len);
    if (size != rep_len)
    {
        WLOG("%s: expected %d bytes. Got %zd bytes\n", __func__, rep_len, size);
        return ST_PROTOCOL_ERROR;
    }
    sl->q_len = (size_t) size;
    stlink_print_data(sl);

    return ST_SUCCESS;
}

stlink_backend_t _stlink_usb_backend = {
    _stlink_usb_close,
    _stlink_usb_exit_debug_mode,
    _stlink_usb_enter_swd_mode,
    NULL,  // no enter_jtag_mode here...
    _stlink_usb_exit_dfu_mode,
    _stlink_usb_core_id,
    _stlink_usb_reset,
    _stlink_usb_jtag_reset,
    _stlink_usb_run,
    _stlink_usb_status,
    _stlink_usb_version,
    _stlink_usb_read_debug32,
    _stlink_usb_read_mem32,
    _stlink_usb_write_debug32,
    _stlink_usb_write_mem32,
    _stlink_usb_write_mem8,
    _stlink_usb_read_all_regs,
    _stlink_usb_read_reg,
    _stlink_usb_read_all_unsupported_regs,
    _stlink_usb_read_unsupported_reg,
    _stlink_usb_write_unsupported_reg,
    _stlink_usb_write_reg,
    _stlink_usb_step,
    _stlink_usb_current_mode,
    _stlink_usb_force_debug
};


stlink_t*
stlink_open_usb(const int verbose)
{
    stlink_t* sl = NULL;
    struct stlink_libusb* slu = NULL;
    int error = -1;
    libusb_device** devs = NULL;
    int config;

    DLOG("stlink_open_usb\n");

    sl = malloc(sizeof (stlink_t));
    slu = malloc(sizeof (struct stlink_libusb));
    if (sl == NULL)
    {
        goto on_error;
    }
    if (slu == NULL)
    {
        goto on_error;
    }

    memset(sl, 0, sizeof (stlink_t));
    memset(slu, 0, sizeof (struct stlink_libusb));

    ugly_init(verbose);

    sl->backend = &_stlink_usb_backend;
    sl->backend_data = slu;
    sl->core_stat = STLINK_CORE_STAT_UNKNOWN;

    if (libusb_init(&(slu->libusb_ctx))) {
        WLOG("failed to init libusb context, wrong version of libraries?\n");
        goto on_error;
    }

    slu->usb_handle = libusb_open_device_with_vid_pid(slu->libusb_ctx,
                                                      USB_ST_VID,
                                                      USB_STLINK_32L_PID);

    if (slu->usb_handle == NULL) {
        WLOG("Couldn't find any ST-Link V2 devices\n");
        goto on_error;
    }

    if (libusb_kernel_driver_active(slu->usb_handle, 0) == 1) {
        int r;

        r = libusb_detach_kernel_driver(slu->usb_handle, 0);
        if (r < 0)
        {
            WLOG("libusb_detach_kernel_driver(() error %s\n", strerror(-r));
            goto on_libusb_error;
        }
    }

    if (libusb_get_configuration(slu->usb_handle, &config)) {
        /* this may fail for a previous configured device */
        WLOG("libusb_get_configuration()\n");
        goto on_libusb_error;
    }

    if (config != 1)
    {
        DLOG("setting new configuration (%d -> 1)\n", config);
        if (libusb_set_configuration(slu->usb_handle, 1)) {
            /* this may fail for a previous configured device */
            WLOG("libusb_set_configuration() failed\n");
            goto on_libusb_error;
        }
    }

    if (libusb_claim_interface(slu->usb_handle, 0)) {
        WLOG("libusb_claim_interface() failed\n");
        goto on_libusb_error;
    }

    slu->req_trans = libusb_alloc_transfer(0);
    if (slu->req_trans == NULL) {
        WLOG("libusb_alloc_transfer failed\n");
        goto on_libusb_error;
    }

    slu->rep_trans = libusb_alloc_transfer(0);
    if (slu->rep_trans == NULL) {
        WLOG("libusb_alloc_transfer failed\n");
        goto on_libusb_error;
    }

    // TODO - could use the scanning techniq from stm8 code here...
    slu->ep_rep = 1 /* ep rep */ | LIBUSB_ENDPOINT_IN;
    slu->ep_req = 2 /* ep req */ | LIBUSB_ENDPOINT_OUT;

    /* success */
    uint8_t mode;
    st_error_t r;
    r = stlink_current_mode(sl, &mode);
    if (r != ST_SUCCESS)
    {
        goto on_libusb_error;
    }
    DLOG("Current mode is: %d\n", mode);
    if (mode == STLINK_DEV_DFU_MODE)
    {
      ILOG("-- exit_dfu_mode\n");
      r = stlink_exit_dfu_mode(sl);
      if (r != ST_SUCCESS)
      {
          goto on_libusb_error;
      }
    }

    r = stlink_current_mode(sl, &mode);
    if (r != ST_SUCCESS)
    {
        goto on_libusb_error;
    }
    DLOG("Current mode is: %d\n", mode);
    if (mode != STLINK_DEV_DEBUG_MODE)
    {
      r = stlink_enter_swd_mode(sl);
      if (r != ST_SUCCESS)
      {
          goto on_libusb_error;
      }
    }

    r = stlink_current_mode(sl, &mode);
    if (r != ST_SUCCESS)
    {
        goto on_libusb_error;
    }
    DLOG("Current mode is: %d\n", mode);

    r = stlink_reset_retry(sl, 3);
    if (r != ST_SUCCESS)
    {
        WLOG("Unable to reset (%x)\n", r);
        goto on_libusb_error;
    }
    r = stlink_load_device_params(sl);
    if (r != ST_SUCCESS)
    {
        goto on_libusb_error;
    }
    r = stlink_version(sl);
    if (r != ST_SUCCESS)
    {
        goto on_libusb_error;
    }

    error = 0;

on_libusb_error:
    if (devs != NULL) {
        libusb_free_device_list(devs, 1);
    }

    if (error == -1) {
        stlink_close(sl);
        return NULL;
    }

    /* success */
    return sl;

on_error:
    if (slu->libusb_ctx)
    {
	libusb_exit(slu->libusb_ctx);
    }
    free(sl);
    free(slu);

    return NULL;
}

