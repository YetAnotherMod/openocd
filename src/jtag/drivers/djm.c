
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "helper/system.h"
#include <jtag/interface.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <sys/stat.h>
#endif

#ifdef _WIN32
static HANDLE djm_fd = INVALID_HANDLE_VALUE;
#else
static int djm_fd = -1;
#endif
static char *djm_tty = NULL;
static uint8_t djm_buff[1024];
static uint16_t djm_buff_len = 0;

static void packet_size(char c, uint16_t count){
    djm_buff[djm_buff_len++] = c;
    djm_buff[djm_buff_len++] = count&0xff;
    djm_buff[djm_buff_len++] = count>>8;
}

static void packet_data(const uint8_t *data, uint16_t count){
    int len = count/8 + (count%8?1:0);
    memcpy(djm_buff+djm_buff_len,data,len);
    djm_buff_len+=len;
}

#ifdef _WIN32
static DWORD com_read(uint8_t *data, uint16_t count){
    DWORD rc = 0;
    BOOL res = ReadFile(djm_fd,data,count,&rc,NULL);
    if(res == FALSE){
        LOG_ERROR ("tty broken");
        exit(-1);
    }
    return rc;
}
#else
static ssize_t com_read(uint8_t *data, uint16_t count){
    ssize_t rc = read(djm_fd,data,count);
    LOG_DEBUG_IO("rc: %li",rc);
    if(rc == 0){
        struct stat statbuf;
        if ( (fstat(djm_fd, &statbuf) !=0) || (statbuf.st_nlink == 0)){
            LOG_ERROR ("tty broken");
            exit(-1);
        }
    }else if(rc<0){
        LOG_ERROR ("Can't read fd %i %s",errno,strerror(errno));
        exit(-1);
    }
    return rc;
}
#endif

static void packet_read(uint8_t *data, uint16_t count){
    int len = count/8 + (count%8?1:0);
    uint16_t ind = 0;
    while ( ind < len ){
        ind += com_read(data+ind,len-ind);
    }
}

static void packet_flush (void){
#ifdef _WIN32
    DWORD wc = 0;
    WriteFile(djm_fd, djm_buff, djm_buff_len, &wc, 0);
#else
    ssize_t wc = write(djm_fd, djm_buff, djm_buff_len);
#endif
    if ( wc != djm_buff_len ){
        LOG_ERROR ("Can't write to fd");
        exit(-1);
    }
    djm_buff_len = 0;
}

static int packet_move (const uint8_t *data, uint16_t count){
    packet_size('!',count);
    packet_data(data,count);
    return ERROR_OK;
}

static int packet_wait_ticks(uint16_t count){
    packet_size('_',count);
    return ERROR_OK;
}

static int packet_scan_io (int count, uint8_t *buffer){
    packet_size('@',count);
    packet_data(buffer,count);
    return ERROR_OK;
}

static int packet_scan_i (int count, uint8_t *buffer){
    packet_size('$',count);
    return ERROR_OK;
}

static int packet_scan_o (int count, uint8_t *buffer){
    packet_size('#',count);
    packet_data(buffer,count);
    return ERROR_OK;
}

static int packet_wait_time(uint16_t count){
    packet_size('*',count);
    return ERROR_OK;
}

static int packet_set_speed(uint16_t speed){
    packet_size('%',speed);
    return ERROR_OK;
}

static int djm_speed(int speed){
    return packet_set_speed(speed);
}

static int djm_khz(int khz, int *speed){
    int speed_ = 100000 / khz;
    speed_ = speed_/2 + speed_%2;
    if ( speed_ <= 0 ){
        speed_ = 1;
    }
    *speed = speed_;
    return ERROR_OK;
}

static int djm_speed_div(int speed, int *khz){
    int khz_ = 100000 / speed;
    khz_ = khz_/2 + khz_%2;
    *khz = khz_;
    return ERROR_OK;
}

static int djm_statemove(tap_state_t state){
    LOG_DEBUG_IO("statemove from %s to %s",tap_state_name(tap_get_state()),tap_state_name(state));
    tap_set_end_state(state);
    if ( (state == TAP_RESET) || (tap_get_state() != state) ){
        uint8_t tms_scan = tap_get_tms_path(tap_get_state(), tap_get_end_state());
        int tms_count = tap_get_tms_path_len(tap_get_state(), tap_get_end_state());
        if ( packet_move( &tms_scan, tms_count ) == ERROR_OK )
            tap_set_state(state);
    }
    return tap_get_end_state() == tap_get_state() ? ERROR_OK : ERROR_FAIL;
}

static int djm_runtest(struct runtest_command *runtest){
    djm_statemove(TAP_IDLE);
    packet_wait_ticks(runtest->num_cycles);
    djm_statemove(runtest->end_state);
    return ERROR_OK;
}
static int djm_stableclocks(struct stableclocks_command *stableclocks){
    packet_wait_ticks(stableclocks->num_cycles);
    return ERROR_OK;
}
static int djm_pathmove(struct pathmove_command *pathmove){
    tap_state_t prev = tap_get_state();
    for ( int i = 0 ; i < pathmove->num_states ; i++ ){
        if (
                (tap_state_transition(prev,false) != pathmove->path[i]) &&
                (tap_state_transition(prev,true) != pathmove->path[i])
            ){
            LOG_ERROR("BUG: %s -> %s isn't a valid TAP transition",
                tap_state_name(prev),
                tap_state_name(pathmove->path[i]));
            exit(-1);
        }
        prev = pathmove->path[i];
    }
    for ( int i = 0 ; i < pathmove->num_states ; i++ ){
        djm_statemove(pathmove->path[i]);
    }
    return ERROR_OK;
}
static int djm_scan(struct scan_command *scan){
    uint8_t *buffer;
    int retval = ERROR_OK;
    uint16_t scan_size = jtag_build_buffer(scan, &buffer);
    LOG_DEBUG_IO("%s scan %d bits; end in %s",
        (scan->ir_scan) ? "IR" : "DR",
        scan_size,
        tap_state_name(scan->end_state));
    djm_statemove(scan->ir_scan?TAP_IRSHIFT:TAP_DRSHIFT);
    enum scan_type type = jtag_scan_type(scan);
    switch ( type ){
        case SCAN_OUT:
            packet_scan_o(scan_size,buffer);
            break;
        case SCAN_IN:
            packet_scan_i(scan_size,buffer);
            break;
        case SCAN_IO:
            packet_scan_io(scan_size,buffer);
            break;
    };
    tap_set_state(scan->ir_scan?TAP_IRPAUSE:TAP_DRPAUSE);
    djm_statemove(scan->end_state);
    packet_flush();
    if ( ( type == SCAN_IO ) || ( type == SCAN_IN ) ){
        packet_read(buffer,scan_size);
    }
    if (jtag_read_buffer(buffer, scan) != ERROR_OK)
        retval = ERROR_JTAG_QUEUE_FAILED;
    free(buffer);
    return retval;
}
static int djm_sleep(struct sleep_command *sleep){
    packet_wait_time(sleep->us);
    return ERROR_OK;
}
static int djm_tms(struct tms_command *tms){
    packet_move(tms->bits,tms->num_bits);
    return ERROR_OK;
}

static int djm_execute_queue (void){
    struct jtag_command *cmd = jtag_command_queue;  /* currently processed command */
    while (cmd){
        switch (cmd->type) {

            case JTAG_RUNTEST:
                LOG_DEBUG_IO("RUNTEST");
                if (djm_runtest(cmd->cmd.runtest) != ERROR_OK)
                    return ERROR_FAIL;
                break;

            case JTAG_STABLECLOCKS:
                LOG_DEBUG_IO("STABLE_CLOCKS");
                if (djm_stableclocks(cmd->cmd.stableclocks) != ERROR_OK)
                    return ERROR_FAIL;
                break;

            case JTAG_TLR_RESET:
                LOG_DEBUG_IO("TLR_RESET");
                if (djm_statemove(cmd->cmd.statemove->end_state) != ERROR_OK)
                    return ERROR_FAIL;
                break;

            case JTAG_PATHMOVE:
                LOG_DEBUG_IO("PATHMOVE");
                if (djm_pathmove(cmd->cmd.pathmove) != ERROR_OK)
                    return ERROR_FAIL;
                break;

            case JTAG_SCAN:
                LOG_DEBUG_IO("SCAN");
                if (djm_scan(cmd->cmd.scan) != ERROR_OK)
                    return ERROR_FAIL;
                break;

            case JTAG_SLEEP:
                LOG_DEBUG_IO("SLEEP");
                if (djm_sleep(cmd->cmd.sleep) != ERROR_OK)
                    return ERROR_FAIL;
                break;

            case JTAG_TMS:
                LOG_DEBUG_IO("TMS");
                if (djm_tms(cmd->cmd.tms) != ERROR_OK)
                    return ERROR_FAIL;
                break;

            default:
                LOG_ERROR("BUG: unknown JTAG command type encountered");
                exit(-1);
        }
        packet_flush();
        cmd = cmd->next;
    }
    return ERROR_OK;
}

static int djm_init(void){
    LOG_DEBUG("Initializing DJM driver");
    if ( djm_tty == NULL ){
        LOG_ERROR("No tty specified");
        return ERROR_JTAG_INIT_FAILED;
    }
    LOG_DEBUG("Opening %s",djm_tty);
#ifdef _WIN32
    HANDLE fd = CreateFileA(djm_tty,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if ( fd == INVALID_HANDLE_VALUE ){
        LOG_ERROR("Can't open %s", djm_tty);
        return ERROR_JTAG_INIT_FAILED;
    }
    COMMTIMEOUTS commtimeouts;

    commtimeouts.ReadIntervalTimeout = 0;
    commtimeouts.ReadTotalTimeoutMultiplier = 0;
    commtimeouts.ReadTotalTimeoutConstant = 100;
    commtimeouts.WriteTotalTimeoutMultiplier = 0;
    commtimeouts.WriteTotalTimeoutConstant = 100;
    if (SetCommTimeouts(fd, &commtimeouts) == FALSE){
        LOG_ERROR("Can't SetCommTimeouts %li", GetLastError());
        return ERROR_JTAG_INIT_FAILED;
    }
    djm_fd = fd;

#else
    int fd = open(djm_tty,O_RDWR | O_NOCTTY);
    if ( fd == -1 ){
        LOG_ERROR("Can't open %s, reason: %s",djm_tty, strerror(errno));
        return ERROR_JTAG_INIT_FAILED;
    }
	struct termios t_opt;
	if (tcgetattr(fd, &t_opt) != 0){
        LOG_ERROR("Can't tcgetattr");
        return ERROR_JTAG_INIT_FAILED;
    }
	
    t_opt.c_cflag |= (CLOCAL | CREAD);
	t_opt.c_cflag &= ~PARENB;
	t_opt.c_cflag &= ~CSTOPB;
	t_opt.c_cflag &= ~CSIZE;
	t_opt.c_cflag |= CS8;
	t_opt.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

	t_opt.c_iflag &= ~(IXON | IXOFF | IXANY | INLCR | ICRNL);

	t_opt.c_oflag &= ~OPOST;
	t_opt.c_cc[VMIN] = 0;
	t_opt.c_cc[VTIME] = 1;
    
    if (tcsetattr(fd, TCSADRAIN, &t_opt) != 0) {
        LOG_ERROR("Can't tcsetattr");
        return ERROR_JTAG_INIT_FAILED;
    }
    djm_fd = fd;
#endif
    char ident[256];
    unsigned ind = 0;
    for (int i = 0; (strcmp(ident,"djmv1\r\n")!=0)&&(i < 128); i++){
        ind = 0;
        djm_buff_len = 3;
        djm_buff[0] = 0;
        djm_buff[1] = 0;
        djm_buff[2] = 'h';

        packet_flush();

        ssize_t rc = com_read ( (unsigned char *)ident, sizeof(ident)-1);
        while ( (rc > 0) && (ind < (sizeof(ident)-1)) ){
            ind += rc;
            rc = com_read ( (unsigned char *)(ident+ind), 1);
        }
        ident[ind] = '\0';
        LOG_DEBUG("ident: %s", ident);
    }

    if ( strcmp(ident,"djmv1\r\n")!=0 ){
        char hex[sizeof(ident)*3] = "";
        char *p = hex, *i = ident;
        while(*i){
            p+= sprintf (p,"%02x ",*i++);
        }
        LOG_DEBUG("ident hex: %s", hex);
        LOG_ERROR("incorrect ident");
        return ERROR_JTAG_INIT_FAILED;
    }
#ifndef _WIN32
	t_opt.c_cc[VMIN] = 1;
    if (tcsetattr(djm_fd, TCSADRAIN, &t_opt) != 0) {
        LOG_ERROR("Can't tcsetattr");
        return ERROR_JTAG_INIT_FAILED;
    }
#endif

    return ERROR_OK;
}

static int djm_quit(void){
#ifdef _WIN32
    CloseHandle ( djm_fd );
#else
    close ( djm_fd );
#endif
    free (djm_tty);
    djm_tty = NULL;
    return ERROR_OK;
}

static int djm_reset(int trst, int srst){
	char c = 'r' + ((trst ? 0x2 : 0x0) | (srst ? 0x1 : 0x0));
    djm_buff[djm_buff_len++] = c;
    packet_flush();
    return ERROR_OK;
}

COMMAND_HANDLER(djm_handle_djm_tty_command){
    if ( CMD_ARGC == 1 ){
        free(djm_tty);
        djm_tty = strdup(CMD_ARGV[0]);
        return ERROR_OK;
    }
    return ERROR_COMMAND_SYNTAX_ERROR;
}

static const struct command_registration djm_cubcommands_handlers[] = {
    {
        .name = "tty",
        .mode = COMMAND_CONFIG,
        .help = "set tty",
        .handler = djm_handle_djm_tty_command,
        .usage = "<tty_file>",
    },
    COMMAND_REGISTRATION_DONE
};

static const struct command_registration djm_commands_handlers[] = {
    {
        .name = "djm",
        .mode = COMMAND_CONFIG,
        .help = "peerform djm managment",
        .chain = djm_cubcommands_handlers,
        .usage = "",
    },
    COMMAND_REGISTRATION_DONE
};

static struct jtag_interface djm_interface = {
    .execute_queue = djm_execute_queue,
};

struct adapter_driver djm_adapter_driver = {
    .name = "djm",
    .transports = jtag_only,
    .commands = djm_commands_handlers,

    .init = djm_init,
    .quit = djm_quit,
    .reset = djm_reset,
    .speed = djm_speed,
    .khz = djm_khz,
    .speed_div = djm_speed_div,

    .jtag_ops = &djm_interface,
};
