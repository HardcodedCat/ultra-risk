#pragma once

#include <pthread.h>
#include <poll.h>
#include <string>
#include <limits>
#include <atomic>
#include <functional>

#include <socket.hpp>

// Daemon command code flags/masks
enum : int {
    SYNC_FLAG = (1 << 30),
    DAEMON_CODE_MASK = std::numeric_limits<int>::max() >> 1
};

// Daemon command codes
enum : int {
    START_DAEMON = SYNC_FLAG | 0,
    CHECK_VERSION = SYNC_FLAG | 1,
    CHECK_VERSION_CODE = SYNC_FLAG | 2,
    GET_PATH = SYNC_FLAG | 3,
    STOP_DAEMON = SYNC_FLAG | 4,
    SUPERUSER = 5,
    POST_FS_DATA,
    LATE_START,
    BOOT_COMPLETE,
    MAGISKHIDE,
    SQLITE_CMD,
    REMOVE_MODULES,
    ZYGISK_REQUEST,
    DAEMON_CODE_END
};

// Return codes for daemon
enum : int {
    DAEMON_ERROR = -1,
    DAEMON_SUCCESS = 0,
    ROOT_REQUIRED,
    DAEMON_LAST
};

// Daemon state
enum : int {
    STATE_NONE,
    STATE_POST_FS_DATA,
    STATE_POST_FS_DATA_DONE,
    STATE_LATE_START_DONE,
    STATE_BOOT_COMPLETE
};

extern bool zygisk_enabled;

int connect_daemon(bool create = false);

// Poll control
using poll_callback = void(*)(pollfd*);
void register_poll(const pollfd *pfd, poll_callback callback);
void unregister_poll(int fd, bool auto_close);

// Thread pool
void exec_task(std::function<void()> &&task);

// Logging
extern std::atomic<int> logd_fd;
int magisk_log(int prio, const char *fmt, va_list ap);
void android_logging();

// Daemon handlers
void post_fs_data(int client);
void late_start(int client);
void boot_complete(int client);
void magiskhide_handler(int client, ucred *cred);
void su_daemon_handler(int client, ucred *credential);
void zygisk_handler(int client, ucred *cred);
std::vector<int> zygisk_module_fds(bool is_64_bit);

// MagiskHide
void auto_start_magiskhide(bool late_props);
int stop_magiskhide();

// For injected process to access daemon
int remote_check_hide(int uid, const char *process);
void remote_request_hide();
