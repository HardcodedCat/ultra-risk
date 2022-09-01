#pragma once

#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include <string_view>
#include <functional>
#include <map>
#include <atomic>

#include <daemon.hpp>

#define SIGTERMTHRD SIGUSR1
#define ISOLATED_MAGIC "isolated"

// CLI entries
int launch_magiskhide(bool late_props);
int stop_magiskhide();
int add_hide_list(int client);
int rm_hide_list(int client);
void ls_hide_list(int client);

// Process monitoring
extern pthread_t monitor_thread;
[[noreturn]] void proc_monitor();
[[noreturn]] void test_proc_monitor();

// Utility functions
void crawl_procfs(const std::function<bool (int)> &fn);
void crawl_procfs(DIR *dir, const std::function<bool (int)> &fn);
void update_uid_map();
bool is_hide_target(int uid, std::string_view process, int max_len = 1024);

// Hide policies
void hide_daemon(int pid);
void hide_unmount(int pid = -1);
void hide_sensitive_props();
void hide_late_sensitive_props();

extern std::atomic<bool> hide_enabled;
extern std::atomic<int> cached_manager_app_id;

enum {
    LAUNCH_MAGISKHIDE,
    STOP_MAGISKHIDE,
    ADD_HIDELIST,
    RM_HIDELIST,
    LS_HIDELIST,
    HIDE_STATUS,
};

enum {
    HIDE_IS_ENABLED = DAEMON_LAST + 1,
    HIDE_NOT_ENABLED,
    HIDE_ITEM_EXIST,
    HIDE_ITEM_NOT_EXIST,
    HIDE_NO_NS,
    HIDE_INVALID_PKG,
};
