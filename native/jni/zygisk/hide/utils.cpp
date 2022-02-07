#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <set>

#include <magisk.hpp>
#include <utils.hpp>
#include <db.hpp>

#include "hide.hpp"

using namespace std;

// Package name -> list of process names
using str_set = set<string, StringCmp>;
static map<string, str_set, StringCmp> *hide_map_;
#define hide_map (*hide_map_)

// app ID -> list of process name
static map<int, vector<string_view>> *uid_proc_map;
static int inotify_fd = -1;

// Locks the variables above
static pthread_mutex_t hide_state_lock = PTHREAD_MUTEX_INITIALIZER;

atomic<bool> hide_enabled = false;

#define do_kill (zygisk_enabled && hide_enabled)

static void update_uid_map() {
    if (!do_kill)
        return;
    uid_proc_map->clear();
    string data_path(APP_DATA_DIR);
    size_t len = data_path.length();

    // Collect all user IDs
    vector<string> users;
    if (auto dir = open_dir(APP_DATA_DIR)) {
        for (dirent *entry; (entry = xreaddir(dir.get()));) {
            users.emplace_back(entry->d_name);
        }
    } else {
        return;
    }

    for (const auto &[pkg, procs] : hide_map) {
        int app_id = -1;
        if (pkg != ISOLATED_MAGIC) {
            // Traverse the filesystem to find app ID
            for (const auto &user_id : users) {
                data_path.resize(len);
                data_path += '/';
                data_path += user_id;
                data_path += '/';
                data_path += pkg;
                struct stat st{};
                if (stat(data_path.data(), &st) != 0) {
                    app_id = to_app_id(st.st_uid);
                    break;
                }
            }
            if (app_id < 0)
                continue;
        }

        for (const auto &proc : procs) {
            (*uid_proc_map)[app_id].emplace_back(proc);

        }
    }
}

// Leave /proc fd opened as we're going to read from it repeatedly
static DIR *procfp;
void crawl_procfs(const function<bool(int)> &fn) {
    rewinddir(procfp);
    crawl_procfs(procfp, fn);
}

void crawl_procfs(DIR *dir, const function<bool(int)> &fn) {
    struct dirent *dp;
    int pid;
    while ((dp = readdir(dir))) {
        pid = parse_int(dp->d_name);
        if (pid > 0 && !fn(pid))
            break;
    }
}

template <bool str_op(string_view, string_view)>
static bool proc_name_match(int pid, const char *name) {
    char buf[4019];
    sprintf(buf, "/proc/%d/cmdline", pid);
    if (auto fp = open_file(buf, "re")) {
        fgets(buf, sizeof(buf), fp.get());
        if (str_op(buf, name)) {
            LOGD("hide: kill PID=[%d] (%s)\n", pid, buf);
            return true;
        }
    }
    return false;
}

static inline bool str_eql(string_view s, string_view ss) { return s == ss; }

static void kill_process(const char *name, bool multi = false,
        bool (*filter)(int, const char *) = proc_name_match<&str_eql>) {
    crawl_procfs([=](int pid) -> bool {
        if (filter(pid, name)) {
            kill(pid, SIGKILL);
            return multi;
        }
        return true;
    });
}

static bool validate(const char *pkg, const char *proc) {
    bool pkg_valid = false;
    bool proc_valid = true;

    if (str_eql(pkg, ISOLATED_MAGIC)) {
        pkg_valid = true;
        for (char c; (c = *proc); ++proc) {
            if (isalnum(c) || c == '_' || c == '.')
                continue;
            if (c == ':')
                break;
            proc_valid = false;
            break;
        }
    } else {
        for (char c; (c = *pkg); ++pkg) {
            if (isalnum(c) || c == '_')
                continue;
            if (c == '.') {
                pkg_valid = true;
                continue;
            }
            pkg_valid = false;
            break;
        }

        for (char c; (c = *proc); ++proc) {
            if (isalnum(c) || c == '_' || c == ':' || c == '.')
                continue;
            proc_valid = false;
            break;
        }
    }
    return pkg_valid && proc_valid;
}

static bool add_hide_set(const char *pkg, const char *proc) {
    auto p = hide_map[pkg].emplace(proc);
    if (!p.second)
        return false;
    LOGI("hide_list add: [%s/%s]\n", pkg, proc);
    if (!do_kill)
        return true;;
    if (str_eql(pkg, ISOLATED_MAGIC)) {
        // Kill all matching isolated processes
        kill_process(proc, true, proc_name_match<&str_starts>);
    } else {
        kill_process(proc);
    }
    return true;
}

static void inotify_handler(pollfd *pfd) {
    union {
        inotify_event event;
        char buf[512];
    } u{};
    read(pfd->fd, u.buf, sizeof(u.buf));
    if (u.event.name == "packages.xml"sv) {
        cached_manager_app_id = -1;
        exec_task([] {
            mutex_guard lock(hide_state_lock);
            update_uid_map();
        });
    }
}

static bool init_list() {
    if (uid_proc_map)
        return true;

    LOGI("hide_list: initializing internal data structures\n");

    default_new(hide_map_);
    char *err = db_exec("SELECT * FROM hidelist", [](db_row &row) -> bool {
        add_hide_set(row["package_name"].data(), row["process"].data());
        return true;
    });
    db_err_cmd(err, goto error);

    default_new(uid_proc_map);
    update_uid_map();

    inotify_fd = xinotify_init1(IN_CLOEXEC);
    if (inotify_fd < 0) {
        goto error;
    } else {
        // Monitor packages.xml
        inotify_add_watch(inotify_fd, "/data/system", IN_CLOSE_WRITE);
        pollfd inotify_pfd = { inotify_fd, POLLIN, 0 };
        register_poll(&inotify_pfd, inotify_handler);
    }

    return true;

error:
    return false;
}

static int add_list(const char *pkg, const char *proc) {
    if (proc[0] == '\0')
        proc = pkg;

    if (!validate(pkg, proc))
        return HIDE_INVALID_PKG;

    {
        mutex_guard lock(hide_state_lock);
        if (!init_list())
            return DAEMON_ERROR;
        if (!add_hide_set(pkg, proc))
            return HIDE_ITEM_EXIST;
        update_uid_map();
    }

    // Add to database
    char sql[4096];
    snprintf(sql, sizeof(sql),
            "INSERT INTO hidelist (package_name, process) VALUES('%s', '%s')", pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DAEMON_ERROR);
    return DAEMON_SUCCESS;
}

int add_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return add_list(pkg.data(), proc.data());
}

static int rm_list(const char *pkg, const char *proc) {
    {
        mutex_guard lock(hide_state_lock);
        if (!init_list())
            return DAEMON_ERROR;

        bool remove = false;

        if (proc[0] == '\0') {
            if (hide_map.erase(pkg) != 0) {
                remove = true;
                LOGI("hide_list rm: [%s]\n", pkg);
            }
        } else {
            auto it = hide_map.find(pkg);
            if (it != hide_map.end()) {
                if (it->second.erase(proc) != 0) {
                    remove = true;
                    LOGI("hide_list rm: [%s/%s]\n", pkg, proc);
                }
            }
        }
        if (!remove)
            return HIDE_ITEM_NOT_EXIST;
        update_uid_map();
    }

    char sql[4096];
    if (proc[0] == '\0')
        snprintf(sql, sizeof(sql), "DELETE FROM hidelist WHERE package_name='%s'", pkg);
    else
        snprintf(sql, sizeof(sql),
                "DELETE FROM hidelist WHERE package_name='%s' AND process='%s'", pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DAEMON_ERROR);
    return DAEMON_SUCCESS;
}

int rm_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return rm_list(pkg.data(), proc.data());
}

void ls_list(int client) {
    {
        mutex_guard lock(hide_state_lock);
        if (!init_list()) {
            write_int(client, DAEMON_ERROR);
            return;
        }

        write_int(client, DAEMON_SUCCESS);

        for (const auto &[pkg, procs] : hide_map) {
            for (const auto &proc : procs) {
                write_int(client, pkg.size() + proc.size() + 1);
                xwrite(client, pkg.data(), pkg.size());
                xwrite(client, "|", 1);
                xwrite(client, proc.data(), proc.size());
            }
        }
    }
    write_int(client, 0);
    close(client);
}

static bool str_ends_safe(string_view s, string_view ss) {
    // Never kill webview zygote
    if (s == "webview_zygote")
        return false;
    return str_ends(s, ss);
}

static void update_hide_config() {
    char sql[64];
    sprintf(sql, "REPLACE INTO settings (key,value) VALUES('%s',%d)",
            DB_SETTING_KEYS[HIDE_CONFIG], hide_enabled.load());
    char *err = db_exec(sql);
    db_err(err);
}

static int new_daemon_thread(void(*entry)()) {
    thread_entry proxy = [](void *entry) -> void * {
        reinterpret_cast<void(*)()>(entry)();
        return nullptr;
    };
    return new_daemon_thread(proxy, (void *) entry);
}

#define SNET_PROC    "com.google.android.gms.unstable"
#define GMS_PKG      "com.google.android.gms"

int launch_magiskhide(bool late_props) {
    if (hide_enabled) {
        return DAEMON_SUCCESS;
    } else {
        mutex_guard lock(hide_state_lock);

        if (access("/proc/self/ns/mnt", F_OK) != 0) {
            LOGW("The kernel does not support mount namespace\n");
            return HIDE_NO_NS;
        }

        if (procfp == nullptr && (procfp = opendir("/proc")) == nullptr)
            return DAEMON_ERROR;

        LOGI("* Enable MagiskHide\n");

        // Initialize the hide list
        hide_enabled = true;
        if (!init_list()) {
            hide_enabled = false;
            return DAEMON_ERROR;
        }

        // If Android Q+, also kill blastula pool and all app zygotes
        if (SDK_INT >= 29 && zygisk_enabled) {
            kill_process("usap32", true);
            kill_process("usap64", true);
            kill_process("_zygote", true, proc_name_match<&str_ends_safe>);
        }

        // Add SafetyNet by default
        add_hide_set(GMS_PKG, SNET_PROC);

        // We also need to hide the default GMS process if MAGISKTMP != /sbin
        // The snet process communicates with the main process and get additional info
        if (MAGISKTMP != "/sbin")
            add_hide_set(GMS_PKG, GMS_PKG);

        hide_sensitive_props();
        if (late_props)
            hide_late_sensitive_props();

        // Start monitoring
        if (new_daemon_thread(&proc_monitor))
            return DAEMON_ERROR;

        // Unlock here or else we'll be stuck in deadlock
        lock.unlock();

        update_uid_map();
    }

    update_hide_config();
    return DAEMON_SUCCESS;
}

int stop_magiskhide() {
    mutex_guard lock(hide_state_lock);

    if (hide_enabled) {
        LOGI("* Disable MagiskHide\n");
        delete hide_map_;
        delete uid_proc_map;
        hide_map_ = nullptr;
        uid_proc_map = nullptr;
        unregister_poll(inotify_fd, true);
        inotify_fd = -1;
    }

    // Stop monitoring
    pthread_kill(monitor_thread, SIGTERMTHRD);

    hide_enabled = false;
    update_hide_config();
    return DAEMON_SUCCESS;
}

void auto_start_magiskhide(bool late_props) {
    if (hide_enabled) {
        pthread_kill(monitor_thread, SIGALRM);
        hide_late_sensitive_props();
    } else {
        db_settings dbs;
        get_db_settings(dbs, HIDE_CONFIG);
        if (dbs[HIDE_CONFIG])
            launch_magiskhide(late_props);
    }
}

bool is_hide_target(int uid, string_view process, int max_len) {
    mutex_guard lock(hide_state_lock);
    if (!init_list())
        return false;

    int app_id = to_app_id(uid);
    if (app_id >= 90000) {
        // Isolated processes
        auto it = uid_proc_map->find(-1);
        if (it == uid_proc_map->end())
            return false;

        for (const auto &s : it->second) {
            if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                return true;
            if (str_starts(process, s))
                return true;
        }
    } else {
        auto it = uid_proc_map->find(app_id);
        if (it == uid_proc_map->end())
            return false;

        for (const auto &s : it->second) {
            if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                return true;
            if (s == process)
                return true;
        }
    }
    return false;
}

void test_proc_monitor() {
    if (procfp == nullptr && (procfp = opendir("/proc")) == nullptr)
        exit(1);
    proc_monitor();
}
