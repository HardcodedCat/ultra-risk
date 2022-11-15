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
static unique_ptr<map<string, set<string, StringCmp>, StringCmp>> pkg_to_procs_;
#define pkg_to_procs (*pkg_to_procs_)

// app ID -> list of pkg names
static unique_ptr<map<int, set<string_view>>> app_id_to_pkgs_;
#define app_id_to_pkgs (*app_id_to_pkgs_)

// Locks the data structures above
static pthread_mutex_t hide_state_lock = PTHREAD_MUTEX_INITIALIZER;

atomic<bool> hide_enabled = false;

static unsigned long long pkg_xml_ino = 0;

void update_uid_map() {
    {
        struct stat st{};
        stat("/data/system/packages.xml", &st);
        if (pkg_xml_ino == st.st_ino) {
            // Packages has not changed
            return;
        }
        pkg_xml_ino = st.st_ino;
    }

    LOGD("hide_list: rescanning apps\n");

    app_id_to_pkgs.clear();
    cached_manager_app_id = -1;

    auto data_dir = xopen_dir(APP_DATA_DIR);
    if (!data_dir)
        return;
    dirent *entry;
    while ((entry = xreaddir(data_dir.get()))) {
        // For each user
        int dfd = xopenat(dirfd(data_dir.get()), entry->d_name, O_RDONLY);
        if (auto dir = xopen_dir(dfd)) {
            while ((entry = xreaddir(dir.get()))) {
                // For each package
                struct stat st{};
                xfstatat(dfd, entry->d_name, &st, 0);
                int app_id = to_app_id(st.st_uid);
                if (app_id_to_pkgs.contains(app_id)) {
                    // This app ID has been handled
                    continue;
                }
                if (auto it = pkg_to_procs.find(entry->d_name); it != pkg_to_procs.end()) {
                    app_id_to_pkgs[app_id].insert(it->first);
                }
            }
        } else {
            close(dfd);
        }
    }
}

static void update_pkg_uid(const string &pkg, bool remove) {
    auto data_dir = xopen_dir(APP_DATA_DIR);
    if (!data_dir)
        return;
    dirent *entry;
    struct stat st{};
    char buf[PATH_MAX] = {0};
    // For each user
    while ((entry = xreaddir(data_dir.get()))) {
        snprintf(buf, sizeof(buf), "%s/%s", entry->d_name, pkg.data());
        if (fstatat(dirfd(data_dir.get()), buf, &st, 0) == 0) {
            int app_id = to_app_id(st.st_uid);
            if (remove) {
                if (auto it = app_id_to_pkgs.find(app_id); it != app_id_to_pkgs.end()) {
                    it->second.erase(pkg);
                    if (it->second.empty()) {
                        app_id_to_pkgs.erase(it);
                    }
                }
            } else {
                app_id_to_pkgs[app_id].insert(pkg);
            }
            break;
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

static auto add_hide_set(const char *pkg, const char *proc) {
    auto p = pkg_to_procs[pkg].emplace(proc);
    if (!p.second)
        return p;
    LOGI("hide_list add: [%s/%s]\n", pkg, proc);
    if (str_eql(pkg, ISOLATED_MAGIC)) {
        // Kill all matching isolated processes
        kill_process(proc, true, proc_name_match<&str_starts>);
    } else {
        kill_process(proc);
    }
    return p;
}

static bool init_list() {
    if (pkg_to_procs_)
        return true;

    LOGI("hide_list: initializing internal data structures\n");

    default_new(pkg_to_procs_);
    char *err = db_exec("SELECT * FROM hidelist", [](db_row &row) -> bool {
        add_hide_set(row["package_name"].data(), row["process"].data());
        return true;
    });
    db_err_cmd(err, goto error)

    default_new(app_id_to_pkgs_);
    update_uid_map();

    return true;

error:
    return false;
}

static int add_hide_list(const char *pkg, const char *proc) {
    if (proc[0] == '\0')
        proc = pkg;

    if (!validate(pkg, proc))
        return HIDE_INVALID_PKG;

    {
        mutex_guard lock(hide_state_lock);
        if (!init_list())
            return DAEMON_ERROR;
        auto p = add_hide_set(pkg, proc);
        if (!p.second)
            return HIDE_ITEM_EXIST;
        update_pkg_uid(*p.first, false);
    }

    // Add to database
    char sql[4096];
    snprintf(sql, sizeof(sql),
            "INSERT INTO hidelist (package_name, process) VALUES('%s', '%s')", pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DAEMON_ERROR)
    return DAEMON_SUCCESS;
}

int add_hide_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return add_hide_list(pkg.data(), proc.data());
}

static int rm_hide_list(const char *pkg, const char *proc) {
    {
        mutex_guard lock(hide_state_lock);
        if (!init_list())
            return DAEMON_ERROR;

        bool remove = false;

        auto it = pkg_to_procs.find(pkg);
        if (it != pkg_to_procs.end()) {
            if (proc[0] == '\0') {
                update_pkg_uid(it->first, true);
                pkg_to_procs.erase(it);
                remove = true;
                LOGI("hide_list rm: [%s]\n", pkg);
            } else if (it->second.erase(proc) != 0) {
                remove = true;
                LOGI("hide_list rm: [%s/%s]\n", pkg, proc);
                if (it->second.empty()) {
                    update_pkg_uid(it->first, true);
                    pkg_to_procs.erase(it);
                }
            }
        }

        if (!remove)
            return HIDE_ITEM_NOT_EXIST;
    }

    char sql[4096];
    if (proc[0] == '\0')
        snprintf(sql, sizeof(sql), "DELETE FROM hidelist WHERE package_name='%s'", pkg);
    else
        snprintf(sql, sizeof(sql),
                "DELETE FROM hidelist WHERE package_name='%s' AND process='%s'", pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DAEMON_ERROR)
    return DAEMON_SUCCESS;
}

int rm_hide_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    return rm_hide_list(pkg.data(), proc.data());
}

void ls_hide_list(int client) {
    {
        mutex_guard lock(hide_state_lock);
        if (!init_list()) {
            write_int(client, DAEMON_ERROR);
            return;
        }

        write_int(client, DAEMON_SUCCESS);

        for (const auto &[pkg, procs] : pkg_to_procs) {
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

int new_daemon_thread(void(*entry)()) {
    thread_entry proxy = [](void *entry) -> void * {
        reinterpret_cast<void(*)()>(entry)();
        return nullptr;
    };
    return new_daemon_thread(proxy, (void *) entry);
}

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
        if (SDK_INT >= 29) {
            kill_process("usap32", true);
            kill_process("usap64", true);
            kill_process("_zygote", true, proc_name_match<&str_ends_safe>);
        }

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
        pkg_to_procs_.reset(nullptr);
        app_id_to_pkgs_.reset(nullptr);
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

    update_uid_map();

    int app_id = to_app_id(uid);
    if (app_id >= 90000) {
        if (auto it = pkg_to_procs.find(ISOLATED_MAGIC); it != pkg_to_procs.end()) {
            for (const auto &s : it->second) {
                if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                    return true;
                if (str_starts(process, s))
                    return true;
            }
        }
        if (auto it = app_id_to_pkgs.find(-1); it != app_id_to_pkgs.end()) {
            for (const auto &s : it->second) {
                if (s.length() > max_len && process.length() > max_len && str_starts(s, process))
                    return true;
                if (str_starts(process, s))
                    return true;
            }
        }
        return false;
    } else {
        auto it = app_id_to_pkgs.find(app_id);
        if (it == app_id_to_pkgs.end())
            return false;
        for (const auto &pkg : it->second) {
            if (pkg_to_procs.find(pkg)->second.count(process))
                return true;
        }
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

int check_uid_map(int client) {
    if (!hide_enabled)
        return 0;

    int uid = read_int(client);
    string process = read_string(client);
    return is_hide_target(uid, process) ? 1 : 0;
}
