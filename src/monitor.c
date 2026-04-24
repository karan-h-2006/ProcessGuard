#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>
#include "monitor.h"
#include "detection.h"
#include "control.h"

typedef struct {
    ProcessInfo *items;
    size_t count;
    size_t capacity;
} ProcessList;

typedef struct {
    int pid;
    unsigned long long process_ticks;
    int seen_this_cycle;
} CpuHistory;

#define CPU_HISTORY_MAX 8192

static volatile sig_atomic_t keep_monitoring = 1;
static CpuHistory cpu_history[CPU_HISTORY_MAX];
static size_t cpu_history_count = 0;
static unsigned long long previous_total_cpu_ticks = 0;

static int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit((unsigned char) *str)) {
            return 0;
        }
        str++;
    }
    return 1;
}

static void write_json_string(FILE *fp, const char *value) {
    const unsigned char *cursor = (const unsigned char *) value;

    fputc('"', fp);
    while (*cursor) {
        switch (*cursor) {
            case '\\':
                fputs("\\\\", fp);
                break;
            case '"':
                fputs("\\\"", fp);
                break;
            case '\n':
                fputs("\\n", fp);
                break;
            case '\r':
                fputs("\\r", fp);
                break;
            case '\t':
                fputs("\\t", fp);
                break;
            default:
                if (*cursor < 0x20) {
                    fprintf(fp, "\\u%04x", *cursor);
                } else {
                    fputc(*cursor, fp);
                }
        }
        cursor++;
    }
    fputc('"', fp);
}

static int ensure_capacity(ProcessList *list) {
    ProcessInfo *expanded;
    size_t new_capacity;

    if (list->count < list->capacity) {
        return 1;
    }

    new_capacity = list->capacity == 0 ? 128 : list->capacity * 2;
    expanded = (ProcessInfo *) realloc(list->items, new_capacity * sizeof(ProcessInfo));
    if (!expanded) {
        return 0;
    }

    list->items = expanded;
    list->capacity = new_capacity;
    return 1;
}

static unsigned long long read_total_cpu_ticks(void) {
    FILE *fp = fopen("/proc/stat", "r");
    unsigned long long user = 0;
    unsigned long long nice = 0;
    unsigned long long system = 0;
    unsigned long long idle = 0;
    unsigned long long iowait = 0;
    unsigned long long irq = 0;
    unsigned long long softirq = 0;
    unsigned long long steal = 0;

    if (!fp) {
        return 0;
    }

    if (fscanf(fp, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) != 8) {
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return user + nice + system + idle + iowait + irq + softirq + steal;
}

static int read_process_status_fields(int pid, ProcessInfo *info) {
    char path[256];
    FILE *fp;
    char line[256];

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Name:", 5) == 0) {
            sscanf(line, "Name:%255s", info->name);
        } else if (strncmp(line, "State:", 6) == 0) {
            sscanf(line, "State:%15s", info->state);
        } else if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%u", &info->uid);
        } else if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS:%ld kB", &info->memory_kb);
        } else if (strncmp(line, "Threads:", 8) == 0) {
            sscanf(line, "Threads:%d", &info->threads);
        }
    }

    fclose(fp);
    return 1;
}

static int should_export_process(const ProcessInfo *info) {
    if (info->state[0] == 'Z' || info->state[0] == 'X' || info->state[0] == '\0') {
        return 0;
    }

    return 1;
}

static int parse_stat_after_comm(const char *after_comm, int *ppid, unsigned long long *utime,
                                 unsigned long long *stime, long *threads,
                                 unsigned long long *start_time) {
    char buffer[2048];
    char *token;
    char *saveptr = NULL;
    int field = 3;

    strncpy(buffer, after_comm, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    token = strtok_r(buffer, " ", &saveptr);
    while (token != NULL) {
        if (field == 4) {
            *ppid = atoi(token);
        } else if (field == 14) {
            *utime = strtoull(token, NULL, 10);
        } else if (field == 15) {
            *stime = strtoull(token, NULL, 10);
        } else if (field == 20) {
            *threads = strtol(token, NULL, 10);
        } else if (field == 22) {
            *start_time = strtoull(token, NULL, 10);
            return 1;
        }

        field++;
        token = strtok_r(NULL, " ", &saveptr);
    }

    return 0;
}

static int read_process_stat_fields(int pid, ProcessInfo *info) {
    char path[256];
    FILE *fp;
    char line[2048];
    char *comm_end;
    char *after_comm;
    unsigned long long utime = 0;
    unsigned long long stime = 0;
    long threads = 0;
    unsigned long long start_time = 0;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }

    fclose(fp);

    comm_end = strrchr(line, ')');
    if (!comm_end || !comm_end[1] || comm_end[1] != ' ') {
        return 0;
    }

    after_comm = comm_end + 2;
    if (!parse_stat_after_comm(after_comm, &info->ppid, &utime, &stime, &threads, &start_time)) {
        return 0;
    }

    info->cpu_ticks = utime + stime;
    info->threads = info->threads > 0 ? info->threads : (int) threads;
    return 1;
}

static void read_cmdline(int pid, char *buffer, size_t size) {
    char path[256];
    FILE *fp;
    size_t bytes_read;
    size_t i;

    buffer[0] = '\0';
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return;
    }

    bytes_read = fread(buffer, 1, size - 1, fp);
    fclose(fp);

    if (bytes_read == 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    for (i = 0; i < bytes_read; i++) {
        if (buffer[i] == '\0') {
            buffer[i] = ' ';
        }
    }
}

static int count_open_fds(int pid, int *fd_count, int *socket_count, int *access_denied) {
    char fd_path[256];
    DIR *fd_dir;
    struct dirent *fd_entry;

    *fd_count = 0;
    *socket_count = 0;
    *access_denied = 0;

    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
    fd_dir = opendir(fd_path);
    if (!fd_dir) {
        if (errno == EACCES || errno == EPERM) {
            *access_denied = 1;
        }
        return 0;
    }

    while ((fd_entry = readdir(fd_dir)) != NULL) {
        char fd_target_path[PATH_MAX];
        char target_value[PATH_MAX];
        ssize_t target_len;

        if (fd_entry->d_name[0] == '.') {
            continue;
        }

        (*fd_count)++;
        snprintf(fd_target_path, sizeof(fd_target_path), "%s/%s", fd_path, fd_entry->d_name);
        target_len = readlink(fd_target_path, target_value, sizeof(target_value) - 1);
        if (target_len > 0) {
            target_value[target_len] = '\0';
            if (strncmp(target_value, "socket:", 7) == 0) {
                (*socket_count)++;
            }
        }
    }

    closedir(fd_dir);
    return 1;
}

static double compute_runtime_seconds(int pid) {
    char path[256];
    FILE *fp;
    double uptime = 0.0;
    long ticks_per_second = sysconf(_SC_CLK_TCK);
    char line[2048];
    char *comm_end;
    char *after_comm;
    int ppid = 0;
    unsigned long long utime = 0;
    unsigned long long stime = 0;
    long threads = 0;
    unsigned long long start_time = 0;

    fp = fopen("/proc/uptime", "r");
    if (!fp) {
        return 0.0;
    }

    if (fscanf(fp, "%lf", &uptime) != 1) {
        fclose(fp);
        return 0.0;
    }
    fclose(fp);

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return 0.0;
    }

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0.0;
    }

    fclose(fp);

    comm_end = strrchr(line, ')');
    if (!comm_end || !comm_end[1] || comm_end[1] != ' ') {
        return 0.0;
    }

    after_comm = comm_end + 2;
    if (!parse_stat_after_comm(after_comm, &ppid, &utime, &stime, &threads, &start_time)) {
        return 0.0;
    }

    return uptime - ((double) start_time / (double) ticks_per_second);
}

static int find_cpu_history_index(int pid) {
    size_t i;

    for (i = 0; i < cpu_history_count; i++) {
        if (cpu_history[i].pid == pid) {
            return (int) i;
        }
    }

    return -1;
}

static void cleanup_cpu_history(void) {
    size_t i = 0;

    while (i < cpu_history_count) {
        if (!cpu_history[i].seen_this_cycle) {
            cpu_history[i] = cpu_history[cpu_history_count - 1];
            cpu_history_count--;
        } else {
            i++;
        }
    }
}

static void compute_cpu_percent(ProcessInfo *info, unsigned long long total_cpu_ticks) {
    int history_index = find_cpu_history_index(info->pid);
    unsigned long long total_delta = total_cpu_ticks - previous_total_cpu_ticks;

    info->cpu_percent = 0.0;

    if (history_index >= 0 && total_delta > 0 && info->cpu_ticks >= cpu_history[history_index].process_ticks) {
        unsigned long long process_delta = info->cpu_ticks - cpu_history[history_index].process_ticks;
        info->cpu_percent = ((double) process_delta * 100.0) / (double) total_delta;
        cpu_history[history_index].process_ticks = info->cpu_ticks;
        cpu_history[history_index].seen_this_cycle = 1;
        return;
    }

    if (cpu_history_count < CPU_HISTORY_MAX) {
        cpu_history[cpu_history_count].pid = info->pid;
        cpu_history[cpu_history_count].process_ticks = info->cpu_ticks;
        cpu_history[cpu_history_count].seen_this_cycle = 1;
        cpu_history_count++;
    }
}

static int capture_processes(ProcessList *list, int *access_limited_count) {
    DIR *dir;
    struct dirent *entry;
    unsigned long long total_cpu_ticks = read_total_cpu_ticks();
    size_t i;

    *access_limited_count = 0;
    list->count = 0;

    for (i = 0; i < cpu_history_count; i++) {
        cpu_history[i].seen_this_cycle = 0;
    }

    dir = opendir("/proc");
    if (dir == NULL) {
        perror("Failed to open /proc directory");
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        ProcessInfo info;
        int pid;

        if (!is_numeric(entry->d_name)) {
            continue;
        }

        pid = atoi(entry->d_name);
        memset(&info, 0, sizeof(info));
        info.pid = pid;

        if (!read_process_status_fields(pid, &info) || !read_process_stat_fields(pid, &info)) {
            continue;
        }

        if (!should_export_process(&info)) {
            continue;
        }

        read_cmdline(pid, info.cmdline, sizeof(info.cmdline));
        info.runtime_seconds = compute_runtime_seconds(pid);

        count_open_fds(pid, &info.fd_count, &info.socket_count, &info.fd_access_denied);
        if (info.fd_access_denied) {
            (*access_limited_count)++;
        }

        compute_cpu_percent(&info, total_cpu_ticks);

        if (!ensure_capacity(list)) {
            fprintf(stderr, "Failed to allocate memory for process list.\n");
            closedir(dir);
            return 0;
        }

        list->items[list->count++] = info;
    }

    closedir(dir);

    for (i = 0; i < list->count; i++) {
        size_t j;
        int children = 0;

        for (j = 0; j < list->count; j++) {
            if (list->items[j].ppid == list->items[i].pid) {
                children++;
            }
        }
        list->items[i].children_count = children;
        analyze_process(&list->items[i]);
    }

    previous_total_cpu_ticks = total_cpu_ticks;
    cleanup_cpu_history();
    return 1;
}

static void write_snapshot_json(const ProcessList *list, int scan_number, unsigned interval_seconds, int access_limited_count) {
    char timestamp[64];
    char temp_path[] = "live_state.json.tmp";
    FILE *json_fp;
    time_t now;
    struct tm tm_now;
    size_t i;
    int alert_count = 0;
    int action_count = 0;
    const DetectionRules *rules = get_rules();

    now = time(NULL);
    gmtime_r(&now, &tm_now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_now);

    for (i = 0; i < list->count; i++) {
        if (list->items[i].alerted) {
            alert_count++;
        }
        if (list->items[i].action_taken) {
            action_count++;
        }
    }

    json_fp = fopen(temp_path, "w");
    if (!json_fp) {
        perror("Failed to write live_state.json");
        return;
    }

    fprintf(json_fp, "{\n");
    fprintf(json_fp, "  \"generated_at\": ");
    write_json_string(json_fp, timestamp);
    fprintf(json_fp, ",\n");
    fprintf(json_fp, "  \"scan_number\": %d,\n", scan_number);
    fprintf(json_fp, "  \"scan_interval_seconds\": %u,\n", interval_seconds);
    fprintf(json_fp, "  \"thresholds\": {\n");
    fprintf(json_fp, "    \"max_memory_kb\": %ld,\n", rules->max_memory_kb);
    fprintf(json_fp, "    \"max_fd_count\": %d,\n", rules->max_fd_count);
    fprintf(json_fp, "    \"max_socket_count\": %d,\n", rules->max_socket_count);
    fprintf(json_fp, "    \"max_threads\": %d,\n", rules->max_threads);
    fprintf(json_fp, "    \"max_cpu_percent\": %.1f,\n", rules->max_cpu_percent);
    fprintf(json_fp, "    \"max_children_per_ppid\": %d,\n", rules->max_children_per_ppid);
    fprintf(json_fp, "    \"min_alert_score\": %d\n", rules->min_alert_score);
    fprintf(json_fp, "  },\n");
    fprintf(json_fp, "  \"summary\": {\n");
    fprintf(json_fp, "    \"process_count\": %zu,\n", list->count);
    fprintf(json_fp, "    \"alert_count\": %d,\n", alert_count);
    fprintf(json_fp, "    \"action_count\": %d,\n", action_count);
    fprintf(json_fp, "    \"fd_access_limited_count\": %d\n", access_limited_count);
    fprintf(json_fp, "  },\n");
    fprintf(json_fp, "  \"processes\": [\n");

    for (i = 0; i < list->count; i++) {
        const ProcessInfo *process = &list->items[i];

        fprintf(json_fp, "    {\n");
        fprintf(json_fp, "      \"pid\": %d,\n", process->pid);
        fprintf(json_fp, "      \"ppid\": %d,\n", process->ppid);
        fprintf(json_fp, "      \"uid\": %u,\n", process->uid);
        fprintf(json_fp, "      \"name\": ");
        write_json_string(json_fp, process->name);
        fprintf(json_fp, ",\n");
        fprintf(json_fp, "      \"state\": ");
        write_json_string(json_fp, process->state);
        fprintf(json_fp, ",\n");
        fprintf(json_fp, "      \"cmdline\": ");
        write_json_string(json_fp, process->cmdline);
        fprintf(json_fp, ",\n");
        fprintf(json_fp, "      \"memory_kb\": %ld,\n", process->memory_kb);
        fprintf(json_fp, "      \"memory_delta_kb\": %ld,\n", process->memory_delta_kb);
        fprintf(json_fp, "      \"fd_count\": %d,\n", process->fd_count);
        fprintf(json_fp, "      \"socket_count\": %d,\n", process->socket_count);
        fprintf(json_fp, "      \"threads\": %d,\n", process->threads);
        fprintf(json_fp, "      \"children_count\": %d,\n", process->children_count);
        fprintf(json_fp, "      \"cpu_percent\": %.2f,\n", process->cpu_percent);
        fprintf(json_fp, "      \"runtime_seconds\": %.2f,\n", process->runtime_seconds);
        fprintf(json_fp, "      \"fd_access_denied\": %s,\n", process->fd_access_denied ? "true" : "false");
        fprintf(json_fp, "      \"alerted\": %s,\n", process->alerted ? "true" : "false");
        fprintf(json_fp, "      \"memory_alert\": %s,\n", process->memory_alert ? "true" : "false");
        fprintf(json_fp, "      \"fd_alert\": %s,\n", process->fd_alert ? "true" : "false");
        fprintf(json_fp, "      \"socket_alert\": %s,\n", process->socket_alert ? "true" : "false");
        fprintf(json_fp, "      \"thread_alert\": %s,\n", process->thread_alert ? "true" : "false");
        fprintf(json_fp, "      \"cpu_alert\": %s,\n", process->cpu_alert ? "true" : "false");
        fprintf(json_fp, "      \"growth_alert\": %s,\n", process->growth_alert ? "true" : "false");
        fprintf(json_fp, "      \"fork_alert\": %s,\n", process->fork_alert ? "true" : "false");
        fprintf(json_fp, "      \"alert_score\": %d,\n", process->alert_score);
        fprintf(json_fp, "      \"sustained_alerts\": %d,\n", process->sustained_alerts);
        fprintf(json_fp, "      \"action_taken\": %s,\n", process->action_taken ? "true" : "false");
        fprintf(json_fp, "      \"protected_process\": %s,\n", process->protected_process ? "true" : "false");
        fprintf(json_fp, "      \"user_allowed\": %s,\n", process->user_allowed ? "true" : "false");
        fprintf(json_fp, "      \"simulation_match\": %s,\n", process->simulation_match ? "true" : "false");
        fprintf(json_fp, "      \"action_label\": ");
        write_json_string(json_fp, process->action_label);
        fprintf(json_fp, ",\n");
        fprintf(json_fp, "      \"category\": ");
        write_json_string(json_fp, process->category);
        fprintf(json_fp, ",\n");
        fprintf(json_fp, "      \"alert_reason\": ");
        write_json_string(json_fp, process->alert_reason);
        fprintf(json_fp, "\n    }%s\n", i + 1 == list->count ? "" : ",");
    }

    fprintf(json_fp, "  ]\n");
    fprintf(json_fp, "}\n");
    fclose(json_fp);

    if (rename(temp_path, "live_state.json") != 0) {
        perror("Failed to update live_state.json");
    }
}

static void print_cycle_summary(const ProcessList *list, int scan_number, int access_limited_count) {
    size_t i;
    int alert_count = 0;
    int action_count = 0;

    for (i = 0; i < list->count; i++) {
        if (list->items[i].alerted) {
            alert_count++;
        }
        if (list->items[i].action_taken) {
            action_count++;
        }
    }

    printf("[MONITOR] Scan #%d complete: %zu processes, %d alerts, %d actions, %d limited FD reads.\n",
           scan_number, list->count, alert_count, action_count, access_limited_count);
    fflush(stdout);
}

void handle_monitor_signal(int signum) {
    (void) signum;
    keep_monitoring = 0;
}

void scan_processes(void) {
    ProcessList list = {0};
    int access_limited_count = 0;

    begin_detection_cycle();
    if (capture_processes(&list, &access_limited_count)) {
        end_detection_cycle();
        write_snapshot_json(&list, 1, 0, access_limited_count);
        print_cycle_summary(&list, 1, access_limited_count);
    }

    free(list.items);
}

void run_monitor_loop(unsigned interval_seconds) {
    ProcessList list = {0};
    int scan_number = 0;

    while (keep_monitoring) {
        int access_limited_count = 0;

        scan_number++;
        process_control_queue();
        begin_detection_cycle();

        if (capture_processes(&list, &access_limited_count)) {
            end_detection_cycle();
            write_snapshot_json(&list, scan_number, interval_seconds, access_limited_count);
            print_cycle_summary(&list, scan_number, access_limited_count);
        }

        if (!keep_monitoring) {
            break;
        }

        sleep(interval_seconds);
    }

    free(list.items);
    printf("\n[MONITOR] Monitoring stopped.\n");
}
