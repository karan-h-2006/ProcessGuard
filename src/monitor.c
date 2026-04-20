#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include "monitor.h"
#include "detection.h"

static volatile sig_atomic_t keep_monitoring = 1;

typedef struct {
    ProcessInfo *items;
    size_t count;
    size_t capacity;
} ProcessList;

static int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit((unsigned char) *str)) return 0;
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

static int read_process_name(int pid, char *name, size_t size) {
    char path[256];
    FILE *fp_comm;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    fp_comm = fopen(path, "r");
    if (!fp_comm) {
        return 0;
    }

    if (!fgets(name, (int) size, fp_comm)) {
        fclose(fp_comm);
        return 0;
    }

    name[strcspn(name, "\n")] = '\0';
    fclose(fp_comm);
    return 1;
}

static long read_memory_kb(int pid) {
    char path[256];
    char line[256];
    long mem_kb = 0;
    FILE *fp_status;

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fp_status = fopen(path, "r");
    if (!fp_status) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp_status)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS: %ld kB", &mem_kb);
            break;
        }
    }

    fclose(fp_status);
    return mem_kb;
}

static int count_open_fds(int pid, int *fd_count, int *access_denied) {
    char fd_path[256];
    DIR *fd_dir;
    struct dirent *fd_entry;

    *fd_count = 0;
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
        if (fd_entry->d_name[0] != '.') {
            (*fd_count)++;
        }
    }

    closedir(fd_dir);
    return 1;
}

static int capture_processes(ProcessList *list, int *access_limited_count) {
    DIR *dir;
    struct dirent *entry;

    *access_limited_count = 0;
    list->count = 0;

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

        if (!read_process_name(pid, info.name, sizeof(info.name))) {
            continue;
        }

        info.memory_kb = read_memory_kb(pid);
        if (info.memory_kb <= 0) {
            continue;
        }

        count_open_fds(pid, &info.fd_count, &info.fd_access_denied);
        if (info.fd_access_denied) {
            (*access_limited_count)++;
        }

        analyze_process(&info);

        if (!ensure_capacity(list)) {
            fprintf(stderr, "Failed to allocate memory for process list.\n");
            closedir(dir);
            return 0;
        }

        list->items[list->count++] = info;
    }

    closedir(dir);
    return 1;
}

static void write_snapshot_json(const ProcessList *list, int scan_number, unsigned interval_seconds,int access_limited_count) {
    char timestamp[64];
    char temp_path[] = "live_state.json.tmp";
    FILE *json_fp;
    time_t now;
    struct tm tm_now;
    size_t i;
    int alert_count = 0;
    int action_count = 0;

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
    fprintf(json_fp, "    \"max_memory_kb\": %ld,\n", get_max_memory_kb());
    fprintf(json_fp, "    \"max_fd_count\": %d\n", get_max_fd_count());
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
        fprintf(json_fp, "      \"name\": ");
        write_json_string(json_fp, process->name);
        fprintf(json_fp, ",\n");
        fprintf(json_fp, "      \"memory_kb\": %ld,\n", process->memory_kb);
        fprintf(json_fp, "      \"fd_count\": %d,\n", process->fd_count);
        fprintf(json_fp, "      \"fd_access_denied\": %s,\n", process->fd_access_denied ? "true" : "false");
        fprintf(json_fp, "      \"alerted\": %s,\n", process->alerted ? "true" : "false");
        fprintf(json_fp, "      \"memory_alert\": %s,\n", process->memory_alert ? "true" : "false");
        fprintf(json_fp, "      \"fd_alert\": %s,\n", process->fd_alert ? "true" : "false");
        fprintf(json_fp, "      \"action_taken\": %s,\n", process->action_taken ? "true" : "false");
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

    for (i = 0; i < list->count; i++) {
        if (list->items[i].alerted) {
            alert_count++;
        }
    }

    printf("[MONITOR] Scan #%d complete: %zu processes, %d alerts, %d limited FD reads.\n",
           scan_number, list->count, alert_count, access_limited_count);
    fflush(stdout);
}

void handle_monitor_signal(int signum) {
    (void) signum;
    keep_monitoring = 0;
}

void scan_processes() {
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
