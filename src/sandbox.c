#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include "sandbox.h"
#include "detection.h"
#include "logger.h"

static pid_t active_child = -1;
static char resolved_command_path[PATH_MAX];
static char artifact_stdout_path[PATH_MAX];
static char artifact_stderr_path[PATH_MAX];
static char artifact_stdout_href[PATH_MAX];
static char artifact_stderr_href[PATH_MAX];
static char artifact_run_id[128];

typedef struct {
    long peak_memory_kb;
    int peak_fd_count;
    long peak_threads;
    double runtime_seconds;
    int exit_code;
    int signal_number;
} SandboxRunStats;

static void sandbox_signal_handler(int signum) {
    if (active_child > 0) {
        log_sandbox_event("signal", "interrupted", "sandbox-child", "sandbox interrupted by external signal");
        (void) kill(-active_child, SIGTERM);
        usleep(200000);
        (void) kill(-active_child, SIGKILL);
    }
    _exit(128 + signum);
}

static int apply_limit(int resource, rlim_t value) {
    struct rlimit limit;

    limit.rlim_cur = value;
    limit.rlim_max = value;
    return setrlimit(resource, &limit);
}

static void write_json_string(FILE *fp, const char *value) {
    const unsigned char *cursor = (const unsigned char *) (value ? value : "");

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

static void ensure_artifact_paths(void) {
    time_t now = time(NULL);
    char dir_path[PATH_MAX];

    snprintf(artifact_run_id, sizeof(artifact_run_id), "run-%ld-%d", (long) now, (int) getpid());
    (void) mkdir("sandbox_workspace", 0755);
    (void) mkdir("sandbox_workspace/artifacts", 0755);

    snprintf(dir_path, sizeof(dir_path), "sandbox_workspace/artifacts/%s", artifact_run_id);
    (void) mkdir(dir_path, 0755);

    snprintf(artifact_stdout_path, sizeof(artifact_stdout_path), "%s/stdout.log", dir_path);
    snprintf(artifact_stderr_path, sizeof(artifact_stderr_path), "%s/stderr.log", dir_path);
    snprintf(artifact_stdout_href, sizeof(artifact_stdout_href), "/sandbox-artifacts/%s/stdout.log", artifact_run_id);
    snprintf(artifact_stderr_href, sizeof(artifact_stderr_href), "/sandbox-artifacts/%s/stderr.log", artifact_run_id);
}

static void write_artifact_record(const char *stage,
                                  const char *status,
                                  const char *target,
                                  const char *detail,
                                  const SandboxRunStats *stats) {
    FILE *fp;
    time_t now = time(NULL);
    struct tm tm_now;
    char timestamp[64];

    fp = fopen("sandbox_artifacts.jsonl", "a");
    if (!fp) {
        return;
    }

    gmtime_r(&now, &tm_now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_now);

    fprintf(fp, "{");
    fprintf(fp, "\"timestamp\":");
    write_json_string(fp, timestamp);
    fprintf(fp, ",\"run_id\":");
    write_json_string(fp, artifact_run_id);
    fprintf(fp, ",\"stage\":");
    write_json_string(fp, stage);
    fprintf(fp, ",\"status\":");
    write_json_string(fp, status);
    fprintf(fp, ",\"target\":");
    write_json_string(fp, target);
    fprintf(fp, ",\"detail\":");
    write_json_string(fp, detail);
    fprintf(fp, ",\"stdout_path\":");
    write_json_string(fp, artifact_stdout_path);
    fprintf(fp, ",\"stderr_path\":");
    write_json_string(fp, artifact_stderr_path);
    fprintf(fp, ",\"stdout_href\":");
    write_json_string(fp, artifact_stdout_href);
    fprintf(fp, ",\"stderr_href\":");
    write_json_string(fp, artifact_stderr_href);
    fprintf(fp, ",\"peak_memory_kb\":%ld", stats ? stats->peak_memory_kb : 0L);
    fprintf(fp, ",\"peak_fd_count\":%d", stats ? stats->peak_fd_count : 0);
    fprintf(fp, ",\"peak_threads\":%ld", stats ? stats->peak_threads : 0L);
    fprintf(fp, ",\"runtime_seconds\":%.2f", stats ? stats->runtime_seconds : 0.0);
    fprintf(fp, ",\"exit_code\":%d", stats ? stats->exit_code : -1);
    fprintf(fp, ",\"signal_number\":%d", stats ? stats->signal_number : 0);
    fprintf(fp, "}\n");
    fclose(fp);
}

static void prepare_sandbox_child(const DetectionRules *rules, char **argv) {
    int null_fd;
    int stdout_fd;
    int stderr_fd;

    stdout_fd = open(artifact_stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (stdout_fd >= 0) {
        (void) dup2(stdout_fd, STDOUT_FILENO);
        close(stdout_fd);
    }

    stderr_fd = open(artifact_stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (stderr_fd >= 0) {
        (void) dup2(stderr_fd, STDERR_FILENO);
        close(stderr_fd);
    }

    (void) mkdir("sandbox_workspace", 0755);
    (void) chdir("sandbox_workspace");
    (void) setsid();

    if (apply_limit(RLIMIT_AS, (rlim_t) rules->sandbox_memory_kb * 1024) != 0 ||
        apply_limit(RLIMIT_NOFILE, (rlim_t) rules->sandbox_fd_limit) != 0 ||
        apply_limit(RLIMIT_CPU, (rlim_t) rules->sandbox_cpu_seconds) != 0 ||
        apply_limit(RLIMIT_CORE, 0) != 0 ||
        apply_limit(RLIMIT_FSIZE, 10 * 1024 * 1024) != 0) {
        perror("Failed to set sandbox limits");
        _exit(1);
    }

    null_fd = open("/dev/null", O_RDONLY);
    if (null_fd >= 0) {
        (void) dup2(null_fd, STDIN_FILENO);
        close(null_fd);
    }

    if (resolved_command_path[0] != '\0') {
        argv[0] = resolved_command_path;
    }

    execvp(argv[0], argv);
    perror("Sandbox execution failed");
    _exit(1);
}

static void resolve_command_path(char **argv) {
    char cwd[PATH_MAX];
    char candidate[PATH_MAX];

    resolved_command_path[0] = '\0';

    if (!argv || !argv[0] || strchr(argv[0], '/') == NULL) {
        return;
    }

    if (realpath(argv[0], resolved_command_path) != NULL) {
        return;
    }

    if (!getcwd(cwd, sizeof(cwd))) {
        return;
    }

    snprintf(candidate, sizeof(candidate), "%s/%s", cwd, argv[0]);
    if (realpath(candidate, resolved_command_path) == NULL) {
        resolved_command_path[0] = '\0';
    }
}

static int read_status_value(pid_t pid, const char *field, long *result) {
    char path[256];
    FILE *fp;
    char line[256];
    size_t field_len = strlen(field);

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, field, field_len) == 0) {
            long value = 0;
            if (sscanf(line + field_len, " %ld", &value) == 1) {
                *result = value;
                fclose(fp);
                return 1;
            }
        }
    }

    fclose(fp);
    return 0;
}

static int count_fd_entries(pid_t pid) {
    char path[256];
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    dir = opendir(path);
    if (!dir) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }

    closedir(dir);
    return count;
}

static void force_stop_group(pid_t pgid, const char *reason) {
    char log_line[512];

    snprintf(log_line, sizeof(log_line), "SANDBOX BLOCKED pgid=%d reason=%s", (int) pgid, reason);
    printf("[SANDBOX] %s\n", log_line);
    log_event(log_line);
    log_sandbox_event("review", "blocked", "sandbox-group", reason);

    (void) kill(-pgid, SIGTERM);
    usleep(300000);
    (void) kill(-pgid, SIGKILL);
}

static int evaluate_sandbox_process(pid_t pid, const DetectionRules *rules, char *reason, size_t reason_size, int *status, SandboxRunStats *stats) {
    time_t start_time = time(NULL);

    while (1) {
        long memory_kb = 0;
        long threads = 0;
        int fd_count = count_fd_entries(pid);
        pid_t wait_result = waitpid(pid, status, WNOHANG);

        if (wait_result == pid) {
            if (stats) {
                stats->runtime_seconds = difftime(time(NULL), start_time);
            }
            return 1;
        }

        if ((int) difftime(time(NULL), start_time) > rules->sandbox_eval_seconds) {
            if (stats) {
                stats->runtime_seconds = difftime(time(NULL), start_time);
            }
            snprintf(reason, reason_size, "sandbox evaluation timeout");
            return 0;
        }

        (void) read_status_value(pid, "VmRSS:", &memory_kb);
        (void) read_status_value(pid, "Threads:", &threads);

        if (stats) {
            if (memory_kb > stats->peak_memory_kb) {
                stats->peak_memory_kb = memory_kb;
            }
            if (fd_count > stats->peak_fd_count) {
                stats->peak_fd_count = fd_count;
            }
            if (threads > stats->peak_threads) {
                stats->peak_threads = threads;
            }
            stats->runtime_seconds = difftime(time(NULL), start_time);
        }

        if (memory_kb > rules->sandbox_memory_kb) {
            snprintf(reason, reason_size, "sandbox memory %ldkB > %ldkB", memory_kb, rules->sandbox_memory_kb);
            return 0;
        }

        if (fd_count > rules->sandbox_fd_limit) {
            snprintf(reason, reason_size, "sandbox fd %d > %d", fd_count, rules->sandbox_fd_limit);
            return 0;
        }

        if (threads > rules->max_threads) {
            snprintf(reason, reason_size, "sandbox threads %ld > %d", threads, rules->max_threads);
            return 0;
        }

        usleep(250000);
    }
}

static int run_supervised_child(char **argv, const DetectionRules *rules, int sandboxed, SandboxRunStats *stats) {
    pid_t pid = fork();
    int status = 0;
    char reason[256];

    if (pid < 0) {
        perror("Fork failed");
        return 0;
    }

    if (pid == 0) {
        if (sandboxed) {
            prepare_sandbox_child(rules, argv);
        } else {
            (void) setsid();
            execvp(argv[0], argv);
            perror("Host execution failed");
            _exit(1);
        }
    }

    active_child = pid;

    if (sandboxed && !evaluate_sandbox_process(pid, rules, reason, sizeof(reason), &status, stats)) {
        force_stop_group(pid, reason);
        (void) waitpid(pid, &status, 0);
        active_child = -1;
        if (stats) {
            stats->signal_number = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
            stats->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        }
        return 0;
    }

    if (!sandboxed && waitpid(pid, &status, 0) < 0) {
        perror("waitpid failed");
        active_child = -1;
        return 0;
    }

    active_child = -1;

    if (stats) {
        stats->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        stats->signal_number = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 1;
    }

    if (WIFSIGNALED(status)) {
        char log_line[256];
        snprintf(log_line, sizeof(log_line), "PROCESS EXITED BY SIGNAL pid=%d signal=%d sandboxed=%d", (int) pid, WTERMSIG(status), sandboxed);
        log_event(log_line);
    }

    return 0;
}

/* Run a command in a supervised sandbox first and optionally promote it after a clean run. */
void run_in_sandbox(char **argv) {
    const DetectionRules *rules = get_rules();
    SandboxRunStats sandbox_stats;

    if (!argv || !argv[0]) {
        fprintf(stderr, "No command provided for sandbox execution.\n");
        return;
    }

    memset(&sandbox_stats, 0, sizeof(sandbox_stats));
    ensure_artifact_paths();
    signal(SIGINT, sandbox_signal_handler);
    signal(SIGTERM, sandbox_signal_handler);
    resolve_command_path(argv);

    printf("[SANDBOX] Evaluating `%s` inside restricted mode first.\n", argv[0]);
    printf("[SANDBOX] Limits: memory=%ldkB fd=%d cpu=%ds promote_after_clean=%d\n",
           rules->sandbox_memory_kb,
           rules->sandbox_fd_limit,
           rules->sandbox_cpu_seconds,
           rules->sandbox_promote_after_clean);
    log_sandbox_event("review", "started", argv[0], "sandbox review started");

    if (!run_supervised_child(argv, rules, 1, &sandbox_stats)) {
        printf("[SANDBOX] Command blocked or failed during sandbox review.\n");
        log_sandbox_event("review", "failed", argv[0], "sandbox review blocked or failed");
        write_artifact_record("review", "failed", argv[0], "sandbox review blocked or failed", &sandbox_stats);
        return;
    }

    printf("[SANDBOX] Command completed cleanly inside sandbox review.\n");
    log_sandbox_event("review", "clean", argv[0], "sandbox review completed cleanly");
    write_artifact_record("review", "clean", argv[0], "sandbox review completed cleanly", &sandbox_stats);

    if (!rules->sandbox_promote_after_clean) {
        printf("[SANDBOX] Promotion disabled by default to avoid running the same command twice.\n");
        printf("[SANDBOX] Set SANDBOX_PROMOTE_AFTER_CLEAN=1 in conf/rules.conf only for trusted, repeatable commands.\n");
        log_sandbox_event("promotion", "disabled", argv[0], "promotion disabled by configuration");
        write_artifact_record("promotion", "disabled", argv[0], "promotion disabled by configuration", &sandbox_stats);
        return;
    }

    printf("[SANDBOX] Promoting command to host execution.\n");
    log_sandbox_event("promotion", "started", argv[0], "promoting sandbox-clean command to host execution");
    if (!run_supervised_child(argv, rules, 0, &sandbox_stats)) {
        printf("[SANDBOX] Host execution failed.\n");
        log_sandbox_event("promotion", "failed", argv[0], "host execution failed after sandbox review");
        write_artifact_record("promotion", "failed", argv[0], "host execution failed after sandbox review", &sandbox_stats);
        return;
    }
    log_sandbox_event("promotion", "completed", argv[0], "host execution completed after sandbox review");
    write_artifact_record("promotion", "completed", argv[0], "host execution completed after sandbox review", &sandbox_stats);
}
