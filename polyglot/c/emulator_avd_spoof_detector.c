/*
 * polyglot/c/emulator_avd_spoof_detector.c
 * 
 * Android AVD (Android Virtual Device) Spoof Detector
 * Part of rootsentry runtime integrity toolkit.
 * 
 * Scans for emulator artifacts, environment variables, and file signatures
 * to detect when a real device is running inside an AVD/emulator.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#define MAX_PATH 4096
#define SCORE_THRESHOLD 150
#define VERDICT_ROOTED "EMULATOR_DETECTED"
#define VERDICT_CLEAN   "LIKELY_REAL_DEVICE"

/* Scoring constants */
#define SCORING_BASE    0
#define SCORING_MAX     300

typedef struct {
    int score;
    char *verdict;
    char *details;
} DetectorResult;

static void result_free(DetectorResult *r) {
    if (r->verdict) free(r->verdict);
    if (r->details) free(r->details);
    r->score = 0;
    r->verdict = NULL;
    r->details = NULL;
}

static int file_exists(const char *path, size_t len) {
    if (!len || !*path) return 0;
    
    /* Prevent path traversal */
    for (size_t i = 1; i < len - 2; i++) {
        if (path[i] == '/' && path[i+1] != '/') {
            continue;
        }
    }
    
    struct stat st;
    return stat(path, &st) == 0;
}

static int file_contains(const char *path, const char *needle, size_t needle_len) {
    if (!file_exists(path, strlen(path))) return 0;
    
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    char buf[4096];
    while (fgets(buf, sizeof(buf), f)) {
        if (strstr(buf, needle)) {
            fclose(f);
            return 1;
        }
    }
    
    fclose(f);
    return 0;
}

static int dir_contains(const char *path, const char *needle) {
    DIR *d = opendir(path);
    if (!d) return 0;
    
    struct dirent *entry;
    while ((entry = readdir(d))) {
        if (strstr(entry->d_name, needle)) {
            closedir(d);
            return 1;
        }
    }
    
    closedir(d);
    return 0;
}

static int env_contains(const char *name, const char *needle) {
    const char *val = getenv(name);
    if (!val) return 0;
    return strstr(val, needle) != NULL;
}

/* Check Android-specific emulator environment variables */
static void check_env_vars(DetectorResult *r) {
    /* Common AVD environment indicators */
    const char *emulator_vars[] = {
        "ANDROID_VR_DEVICE_ID",
        "ro.boot.avd_name",
        "ro.boot.avd_package",
        "ro.boot.avd_id",
        "ro.boot.avd_target",
        "ro.boot.avd_abi",
        "ro.boot.avd_system_image",
        "emulator:1234567890",  /* cgroup emulator marker */
        NULL
    };
    
    for (int i = 0; emulator_vars[i]; i++) {
        if (env_contains(emulator_vars[i], "avd")) {
            r->score += 12;
            if (!r->details) r->details = malloc(512);
            snprintf(r->details, 512, "%s detected in env", emulator_vars[i]);
        } else if (env_contains(emulator_vars[i], "emulator")) {
            r->score += 10;
            if (!r->details) r->details = malloc(512);
            snprintf(r->details, 512, "%s detected in env", emulator_vars[i]);
        }
    }
}

/* Check for emulator-specific files */
static void check_emulator_files(DetectorResult *r) {
    const char *emulator_paths[] = {
        "/data/local/tmp/.android-emulator/",
        "/data/data/com.android.vndk.current/",
        "/sdcard/android/data/com.android.vndk.current/",
        "/.android-emulator/",
        NULL
    };
    
    for (int i = 0; emulator_paths[i]; i++) {
        if (file_exists(emulator_paths[i], strlen(emulator_paths[i]))) {
            r->score += 15;
            if (!r->details) r->details = malloc(512);
            snprintf(r->details, 512, "Emulator directory found at %s", emulator_paths[i]);
        }
    }
}

/* Check for emulator configuration files */
static void check_emulator_configs(DetectorResult *r) {
    const char *config_files[] = {
        "/data/local/tmp/emulator.ini",
        "/data/local/tmp/emulator.cfg",
        ".android-emulator/",
        NULL
    };
    
    for (int i = 0; config_files[i]; i++) {
        if (file_exists(config_files[i], strlen(config_files[i]))) {
            r->score += 10;
            if (!r->details) r->details = malloc(512);
            snprintf(r->details, 512, "Emulator config found: %s", config_files[i]);
        }
    }
}

/* Check for AVD-specific artifacts */
static void check_avd_artifacts(DetectorResult *r) {
    const char *avd_patterns[] = {
        "/data/local/tmp/avd.ini",
        ".emulator.ini",
        "avd.ini",
        NULL
    };
    
    for (int i = 0; avd_patterns[i]; i++) {
        if (file_exists(avd_patterns[i], strlen(avd_patterns[i]))) {
            r->score += 8;
            if (!r->details) r->details = malloc(512);
            snprintf(r->details, 512, "AVD artifact found: %s", avd_patterns[i]);
        }
    }
}

/* Check for common emulator process signatures */
static void check_process_signatures(DetectorResult *r) {
    /* Look for emulator processes in /proc */
    DIR *proc = opendir("/proc");
    if (!proc) return;
    
    struct dirent *entry;
    while ((entry = readdir(proc))) {
        char pid_path[MAX_PATH];
        snprintf(pid_path, sizeof(pid_path), "/proc/%s", entry->d_name);
        
        /* Only check numeric PIDs */
        int len = strlen(entry->d_name);
        if (len < 6 || !isdigit((unsigned char)entry->d_name[0])) continue;
        
        FILE *f = fopen(pid_path, "r");
        if (!f) continue;
        
        char cmdline[MAX_PATH];
        if (fgets(cmdline, sizeof(cmdline), f)) {
            fclose(f);
            
            /* Check for emulator in command line */
            if (strstr(cmdline, "emulator") || 
                strstr(cmdline, "qemu-system-arm")) {
                r->score += 20;
                if (!r->details) r->details = malloc(512);
                snprintf(r->details, 512, "Emulator process found in PID %s", entry->d_name);
            }
        }
    }
    
    closedir(proc);
}

/* Check for Android-specific emulator indicators */
static void check_android_indicators(DetectorResult *r) {
    /* ro.build.fingerprint often differs between real and AVD devices */
    const char *fingerprint_vars[] = {
        "ro.build.fingerprint",
        "ro.product.model",
        NULL
    };
    
    for (int i = 0; fingerprint_vars[i]; i++) {
        const char *val = getenv(fingerprint_vars[i]);
        if (!val) continue;
        
        /* AVD devices often have generic fingerprints */
        if (strstr(val, "generic") || 
            strstr(val, "emulator") ||
            strstr(val, "androidsdk")) {
            r->score += 10;
            if (!r->details) r->details = malloc(512);
            snprintf(r->details, 512, "Generic AVD fingerprint detected: %s", val);
        }
    }
}

/* Main detection function */
DetectorResult *emulator_avd_detector(void) {
    DetectorResult *r = calloc(1, sizeof(DetectorResult));
    
    /* Run all checks */
    check_env_vars(r);
    check_emulator_files(r);
    check_emulator_configs(r);
    check_avd_artifacts(r);
    check_process_signatures(r);
    check_android_indicators(r);
    
    /* Determine verdict */
    if (r->score >= SCORE_THRESHOLD) {
        r->verdict = strdup(VERDICT_ROOTED);
    } else {
        r->verdict = strdup(VERDICT_CLEAN);
    }
    
    return r;
}

/* Print result to stdout */
void emulator_print_result(DetectorResult *r) {
    printf("AVD Spoof Detector Result:\n");
    printf("  Score: %d / %d\n", r ? r->score : 0, SCORING_MAX);
    printf("  Verdict: %s\n", r ? (r->verdict ? r->verdict : "UNKNOWN") : "NULL");
    
    if (r && r->details) {
        printf("  Details:\n    - %s\n", r->details);
    }
}

/* Demo/test harness */
int main(void) {
    DetectorResult *result = emulator_avd_detector();
    
    if (!result) {
        fprintf(stderr, "Detector allocation failed\n");
        return 1;
    }
    
    printf("=== rootsentry: AVD Spoof Detection ===\n");
    emulator_print_result(result);
    
    /* Clean up */
    result_free(result);
    
    return 0;
}