/*
 * polyglot/c/root_jailbreak_detector.c
 * 
 * Mobile Runtime Integrity Detection - RASP-style posture analysis
 * Zero dependencies, pure C implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <ctype.h>

#define MAX_PATH_LEN 256
#define SCORE_THRESHOLD_CLEAN 10
#define SCORE_THRESHOLD_SUSPICIOUS 25
#define SCORE_THRESHOLD_COMPROMISED 40
#define SCORE_THRESHOLD_ROOTED 41

/* Detection flags */
typedef enum {
    FLAG_NONE = 0,
    FLAG_ROOT_ANDROID = (1 << 0),
    FLAG_JAILBREAK_IOS = (1 << 1),
    FLAG_EMULATOR = (1 << 2),
    FLAG_HOOKED = (1 << 3),
    FLAG_TAMPERED = (1 << 4)
} DetectionFlags;

/* Posture verdict levels */
typedef enum {
    VERDICT_CLEAN,
    VERDICT_SUSPICIOUS,
    VERDICT_COMPROMISED,
    VERDICT_ROOTED,
    VERDICT_HOOKED
} VerdictLevel;

/* Result structure */
typedef struct {
    int score;
    DetectionFlags flags;
    VerdictLevel verdict;
    char *details;
} PostureResult;

/* Forward declarations */
static int check_android_root_indicators(void);
static int check_ios_jailbreak_indicators(void);
static int check_emulator_artifacts(void);
static int check_hook_injection_signatures(void);
static int check_system_integrity(void);
static void build_details_string(PostureResult *result, char *buffer, size_t buf_size);

/*
 * Check for Android root indicators
 */
static int check_android_root_indicators(void) {
    int score = 0;
    
    /* Check for su binary in common locations */
    const char *su_paths[] = {
        "/system/bin/su",
        "/data/local/tmp/su",
        "/data/local/su",
        "/data/data/com.android.shell/dropbox/su",
        "/sbin/su"
    };
    
    for (size_t i = 0; i < sizeof(su_paths) / sizeof(su_paths[0]); i++) {
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s", su_paths[i]);
        
        struct stat st;
        if (stat(path, &st) == 0 && 
            S_ISREG(st.st_mode) && 
            (st.st_mode & 0111)) {
            /* Verify it's actually a shell script or binary */
            FILE *f = fopen(path, "r");
            if (f) {
                char buf[64];
                size_t n = fread(buf, 1, sizeof(buf)-1, f);
                fclose(f);
                
                /* Check for common shebangs */
                if (n > 0 && 
                    (strncmp(buf, "#!/system/bin/sh", 15) == 0 ||
                     strncmp(buf, "#!/data/local/tmp/busybox", 26) == 0 ||
                     strncmp(buf, "#!/system/xbin/busybox", 23) == 0)) {
                    score += 8;
                } else if (n > 0 && 
                           memchr(buf, 'sh', n) != NULL &&
                           memchr(buf, 'su', n) != NULL) {
                    /* Binary or script with su/sh content */
                    score += 5;
                }
            }
        }
    }
    
    /* Check for busybox in unusual locations (often indicates root) */
    const char *busybox_paths[] = {
        "/system/bin/busybox",
        "/data/local/tmp/busybox"
    };
    
    for (size_t i = 0; i < sizeof(busybox_paths) / sizeof(busybox_paths[0]); i++) {
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s", busybox_paths[i]);
        
        struct stat st;
        if (stat(path, &st) == 0 && 
            S_ISREG(st.st_mode) && 
            (st.st_mode & 0111)) {
            
            /* Check file size - real busybox is ~200KB+ */
            if (st.st_size > 150 * 1024) {
                score += 6;
            } else if (st.st_size < 100 && st.st_size > 50) {
                /* Tiny busybox - often from rooter apps */
                score += 7;
            }
        }
    }
    
    /* Check for remounted read-write system partition */
    FILE *f = fopen("/proc/mounts", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "/system") && strstr(line, "rw")) {
                score += 10;
                break;
            }
        }
        fclose(f);
    }
    
    /* Check for /proc/self/status showing uid 0 with non-system PID */
    f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "Uid:", 4) == 0 && 
                sscanf(line + 4, "%d", &line[4]) > 0) {
                
                int uid = atoi(line);
                if (uid == 0) {
                    /* Root process - check if it's a system shell */
                    f = fopen("/proc/self/cmdline", "r");
                    if (f) {
                        char cmdline[256];
                        size_t len = fread(cmdline, 1, sizeof(cmdline)-1, f);
                        fclose(f);
                        
                        /* Non-system root processes */
                        if (!strstr(cmdline, "/system/bin/sh") &&
                            !strstr(cmdline, "/system/xbin/sh") &&
                            !strstr(cmdline, "com.android.shell")) {
                            score += 8;
                        } else {
                            score += 3;
                        }
                    }
                }
            }
        }
        fclose(f);
    }
    
    return score > 0 ? 1 : 0;
}

/*
 * Check for iOS jailbreak indicators
 */
static int check_ios_jailbreak_indicators(void) {
    int score = 0;
    
    /* Common Cydia/Sileo app paths */
    const char *jailbreak_paths[] = {
        "/var/mobile/Media/Containers/Data/Application/*/Documents/.jailbreak",
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Rocky.app",
        "/Applications/Zebra.app"
    };
    
    for (size_t i = 0; i < sizeof(jailbreak_paths) / sizeof(jailbreak_paths[0]); i++) {
        char path[MAX_PATH_LEN];
        
        /* Handle wildcard pattern */
        if (strstr(jailbreak_paths[i], "*")) {
            DIR *d = opendir("/var/mobile/Media/Containers/Data/Application");
            if (!d) continue;
            
            struct dirent *entry;
            while ((entry = readdir(d)) != NULL) {
                snprintf(path, sizeof(path), 
                         "/var/mobile/Media/Containers/Data/Application/%s/Documents/.jailbreak",
                         entry->d_name);
                
                struct stat st;
                if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                    score += 5;
                }
            }
            closedir(d);
        } else {
            struct stat st;
            if (stat(jailbreak_paths[i], &st) == 0 && 
                S_ISDIR(st.st_mode)) {
                score += 6;
            }
        }
    }
    
    /* Check for Cydia Substrate hooks */
    f = fopen("/var/mobile/Containers/Data/Application/*/Library/Caches/*", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Cydia") || strstr(line, "Substrate")) {
                score += 4;
                break;
            }
        }
        fclose(f);
    }
    
    /* Check for common jailbreak tweak directories */
    const char *tweak_paths[] = {
        "/var/mobile/Library/Preferences/de.betterthanandroid.*.plist",
        "/var/mobile/Library/Preferences/com.saurik.Cydia.plist"
    };
    
    for (size_t i = 0; i < sizeof(tweak_paths) / sizeof(tweak_paths[0]); i++) {
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s", tweak_paths[i]);
        
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            score += 3;
        }
    }
    
    return score > 0 ? 1 : 0;
}

/*
 * Check for emulator artifacts
 */
static int check_emulator_artifacts(void) {
    int score = 0;
    
    /* Environment variable checks */
    char env[256];
    size_t len = readlink("/proc/self/exe", env, sizeof(env));
    if (len > 0) {
        env[len] = '\0';
        
        /* Check for emulator-specific environment variables */
        if (!strncmp(env, "ANDROID_EMULATOR=", 18)) {
            score += 12;
        } else if (!strncmp(env, "QEMU_", 5)) {
            score += 10;
        }
    }
    
    /* Check for emulator-specific file paths */
    const char *emulator_paths[] = {
        "/data/local/tmp/emulator/",
        "/data/data/com.android.vndk.instance/proc/self/cmdline",
        "/system/lib64/libqemu.so"
    };
    
    for (size_t i = 0; i < sizeof(emulator_paths) / sizeof(emulator_paths[0]); i++) {
        char path[MAX_PATH_LEN];
        snprintf(path, sizeof(path), "%s", emulator_paths[i]);
        
        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            score += 8;
        } else if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            /* Check for QEMU library */
            if (strstr(path, "qemu") || strstr(path, "libqemu")) {
                score += 6;
            }
        }
    }
    
    /* Check /proc/cpuinfo for virtual CPU signatures */
    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            /* Look for virtualization indicators */
            if (strstr(line, "Virtual") || 
                strstr(line, "qemu") ||
                strstr(line, "kvm")) {
                score += 7;
                break;
            }
        }
        fclose(f);
    }
    
    return score > 0 ? 1 : 0;
}

/*
 * Check for hook injection signatures
 */
static int check_hook_injection_signatures(void) {
    int score = 0;
    
    /* Check for Frida/GodMode artifacts */
    const char *frida_paths[] = {
        "/data/local/tmp/frida-server",
        "/system/bin/frida-server",
        "/data/data/com.francismorley.frida/files/",
        "/var/folders/*/T/frida"
    };
    
    for (size_t i = 0; i < sizeof(frida_paths) / sizeof(frida_paths[0]); i++) {
        char path[MAX_PATH_LEN];
        
        if (strstr(frida_paths[i], "*")) {
            DIR *d = opendir("/data/local/tmp");
            if (!d) continue;
            
            struct dirent *entry;
            while ((entry = readdir(d)) != NULL) {
                snprintf(path, sizeof(path), "%s/%s", frida_paths[0], entry->d_name);
                
                struct stat st;
                if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                    if (strstr(entry->d_name, "frida") || 
                        strstr(entry->d_name, "godmode")) {
                        score += 15;
                    }
                }
            }
            closedir(d);
        } else {
            struct stat st;
            if (stat(frida_paths[i], &st) == 0 && S_ISREG(st.st_mode)) {
                if (strstr(frida_paths[i], "frida") || 
                    strstr(frida_paths[i], "godmode")) {
                    score += 12;
                }
            }
        }
    }
    
    /* Check for Xposed framework */
    const char *xposed_paths[] = {
        "/data/data/de.robv.android.xposed/",
        "/system/lib/xposed/"
    };
    
    for (size_t i = 0; i < sizeof(xposed_paths) / sizeof(xposed_paths[0]); i++) {
        char path[MAX_PATH_LEN];
        
        if (strstr(xposed_paths[i], "*")) {
            DIR *d = opendir("/data/data");
            if (!d) continue;
            
            struct dirent *entry;
            while ((entry = readdir(d)) != NULL) {
                snprintf(path, sizeof(path), "/data/data/%s/", entry->d_name);
                
                struct stat st;
                if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                    if (strstr(entry->d_name, "xposed")) {
                        score += 14;
                    }
                }
            }
            closedir(d);
        } else {
            struct stat st;
            if (stat(xposed_paths[i], &st) == 0 && S_ISDIR(st.st_mode)) {
                if (strstr(xposed_paths[i], "xposed")) {
                    score += 12;
                }
            }
        }
    }
    
    /* Check for Cydia Substrate in memory (basic check via /proc) */
    f = fopen("/proc/self/maps", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            /* Look for common hook library patterns */
            if (strstr(line, "libsubstrate") || 
                strstr(line, "libfrida") ||
                strstr(line, "libgodmode")) {
                score += 10;
                break;
            }
        }
        fclose(f);