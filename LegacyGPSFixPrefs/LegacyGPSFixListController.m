#import <UIKit/UIKit.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define BUNDLED_EPHEMERIS_PATH "/Library/Application Support/LegacyGPSFix/xtra2.bin"

OBJC_EXTERN CFPropertyListRef MGCopyAnswer(CFStringRef property);

@interface PSViewController : UIViewController
@end

@interface PSListController : PSViewController <UITableViewDelegate, UITableViewDataSource> {
    id _specifiers;
}
- (id)loadSpecifiersFromPlistName:(NSString *)name target:(id)target;
- (void)reloadSpecifiers;
@end

@interface PSSpecifier : NSObject
- (void)setProperty:(id)property forKey:(NSString *)key;
- (id)propertyForKey:(NSString *)key;
@end

@interface LegacyGPSFixListController : PSListController
@end

static int parse_url_host_path(const char *url, char *host, int host_sz, int *port, char *path, int path_sz) {
    if (!url || !host || !path || !port) return -1;
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        *port = 80;
    } else if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        *port = 443;
    } else {
        *port = 80;
    }

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');

    if (colon && (!slash || colon < slash)) {
        int hlen = colon - p;
        if (hlen >= host_sz) hlen = host_sz - 1;
        strncpy(host, p, hlen);
        host[hlen] = '\0';
        *port = atoi(colon + 1);
    } else if (slash) {
        int hlen = slash - p;
        if (hlen >= host_sz) hlen = host_sz - 1;
        strncpy(host, p, hlen);
        host[hlen] = '\0';
    } else {
        strncpy(host, p, host_sz - 1);
        host[host_sz - 1] = '\0';
    }

    if (slash) {
        strncpy(path, slash, path_sz - 1);
        path[path_sz - 1] = '\0';
    } else {
        strncpy(path, "/xtra2.bin", path_sz - 1);
        path[path_sz - 1] = '\0';
    }
    return 0;
}

static int fetch_ephemeris(const char *url, const char *dest_path) {
    char host[128] = {0};
    char path[256] = {0};
    int port = 80;

    if (parse_url_host_path(url, host, sizeof(host), &port, path, sizeof(path)) != 0) return 0;
    if (strlen(host) == 0) return 0;

    struct hostent *he = gethostbyname(host);
    if (!he || !he->h_addr_list[0]) return 0;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct timeval tv = { .tv_sec = 6, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    memcpy(&saddr.sin_addr, he->h_addr_list[0], sizeof(struct in_addr));

    int nosig = 1;
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &nosig, sizeof(nosig));

    if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) != 0) {
        close(sock);
        return 0;
    }

    char req[512];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: iOS/6.1 LegacyGPSFix\r\n"
             "Connection: close\r\n\r\n", path, host);
    write(sock, req, strlen(req));

    char tmp_path[256];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", dest_path);
    FILE *fp = fopen(tmp_path, "wb");
    if (!fp) {
        close(sock);
        return 0;
    }

    char buf[4096];
    char header_buf[4096];
    size_t header_buf_len = 0;
    int header_parsed = 0;
    int status_code = 0;
    size_t body_bytes = 0;
    ssize_t n;

    while ((n = read(sock, buf, sizeof(buf))) > 0) {
        if (!header_parsed) {
            size_t copy_len = (header_buf_len + n < sizeof(header_buf) - 1) ? n : (sizeof(header_buf) - 1 - header_buf_len);
            memcpy(header_buf + header_buf_len, buf, copy_len);
            header_buf_len += copy_len;
            header_buf[header_buf_len] = '\0';

            char *hdr_end = strstr(header_buf, "\r\n\r\n");
            if (hdr_end) {
                sscanf(header_buf, "HTTP/%*s %d", &status_code);
                header_parsed = 1;
                size_t hdr_size = (hdr_end + 4) - header_buf;
                size_t body_in_hdr = header_buf_len - hdr_size;
                if (status_code == 200 && body_in_hdr > 0) {
                    fwrite(hdr_end + 4, 1, body_in_hdr, fp);
                    body_bytes += body_in_hdr;
                }
            }
        } else if (status_code == 200) {
            fwrite(buf, 1, n, fp);
            body_bytes += n;
        }
    }
    fclose(fp);
    close(sock);

    if (status_code == 200 && body_bytes > 10000) {
        rename(tmp_path, dest_path);
        return 1;
    }
    unlink(tmp_path);
    return 0;
}

@implementation LegacyGPSFixListController

- (id)specifiers {
    if (_specifiers == nil) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];

        CFBooleanRef hasGPSVal = (CFBooleanRef)MGCopyAnswer(CFSTR("gps"));
        BOOL hasGPS = (hasGPSVal && CFGetTypeID(hasGPSVal) == CFBooleanGetTypeID() && CFBooleanGetValue(hasGPSVal));
        if (hasGPSVal) CFRelease(hasGPSVal);

        if (!hasGPS) {
            PSSpecifier *statusGroup = nil;
            for (PSSpecifier *spec in _specifiers) {
                NSString *cellType = [spec propertyForKey:@"cell"];
                if ([cellType isEqualToString:@"PSGroupCell"] && !statusGroup) {
                    statusGroup = spec;
                    [statusGroup setProperty:@"GPS rollover & A-GPS are inactive on Wi-Fi-only hardware (No internal GNSS chip)." forKey:@"footerText"];
                }

                NSString *label = [spec propertyForKey:@"label"];
                NSString *action = [spec propertyForKey:@"action"];
                if ([label isEqualToString:@"Rollover Fix"] ||
                    [label isEqualToString:@"A-GPS Ephemeris"] ||
                    [label isEqualToString:@"Cache Age"] ||
                    [label isEqualToString:@"Update Ephemeris Now"] ||
                    [label isEqualToString:@"Custom Mirror URL"] ||
                    [action isEqualToString:@"updateEphemerisNow:"]) {
                    [spec setProperty:@NO forKey:@"enabled"];
                }
            }
        }
    }
    return _specifiers;
}

- (id)getRolloverStatus:(PSSpecifier *)specifier {
    CFBooleanRef hasGPSVal = (CFBooleanRef)MGCopyAnswer(CFSTR("gps"));
    BOOL hasGPS = (hasGPSVal && CFGetTypeID(hasGPSVal) == CFBooleanGetTypeID() && CFBooleanGetValue(hasGPSVal));
    if (hasGPSVal) CFRelease(hasGPSVal);
    return hasGPS ? @"Active (+1024 w)" : @"N/A (Wi-Fi only)";
}

- (id)getPositionFilterStatus:(PSSpecifier *)specifier {
    CFBooleanRef hasGPSVal = (CFBooleanRef)MGCopyAnswer(CFSTR("gps"));
    BOOL hasGPS = (hasGPSVal && CFGetTypeID(hasGPSVal) == CFBooleanGetTypeID() && CFBooleanGetValue(hasGPSVal));
    if (hasGPSVal) CFRelease(hasGPSVal);
    return hasGPS ? @"Active" : @"N/A (Wi-Fi only)";
}

- (id)getEphemerisCacheAge:(PSSpecifier *)specifier {
    struct stat st;
    if (stat(BUNDLED_EPHEMERIS_PATH, &st) == 0) {
        time_t now = time(NULL);
        long age_sec = (now > st.st_mtime) ? (long)(now - st.st_mtime) : 0;
        long days = age_sec / 86400;
        long hours = (age_sec % 86400) / 3600;

        if (days < 7) {
            return [NSString stringWithFormat:@"\U0001F7E2 Valid (%ldd %ldh)", days, hours];
        } else if (days < 14) {
            return [NSString stringWithFormat:@"\U0001F7E1 Expiring (%ldd)", days];
        } else {
            return [NSString stringWithFormat:@"\U0001F534 Stale (%ldd)", days];
        }
    }
    return @"\U0001F534 Missing";
}

- (void)updateEphemerisNow:(PSSpecifier *)specifier {
    UIActivityIndicatorView *spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
    [spinner startAnimating];
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithCustomView:spinner];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int success = 0;

        CFPreferencesAppSynchronize(CFSTR("com.noname122021.legacygpsfix"));
        CFPropertyListRef customVal = CFPreferencesCopyAppValue(CFSTR("customMirrorUrl"), CFSTR("com.noname122021.legacygpsfix"));
        if (customVal && CFGetTypeID(customVal) == CFStringGetTypeID()) {
            char customUrl[256];
            if (CFStringGetCString((CFStringRef)customVal, customUrl, sizeof(customUrl), kCFStringEncodingUTF8) && strlen(customUrl) > 7) {
                if (fetch_ephemeris(customUrl, BUNDLED_EPHEMERIS_PATH)) {
                    success = 1;
                }
            }
            CFRelease(customVal);
        }

        if (!success) {
            if (fetch_ephemeris("http://xtrapath4.izatcloud.net/xtra2.bin", BUNDLED_EPHEMERIS_PATH)) {
                success = 1;
            }
        }

        if (!success) {
            if (fetch_ephemeris("http://xtra1.gpsonextra.net/xtra2.bin", BUNDLED_EPHEMERIS_PATH)) {
                success = 1;
            }
        }

        if (success) {
            system("killall -9 locationd 2>/dev/null");
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            self.navigationItem.rightBarButtonItem = nil;
            [self reloadSpecifiers];

            struct stat post_st;
            int is_fresh = 0;
            if (stat(BUNDLED_EPHEMERIS_PATH, &post_st) == 0) {
                time_t now = time(NULL);
                if ((now - post_st.st_mtime) < 86400 * 3) {
                    is_fresh = 1;
                }
            }

            UIAlertView *alert;
            if (success) {
                alert = [[UIAlertView alloc] initWithTitle:@"LegacyGPSFix"
                                                   message:@"A-GPS ephemeris successfully updated."
                                                  delegate:nil
                                         cancelButtonTitle:@"OK"
                                         otherButtonTitles:nil];
            } else if (is_fresh) {
                alert = [[UIAlertView alloc] initWithTitle:@"LegacyGPSFix"
                                                   message:@"Ephemeris is already up to date."
                                                  delegate:nil
                                         cancelButtonTitle:@"OK"
                                         otherButtonTitles:nil];
            } else {
                alert = [[UIAlertView alloc] initWithTitle:@"LegacyGPSFix"
                                                   message:@"Download failed. Check internet connection."
                                                  delegate:nil
                                         cancelButtonTitle:@"OK"
                                         otherButtonTitles:nil];
            }
            [alert show];
        });
    });
}

@end
