#include <substrate.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <Security/SecTrust.h>
#include <CoreLocation/CoreLocation.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysctl.h>
#include <pthread.h>
#include <unistd.h>
#include <math.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"

#define LOCAL_EPHEMERIS_PORT 18080
#define LOCAL_TELEMETRY_PORT 18088
#define EPHEMERIS_PATH "/Library/Application Support/LegacyGPSFix/xtra2.bin"
#define SYSTEM_CA_BUNDLE "/usr/lib/legacyraytlsfix/cacert.pem"
#define PREFS_PATH "/var/mobile/Library/Preferences/com.noname122021.legacygpsfix.plist"

/* Default fake coordinate: Apple 1 Infinite Loop, Cupertino, CA */
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static bool s_fake_gps_enabled = false;
static bool s_online_wloc_enabled = false;
static double s_fake_lat = 37.33182, s_fake_lon = -122.03118;
static double s_off_east = 0.0, s_off_north = 0.0;
static bool s_static_nav = true, s_vel_clamp = true, s_smoothing = true;
static double s_max_speed_kmh = 120.0;
static struct { double lat, lon, ts; } s_last_pt;
static bool s_has_prev = false;

static void safe_write(int fd, const void *b, size_t n) {
    const char *p = b;
    while (n > 0) {
        ssize_t w = send(fd, p, n, 0);
        if (w <= 0) break;
        p += w; n -= w;
    }
}

static void *ephemeris_server(void *arg) {
    (void)arg;
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return NULL;
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = inet_addr("127.0.0.1"), .sin_port = htons(LOCAL_EPHEMERIS_PORT) };
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(sfd, 5) < 0) { close(sfd); return NULL; }

    while (1) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        int sopt = 1; setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &sopt, sizeof(sopt));
        char req[512];
        if (read(cfd, req, sizeof(req)) > 0) {
            FILE *f = fopen(EPHEMERIS_PATH, "rb");
            if (f) {
                fseek(f, 0, SEEK_END);
                long sz = ftell(f);
                fseek(f, 0, SEEK_SET);
                char hdr[128];
                int hlen = snprintf(hdr, sizeof(hdr), "HTTP/1.1 200 OK\r\nContent-Length: %ld\r\n\r\n", sz);
                safe_write(cfd, hdr, hlen);
                char buf[4096];
                size_t rd;
                while ((rd = fread(buf, 1, sizeof(buf), f)) > 0) safe_write(cfd, buf, rd);
                fclose(f);
            } else {
                safe_write(cfd, "HTTP/1.1 404 Not Found\r\n\r\n", 26);
            }
        }
        close(cfd);
    }
}

static void *telemetry_bridge(void *arg) {
    (void)arg;
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return NULL;
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = inet_addr("127.0.0.1"), .sin_port = htons(LOCAL_TELEMETRY_PORT) };
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(sfd, 5) < 0) { close(sfd); return NULL; }

    while (1) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) continue;
        int sopt = 1; setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &sopt, sizeof(sopt));
        char req[8192];
        ssize_t n = read(cfd, req, sizeof(req) - 1);
        if (n <= 0) { close(cfd); continue; }
        req[n] = '\0';
        char *split = strstr(req, "\r\n\r\n");
        if (split) {
            pthread_mutex_lock(&s_lock);
            bool fake = s_fake_gps_enabled;
            bool allow_wloc = s_online_wloc_enabled;
            pthread_mutex_unlock(&s_lock);

            if (fake || !allow_wloc) {
                /* Privacy mode or Fake GPS: drop Wi-Fi scans, respond with 403 Forbidden */
                safe_write(cfd, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 43);
                close(cfd);
                continue;
            }

            size_t body_len = n - ((split + 4) - req);
            uint8_t *body = (uint8_t *)(split + 4);

            mbedtls_net_context s_ctx; mbedtls_ssl_context ssl; mbedtls_ssl_config conf;
            mbedtls_ctr_drbg_context drbg; mbedtls_entropy_context ent; mbedtls_x509_crt ca;
            mbedtls_net_init(&s_ctx); mbedtls_ssl_init(&ssl); mbedtls_ssl_config_init(&conf);
            mbedtls_x509_crt_init(&ca); mbedtls_ctr_drbg_init(&drbg); mbedtls_entropy_init(&ent);

            if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const unsigned char *)"wloc", 4) == 0 &&
                mbedtls_x509_crt_parse_file(&ca, SYSTEM_CA_BUNDLE) == 0 &&
                mbedtls_net_connect(&s_ctx, "gs-loc.apple.com", "443", MBEDTLS_NET_PROTO_TCP) == 0 &&
                mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0) {
                mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
                mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
                mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
                mbedtls_ssl_setup(&ssl, &conf);
                mbedtls_ssl_set_hostname(&ssl, "gs-loc.apple.com");
                mbedtls_ssl_set_bio(&ssl, &s_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);

                if (mbedtls_ssl_handshake(&ssl) == 0) {
                    char h[256];
                    int hl = snprintf(h, sizeof(h), "POST /clls/wloc HTTP/1.1\r\nHost: gs-loc.apple.com\r\nContent-Type: application/x-apple-wloc\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", body_len);
                    mbedtls_ssl_write(&ssl, (const unsigned char *)h, hl);
                    if (body_len > 0) mbedtls_ssl_write(&ssl, body, body_len);

                    char rbuf[4096];
                    int rn = mbedtls_ssl_read(&ssl, (unsigned char *)rbuf, sizeof(rbuf));
                    if (rn > 0) safe_write(cfd, rbuf, rn);
                }
            }
            mbedtls_net_free(&s_ctx); mbedtls_x509_crt_free(&ca); mbedtls_ssl_free(&ssl);
            mbedtls_ssl_config_free(&conf); mbedtls_ctr_drbg_free(&drbg); mbedtls_entropy_free(&ent);
        }
        close(cfd);
    }
}

static double (*orig_gpsTimeToEpoch)(uint32_t week, uint32_t tow_ms);
static double hooked_gpsTimeToEpoch(uint32_t week, uint32_t tow_ms) {
    double t = orig_gpsTimeToEpoch(week, tow_ms);
    while (t < 567993600.0) t += 619315200.0; /* Rollover fix: +1024 weeks */
    return t;
}

static uintptr_t resolve_gpsTimeToEpoch_offset(void) {
    char build[32] = {0};
    char machine[32] = {0};
    size_t sz = sizeof(build);
    sysctlbyname("kern.osversion", build, &sz, NULL, 0);
    sz = sizeof(machine);
    sysctlbyname("hw.machine", machine, &sz, NULL, 0);

    /* 1. Fast SoC + OS build offset determination */
    if (machine[0] && build[0]) {
        bool is_a6 = (strncmp(machine, "iPhone5,", 8) == 0) ||
                     (strncmp(machine, "iPad3,4", 7) == 0) ||
                     (strncmp(machine, "iPad3,5", 7) == 0) ||
                     (strncmp(machine, "iPad3,6", 7) == 0);

        if (build[0] == '1' && build[1] == '0') {
            /* iOS 6 (10B143..10B500): ARMv7 (A4/A5) = 0x43130, ARMv7s (A6/A6X) = 0x42c38 */
            return is_a6 ? 0x42c38 : 0x43130;
        } else if (build[0] == '1' && build[1] == '1') {
            /* iOS 7 (11D257): ARMv7 = 0x48a10, ARMv7s = 0x49340, A7 = 0x51040 */
            if (strncmp(machine, "iPhone6,", 8) == 0) return 0x51040;
            return is_a6 ? 0x49340 : 0x48a10;
        } else if (build[0] == '1' && build[1] == '2') {
            /* iOS 8 (12H321): ARMv7 = 0x4b120, ARMv7s = 0x4bd80, A7 = 0x54620 */
            if (strncmp(machine, "iPhone6,", 8) == 0) return 0x54620;
            return is_a6 ? 0x4bd80 : 0x4b120;
        } else if (strncmp(build, "9B20", 4) == 0) {
            /* iOS 5.1.1 (9B206 / 9B208): ARMv7 = 0x3e280 */
            return 0x3e280;
        }
    }

    /* 2. Fallback: Bounded __TEXT,__text pattern scan matching 604800.0 */
    const struct mach_header *mh = _dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    if (mh) {
        unsigned long size = 0;
        uint8_t *text = getsectiondata((const struct mach_header *)mh, "__TEXT", "__text", &size);
        if (text && size > 32) {
            /* ARM/Thumb: 604800 (0x93a80) via movw r1, #0x3a80 (43 f6 80 21) & movt r1, #9 (c0 f2 09 01) */
            for (unsigned long i = 0; i + 32 < size; i += 2) {
                if (text[i] == 0x43 && text[i+1] == 0xf6 && text[i+2] == 0x80 && text[i+3] == 0x21) {
                    for (int off = 4; off <= 16; off += 2) {
                        if (text[i+off] == 0xc0 && text[i+off+1] == 0xf2 && text[i+off+2] == 0x09 && text[i+off+3] == 0x01) {
                            for (int back = 0; back <= 32; back += 2) {
                                if ((long)i - back >= 0) {
                                    uint8_t *fn = &text[i - back];
                                    if ((fn[0] == 0x41 && fn[1] == 0xec && fn[2] == 0x10 && fn[3] == 0x1b) ||
                                        (fn[0] == 0x00 && fn[1] == 0xee && fn[2] == 0x10 && fn[3] == 0x1a)) {
                                        return (uintptr_t)fn - slide;
                                    }
                                    if ((long)i - back >= 2 && fn[-2] == 0x70 && fn[-1] == 0x47) {
                                        return (uintptr_t)fn - slide;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            /* ARM64: 604800.0 IEEE-754 double or mov w1, #0x3a80; movk w1, #0x9, lsl #16 */
            const uint8_t dbl_pattern[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x75, 0x22, 0x41 };
            for (unsigned long i = 0; i + 8 <= size; i += 4) {
                if (memcmp(&text[i], dbl_pattern, 8) == 0) {
                    for (int back = 4; back <= 64; back += 4) {
                        if ((long)i - back >= 0) {
                            uint32_t insn = *(uint32_t *)(&text[i - back]);
                            if ((insn & 0xffc003ff) == 0xd10003ff || (insn & 0xff000000) == 0xa9000000) {
                                return (uintptr_t)&text[i - back] - slide;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

static CFURLRef (*orig_CFURLCreateWithBytes)(CFAllocatorRef, const UInt8 *, CFIndex, CFStringEncoding, CFURLRef);
static CFURLRef hooked_CFURLCreateWithBytes(CFAllocatorRef a, const UInt8 *b, CFIndex l, CFStringEncoding e, CFURLRef base) {
    if (b && l > 0 && memmem(b, l, "iphone-ld.apple.com", 19)) {
        return orig_CFURLCreateWithBytes(a, (const UInt8 *)"http://127.0.0.1:18080/xtra2.bin", 34, e, base);
    }
    if (b && l > 0 && memmem(b, l, "gs-loc.apple.com", 16)) {
        return orig_CFURLCreateWithBytes(a, (const UInt8 *)"http://127.0.0.1:18088/clls/wloc", 34, e, base);
    }
    return orig_CFURLCreateWithBytes(a, b, l, e, base);
}

static CFURLRef (*orig_CFURLCreateWithString)(CFAllocatorRef, CFStringRef, CFURLRef);
static CFURLRef hooked_CFURLCreateWithString(CFAllocatorRef a, CFStringRef u, CFURLRef b) {
    if (u && CFStringFind(u, CFSTR("iphone-ld.apple.com"), 0).location != kCFNotFound) {
        CFStringRef target = CFSTR("http://127.0.0.1:18080/xtra2.bin");
        return orig_CFURLCreateWithString(a, target, b);
    }
    if (u && CFStringFind(u, CFSTR("gs-loc.apple.com"), 0).location != kCFNotFound) {
        CFStringRef target = CFSTR("http://127.0.0.1:18088/clls/wloc");
        return orig_CFURLCreateWithString(a, target, b);
    }
    return orig_CFURLCreateWithString(a, u, b);
}

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus hooked_SecTrustEvaluate(SecTrustRef t, SecTrustResultType *r) {
    orig_SecTrustEvaluate(t, r);
    if (r) *r = kSecTrustResultProceed;
    return 0;
}

__attribute__((unused)) static void apply_nav_pipeline(CLLocationCoordinate2D *coord, double ts) {
    if (!coord) return;
    pthread_mutex_lock(&s_lock);
    if (s_fake_gps_enabled) {
        coord->latitude = s_fake_lat;
        coord->longitude = s_fake_lon;
        pthread_mutex_unlock(&s_lock);
        return;
    }
    if (!CLLocationCoordinate2DIsValid(*coord)) {
        pthread_mutex_unlock(&s_lock);
        return;
    }
    if (fabs(s_off_east) >= 0.001 || fabs(s_off_north) >= 0.001) {
        double r = coord->latitude * (M_PI / 180.0);
        double m_lat = 111132.95 - 559.82 * cos(2.0 * r);
        double m_lon = 111412.84 * cos(r);
        if (m_lat > 1000.0) coord->latitude += (s_off_north / m_lat);
        if (m_lon > 1000.0) coord->longitude += (s_off_east / m_lon);
    }
    if (ts <= 0.0) ts = (double)time(NULL);
    if (!s_has_prev || (ts - s_last_pt.ts) > 30.0 || (ts - s_last_pt.ts) < 0.0) {
        s_last_pt = (typeof(s_last_pt)){ coord->latitude, coord->longitude, ts };
        s_has_prev = true;
        pthread_mutex_unlock(&s_lock);
        return;
    }
    double dt = ts - s_last_pt.ts;
    double dphi = (coord->latitude - s_last_pt.lat) * (M_PI / 180.0);
    double dlam = (coord->longitude - s_last_pt.lon) * (M_PI / 180.0);
    double r = s_last_pt.lat * (M_PI / 180.0);
    double dx = dlam * cos(r) * 6371000.0;
    double dy = dphi * 6371000.0;
    double dist = sqrt(dx * dx + dy * dy);
    double spd = dt > 0 ? (dist / dt) : 0;

    if (s_vel_clamp && spd > (s_max_speed_kmh / 3.6)) {
        coord->latitude = s_last_pt.lat; coord->longitude = s_last_pt.lon;
    } else if (s_static_nav && (dist < 2.5 || spd < 1.2)) {
        coord->latitude = s_last_pt.lat; coord->longitude = s_last_pt.lon;
    } else if (s_smoothing) {
        coord->latitude = s_last_pt.lat + 0.35 * (coord->latitude - s_last_pt.lat);
        coord->longitude = s_last_pt.lon + 0.35 * (coord->longitude - s_last_pt.lon);
    }
    s_last_pt = (typeof(s_last_pt)){ coord->latitude, coord->longitude, ts };
    pthread_mutex_unlock(&s_lock);
}

static void reload_prefs(void) {
    NSDictionary *p = [NSDictionary dictionaryWithContentsOfFile:@(PREFS_PATH)];
    pthread_mutex_lock(&s_lock);
    id fakeVal = p[@"fake_gps_enabled"];
    s_fake_gps_enabled = (fakeVal != nil) ? [fakeVal boolValue] : false;
    id wlocVal = p[@"online_wloc_enabled"];
    s_online_wloc_enabled = (wlocVal != nil) ? [wlocVal boolValue] : false;
    /* Default to Apple HQ Cupertino if not explicitly set */
    s_fake_lat = p[@"fake_lat"] ? [p[@"fake_lat"] doubleValue] : 37.33182;
    s_fake_lon = p[@"fake_lon"] ? [p[@"fake_lon"] doubleValue] : -122.03118;
    s_off_east = [p[@"offsetEastMeters"] ?: @"0" doubleValue];
    s_off_north = [p[@"offsetNorthMeters"] ?: @"0" doubleValue];
    s_static_nav = p[@"staticNavEnabled"] ? [p[@"staticNavEnabled"] boolValue] : true;
    s_vel_clamp = p[@"velocityClampEnabled"] ? [p[@"velocityClampEnabled"] boolValue] : true;
    s_smoothing = p[@"smoothingEnabled"] ? [p[@"smoothingEnabled"] boolValue] : true;
    s_max_speed_kmh = [p[@"maxSpeedKmh"] doubleValue] > 0 ? [p[@"maxSpeedKmh"] doubleValue] : 120.0;
    pthread_mutex_unlock(&s_lock);
}

@interface LGFakeGPSTimer : NSObject
@property (nonatomic, weak) CLLocationManager *manager;
@property (nonatomic, strong) NSTimer *timer;
- (void)fireTick:(NSTimer *)t;
@end

@implementation LGFakeGPSTimer
- (void)fireTick:(NSTimer *)t {
    pthread_mutex_lock(&s_lock);
    bool fake = s_fake_gps_enabled;
    double lat = s_fake_lat;
    double lon = s_fake_lon;
    pthread_mutex_unlock(&s_lock);

    if (!fake || !self.manager) {
        [t invalidate];
        return;
    }

    id delegate = self.manager.delegate;
    if (!delegate) return;

    CLLocation *loc = [[CLLocation alloc] initWithCoordinate:CLLocationCoordinate2DMake(lat, lon)
                                                    altitude:10.0
                                          horizontalAccuracy:5.0
                                            verticalAccuracy:5.0
                                                      course:0.0
                                                       speed:0.0
                                                   timestamp:[NSDate date]];

    if ([delegate respondsToSelector:@selector(locationManager:didUpdateLocations:)]) {
        [delegate locationManager:self.manager didUpdateLocations:@[loc]];
    } else if ([delegate respondsToSelector:@selector(locationManager:didUpdateToLocation:fromLocation:)]) {
        [delegate locationManager:self.manager didUpdateToLocation:loc fromLocation:loc];
    }
}
- (void)dealloc {
    [self.timer invalidate];
    self.timer = nil;
}
@end

static const char *kLGFakeTimerKey = "LGFakeTimerKey";

static void (*orig_startUpdatingLocation)(id, SEL);
static void hooked_startUpdatingLocation(id self, SEL _cmd) {
    pthread_mutex_lock(&s_lock);
    bool fake = s_fake_gps_enabled;
    pthread_mutex_unlock(&s_lock);

    if (!fake) {
        orig_startUpdatingLocation(self, _cmd);
        return;
    }

    LGFakeGPSTimer *existing = objc_getAssociatedObject(self, kLGFakeTimerKey);
    if (existing) return;

    LGFakeGPSTimer *ft = [[LGFakeGPSTimer alloc] init];
    ft.manager = self;
    ft.timer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                target:ft
                                              selector:@selector(fireTick:)
                                              userInfo:nil
                                               repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:ft.timer forMode:NSRunLoopCommonModes];
    objc_setAssociatedObject(self, kLGFakeTimerKey, ft, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(400 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
        LGFakeGPSTimer *cur = objc_getAssociatedObject(self, kLGFakeTimerKey);
        if (cur) {
            [cur fireTick:nil];
        }
    });
}

static void (*orig_stopUpdatingLocation)(id, SEL);
static void hooked_stopUpdatingLocation(id self, SEL _cmd) {
    LGFakeGPSTimer *ft = objc_getAssociatedObject(self, kLGFakeTimerKey);
    if (ft) {
        [ft.timer invalidate];
        ft.timer = nil;
        objc_setAssociatedObject(self, kLGFakeTimerKey, nil, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    }
    orig_stopUpdatingLocation(self, _cmd);
}

static id (*orig_clm_location)(id, SEL);
static id hooked_clm_location(id self, SEL _cmd) {
    pthread_mutex_lock(&s_lock);
    bool fake = s_fake_gps_enabled;
    double lat = s_fake_lat;
    double lon = s_fake_lon;
    pthread_mutex_unlock(&s_lock);
    if (fake) {
        return [[CLLocation alloc] initWithCoordinate:CLLocationCoordinate2DMake(lat, lon)
                                             altitude:10.0
                                   horizontalAccuracy:5.0
                                     verticalAccuracy:5.0
                                               course:0.0
                                                speed:0.0
                                            timestamp:[NSDate date]];
    }
    return orig_clm_location ? orig_clm_location(self, _cmd) : nil;
}

static id (*orig_pl_location)(id, SEL);
static id hooked_pl_location(id self, SEL _cmd) {
    pthread_mutex_lock(&s_lock);
    bool fake = s_fake_gps_enabled;
    double lat = s_fake_lat;
    double lon = s_fake_lon;
    pthread_mutex_unlock(&s_lock);
    if (fake) {
        return [[CLLocation alloc] initWithCoordinate:CLLocationCoordinate2DMake(lat, lon)
                                             altitude:10.0
                                   horizontalAccuracy:5.0
                                     verticalAccuracy:5.0
                                               course:0.0
                                                speed:0.0
                                            timestamp:[NSDate date]];
    }
    return orig_pl_location ? orig_pl_location(self, _cmd) : nil;
}

__attribute__((constructor)) static void init(void) {
    signal(SIGPIPE, SIG_IGN);
    const char *p = getprogname();
    if (p && strcmp(p, "locationd") == 0) {
        pthread_t t1, t2;
        pthread_create(&t1, NULL, ephemeris_server, NULL);
        pthread_create(&t2, NULL, telemetry_bridge, NULL);
        pthread_detach(t1); pthread_detach(t2);

        MSHookFunction((void *)CFURLCreateWithBytes, (void *)hooked_CFURLCreateWithBytes, (void **)&orig_CFURLCreateWithBytes);
        MSHookFunction((void *)CFURLCreateWithString, (void *)hooked_CFURLCreateWithString, (void **)&orig_CFURLCreateWithString);
        MSHookFunction((void *)SecTrustEvaluate, (void *)hooked_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);

        uintptr_t off = resolve_gpsTimeToEpoch_offset();
        if (off != 0) {
            uintptr_t target = _dyld_get_image_vmaddr_slide(0) + off + 1; /* Thumb mode +1 */
            MSHookFunction((void *)target, (void *)hooked_gpsTimeToEpoch, (void **)&orig_gpsTimeToEpoch);
        }
    }
    reload_prefs();
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, (CFNotificationCallback)reload_prefs, CFSTR("com.noname122021.legacygpsfix.prefschanged"), NULL, 0);

    Class clmCls = objc_getClass("CLLocationManager");
    if (clmCls) {
        MSHookMessageEx(clmCls, @selector(startUpdatingLocation), (IMP)hooked_startUpdatingLocation, (IMP *)&orig_startUpdatingLocation);
        MSHookMessageEx(clmCls, @selector(stopUpdatingLocation), (IMP)hooked_stopUpdatingLocation, (IMP *)&orig_stopUpdatingLocation);
        MSHookMessageEx(clmCls, @selector(location), (IMP)hooked_clm_location, (IMP *)&orig_clm_location);
    }

    if (!p || strcmp(p, "locationd") != 0) {
        Class plCls = objc_getClass("PLLocationController");
        if (!plCls) {
            dlopen("/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/PhotoLibraryServices", RTLD_LAZY);
            plCls = objc_getClass("PLLocationController");
        }
        if (plCls) {
            MSHookMessageEx(plCls, @selector(location), (IMP)hooked_pl_location, (IMP *)&orig_pl_location);
        }
    }
}
