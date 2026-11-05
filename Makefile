ARCHS = armv7
TARGET = iphone:clang:6.1:5.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LegacyGPSFix
LegacyGPSFix_FILES = Tweak.m
LegacyGPSFix_CFLAGS = -fobjc-arc -I../tls/include
LegacyGPSFix_FRAMEWORKS = CoreFoundation CFNetwork Security CoreLocation
LegacyGPSFix_LIBRARIES = substrate
LegacyGPSFix_OBJ_FILES = ../tls/lib/libmbedtls.a ../tls/lib/libmbedx509.a ../tls/lib/libmbedcrypto.a

SUBPROJECTS = LegacyGPSFixPrefs

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/aggregate.mk
