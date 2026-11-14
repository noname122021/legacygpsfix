ARCHS = armv7
TARGET = iphone:clang:6.1:5.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LegacyGPSFix
LegacyGPSFix_FILES = Tweak.m
LegacyGPSFix_CFLAGS = -fobjc-arc -I../packages/tls/include
LegacyGPSFix_FRAMEWORKS = CoreFoundation CFNetwork Security CoreLocation
LegacyGPSFix_LIBRARIES = substrate
LegacyGPSFix_OBJ_FILES = ../packages/tls/lib/libmbedtls.a ../packages/tls/lib/libmbedx509.a ../packages/tls/lib/libmbedcrypto.a

SUBPROJECTS = LegacyGPSFixPrefs

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/aggregate.mk

