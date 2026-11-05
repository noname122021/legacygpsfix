ARCHS = armv7
TARGET = iphone:clang:6.1:5.0

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = LegacyGPSFix
LegacyGPSFix_FILES = LegacyGPSFixListController.m
LegacyGPSFix_INSTALL_PATH = /Library/PreferenceBundles
LegacyGPSFix_FRAMEWORKS = UIKit CoreGraphics CoreFoundation
LegacyGPSFix_PRIVATE_FRAMEWORKS = Preferences
LegacyGPSFix_LIBRARIES = MobileGestalt
LegacyGPSFix_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/bundle.mk
