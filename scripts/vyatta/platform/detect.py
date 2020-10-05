#!/usr/bin/python3

def detect():
    class UnknownPlatform(object):
        def get_platform_string(self):
            return "unknown"
    return UnknownPlatform()

class PlatformError(Exception):
    pass
