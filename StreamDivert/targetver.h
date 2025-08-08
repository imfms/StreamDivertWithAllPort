#pragma once

// Including SDKDDKVer.h defines the highest available Windows platform.

// If you wish to build your application for a previous Windows platform, include WinSDKVer.h and
// set the _WIN32_WINNT macro to the platform you wish to support before including SDKDDKVer.h.

#ifndef WINVER
#define WINVER 0x0A00         // Windows 10
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00   // Windows 10
#endif

// Try to include SDKDDKVer.h, fallback to manual defines if not available
#ifdef __has_include
  #if __has_include(<SDKDDKVer.h>)
    #include <SDKDDKVer.h>
  #endif
#else
  // Manual fallback for older compilers
  #include <SDKDDKVer.h>
#endif
