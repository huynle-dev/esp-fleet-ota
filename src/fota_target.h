// Chip and board identity from build macros, so nothing is C3-specific.
//   FOTA_CHIP:  CONFIG_IDF_TARGET from the ESP-IDF sdkconfig ("esp32c3", "esp32s3", ...). Native builds: "native".
//   FOTA_BOARD: set by the device build, e.g. -DFOTA_BOARD=\"esp32-c3-devkitm-1\" (the PlatformIO board id).
//               Unset means "" and the device then refuses manifests that name a board (docs/decisions.md D7).
#pragma once

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#endif

#ifndef FOTA_CHIP
#ifdef CONFIG_IDF_TARGET
#define FOTA_CHIP CONFIG_IDF_TARGET
#else
#define FOTA_CHIP "native"
#endif
#endif

#ifndef FOTA_BOARD
#define FOTA_BOARD ""
#endif
