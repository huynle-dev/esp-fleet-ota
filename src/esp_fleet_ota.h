// esp-fleet-ota umbrella header: the pure logic, plus the ESP32 glue on ESP targets.
#pragma once
#include "fleet_ota.h"
#include "fota_target.h"
#if defined(ESP_PLATFORM) && defined(ARDUINO)
#include "esp/fota_esp.h"
#endif
