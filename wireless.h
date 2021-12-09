#pragma once

#include <cstdint>
#include "mac.h"

// radiotap_header https://www.radiotap.org/
#pragma pack(push, 1)
struct ieee80211_radiotap_header
{
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ieee80211_MAC_header
{
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    Mac da;
    Mac sa;
    Mac bssid;
    uint16_t seq;

    // type_subtype
    enum : uint8_t
    {
        BEACON = 0x80,
    };
};
#pragma pack(pop)

#pragma pack(push, 1)
struct fixed_parameters
{
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability_info;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct tagged_parameters
{
    uint8_t tag_num;
    uint8_t tag_len;

    // tag_num
    enum : uint8_t
    {
        SSID = 0, // SSID parameter set
    };
};
#pragma pack(pop)
