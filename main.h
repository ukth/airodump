#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/in.h>

struct Radiotap_hdr {
        u_int8_t        it_version;
        u_int8_t        it_pad;
        u_int16_t       it_len;
        u_int32_t       it_present1;
        u_int32_t       it_present2;
        u_int8_t        flags;
        u_int8_t        rate;
        u_int16_t       chan_freq;
        u_int16_t       chan_flags;
        u_int8_t        antsignal_1;
        u_int8_t        padding;
        u_int16_t       rx_flags;
        u_int8_t        antsignal_2;
        u_int8_t        ant;
};

struct Beacon{
    u_int16_t type;
    u_int16_t type_padding;
    u_int8_t dst_addr[6];
    u_int8_t src_addr[6];
    u_int8_t BSSID[6];
    u_int16_t number;
};

struct Wireless{
    u_int8_t timestamp[8];
    u_int16_t beacon_interval;
    u_int16_t capabilties_info;
    u_int8_t tag_num;
    u_int8_t ssid_len;
};