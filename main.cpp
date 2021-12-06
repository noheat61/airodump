#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iso646.h>
#include <string>
#include <map>
#include "wireless.h"
using namespace std;

map<string, pair<string, int>> beacon_table;

int main(int argc, char *argv[])
{
    //매개변수 확인(2개여야 함)
    if (argc not_eq 2)
    {
        printf("syntax : airodump <interface>\n");
        printf("sample : airodump mon0\n");
        return -1;
    }

    // pcap_open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        return -1;
    }

    //초기 출력
    system("clear");
    printf("BSSID\t\t\tBeacons\tESSID\n\n");

    while (1)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        
        // reply 수신
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        // header
        ieee80211_radiotap_header *radiotap = (ieee80211_radiotap_header *)packet;
        ieee80211_beacon_header *beacon = (ieee80211_beacon_header *)(packet + radiotap->it_len);
        if (beacon->type not_eq ieee80211_beacon_header::BEACON)
            continue;
        fixed_parameters *fixed = (fixed_parameters *)(packet + radiotap->it_len + sizeof(struct ieee80211_beacon_header));
        tagged_parameters *tagged = (tagged_parameters *)(packet + radiotap->it_len + sizeof(struct ieee80211_beacon_header) + 12);

        // beacon++
        string bssid = string(beacon->bssid);
        if (beacon_table.count(bssid))
            beacon_table[bssid].second++;
        else
        {
            const u_char *essid_ptr = (const u_char *)tagged + 2;
            string essid;
            for (uint8_t i = 0; i < tagged->tag_len; i++)
                essid.push_back(*essid_ptr++);
            beacon_table.insert({bssid, {essid, 1}});
        }

        // 출력
        system("clear");
        printf("BSSID\t\t\tBeacons\tESSID\n\n");
        for (auto &tmp : beacon_table)
        {
            printf("%s\t", tmp.first.c_str());
            printf("%7d\t", tmp.second.second);
            printf("%s\n", tmp.second.first.c_str());
        }
    }

    pcap_close(handle);
    return 0;
}
