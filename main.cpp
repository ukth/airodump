#include "main.h"

void usage(){
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump mon0\n");
}

u_int8_t handle_antsignal(u_int8_t anti_sig){
    u_int8_t n;
    n = ~anti_sig;
    n += 1;
    return n;
}

int main(int argc, char* argv[]){

    if (argc != 2) {
        usage();
        return -1;
    }

    struct Radiotap_hdr* r_hdr;
    struct Beacon* beacon;
    struct Wireless* wrls;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }


    puts("BSSID\t\t\tPWR\t\t\tBeacons\t\t\tESSID\n");

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        r_hdr = (struct Radiotap_hdr*)packet;
        beacon = (struct Beacon*)(packet+r_hdr->it_len);
        wrls = (struct Wireless*)(packet+r_hdr->it_len+sizeof(struct Beacon));
        packet = packet + r_hdr->it_len+sizeof(struct Beacon)+sizeof(struct Wireless);

        handle_antsignal(r_hdr->antsignal_1);

        if(beacon->type == 0x0080){
            printf("%02x:%02x:%02x:%02x:%02x:%02x\t", beacon->BSSID[0], beacon->BSSID[1], beacon->BSSID[2], beacon->BSSID[3], beacon->BSSID[4], beacon->BSSID[5]);
            printf("-%d\t\t",handle_antsignal(r_hdr->antsignal_1));
            printf("%d\t\t\t",beacon->type);

            for(int i = 0; i<wrls->ssid_len; i++){
                        printf("%c", packet[i]);
            }
            printf("\t");
            printf("\n");
        }
    }
    printf("\n\n");

    pcap_close(handle);
}