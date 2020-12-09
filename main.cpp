#include <cstdio>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>

char ssid[100][32];
int num;

typedef struct ieee80211_radiotap_header{
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int64_t it_present;
    u_int64_t MAC_timestamp;
    u_int8_t flags;
    u_int8_t dataRate;
    u_int16_t channelfrequency;
    u_int16_t channelType;
    int8_t ant_sig0;
    u_int16_t RX_flag;
    u_int8_t ant_sig1;
    u_int8_t ant;
}Radiotap_Header;

typedef struct beacon_frame{
    uint8_t fc[2];        
    uint16_t duration;
    uint8_t receiver_mac[6]; 
    uint8_t sender_mac[6]; 
    uint8_t BSSID[6];
    uint16_t frag_seq_num; 
}Dot11_Frame;

typedef struct Dot11_frame_body{
    u_int64_t timestamp;
    u_int16_t beacon_interval;
    u_int16_t capacity_information;
    u_int8_t element_id;
    u_int8_t ssid_length;
    char ssid[32];
}Frame_Body;

void usage(){
    printf("syntax : airodump <interface>\nsample : airodump mon0");
}

void print_beaconframe(const u_char* packet){
    Radiotap_Header *radiotap_header;
    radiotap_header = (Radiotap_Header*)packet;

    Dot11_Frame *dot11_frame;
    dot11_frame = (Dot11_Frame*)(packet + radiotap_header->it_len);

    if((dot11_frame->fc[1] != 0x00) || (dot11_frame->fc[0] != 0x80)){
        return;
    }

    printf("beacon frame");

    printf("  BSSID: %02x:%02x:%02x:%02x:%02x:%02x", dot11_frame->BSSID[0],dot11_frame->BSSID[1],
    dot11_frame->BSSID[2],dot11_frame->BSSID[3],dot11_frame->BSSID[4],dot11_frame->BSSID[5]);

    Frame_Body *frame_body;
    frame_body = (Frame_Body*)(packet + radiotap_header->it_len + sizeof(Dot11_Frame));

    char new_ssid[32];
    strncpy(new_ssid, frame_body->ssid, frame_body-> ssid_length);
    new_ssid[frame_body->ssid_length] = '\0';
    printf("  SSID: %s", new_ssid);
 
     int really_new = 0;

    for(int i=0;i<num-1;i++){
        if(strcmp(new_ssid, ssid[i])==0){
            really_new = i+1;
        }
    }

    if(really_new == 0){
        strncpy(ssid[num], frame_body->ssid, frame_body-> ssid_length);
        ssid[num][ssid, frame_body-> ssid_length] = '\0';
        num++;
        really_new = num;
    }

    printf("  Num: %d",really_new;
    
    printf("  PWR: %d dBm\n",radiotap_header->ant_sig0);

}



int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

    char* dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            return -1;
        }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        print_beaconframe(packet);
    }
    pcap_close(handle);
}


