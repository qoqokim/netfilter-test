#include <header.h>

bool ip_table() {
    system("iptable -F");
    system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    system("iptables -A INPUT -j NFQUEUE --queue-num 0");
    return true;
}
