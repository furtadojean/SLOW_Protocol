#include <iostream>
#include <vector>
#include <cstring>
#include <array>
#include <random>
#include <chrono>
#include <thread>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <deque>
#include <queue>

using UUID = std::array<uint8_t, 16>;
constexpr uint16_t PORT = 7033;
constexpr size_t MAX_PACKET_SIZE = 1472;
constexpr size_t HEADER_SIZE = 32;
constexpr size_t MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE;
constexpr char CENTRAL_IP[] = "142.93.184.175";
constexpr uint16_t LOCAL_RECV_BUF_CAPACITY = 1024;
std::queue<std::vector<uint8_t>> receive_buffer;

// Flags
enum SLOWFlags {
    CONNECT = 1 << 4,
    REVIVE  = 1 << 3,
    ACK     = 1 << 2,
    ACCEPT  = 1 << 1,
    MB      = 1 << 0
};

bool debug = true;

UUID generate_uuid() {
    UUID uuid{};
    std::random_device rd;
    std::mt19937 gen(rd());
    for (int i = 0; i < 16; ++i)
        uuid[i] = gen() & 0xFF;

    // Set version to 8 (UUIDv8) in byte 6 (bits 4 high)
    uuid[6] = (uuid[6] & 0x0F) | (8 << 4);

    // Set variant to 0b10 in byte 8 (bits 6–7)
    uuid[8] = (uuid[8] & 0x3F) | 0x80;

    return uuid;
}

UUID nil_uuid() {
    UUID uuid{};
    uuid.fill(0);
    return uuid;
}

void print_packet_info(const std::vector<uint8_t>& packet, const std::string& label, bool show_data = false) {
    std::cout << "\n=== " << label << " ===\n";

    // Print SID
    UUID sid;
    std::copy(packet.begin(), packet.begin() + 16, sid.begin());

    printf("SID: ");
    for (auto b : sid) printf("%02x", b);
    std::cout << '\n';

    // ================================
    // Decode individual flags (bits 0–4)
    // ================================
    uint8_t flags_byte = packet[16];
    bool flag_connect = flags_byte & (1 << 4);
    bool flag_revive  = flags_byte & (1 << 3);
    bool flag_ack     = flags_byte & (1 << 2);
    bool flag_accept  = flags_byte & (1 << 1);
    bool flag_mb      = flags_byte & (1 << 0);

    std::cout << "Flags: ";
    if (flag_connect) std::cout << "[CONNECT] ";
    if (flag_revive)  std::cout << "[REVIVE] ";
    if (flag_ack)     std::cout << "[ACK] ";
    if (flag_accept)  std::cout << "[ACCEPT] ";
    if (flag_mb)      std::cout << "[MB] ";
    std::cout << "\n";

    // ================================
    // Decode 27-bit sttl (bit-level LE)
    // ================================
    // Bits 5–7 of packet[16], all bits of 17–19
    uint32_t sttl_packed = ((packet[16] >> 5) & 0x07)        // bits 0–2
                         | (packet[17] << 3)                 // bits 3–10
                         | (packet[18] << 11)                // bits 11–18
                         | (packet[19] << 19);               // bits 19–26

    uint32_t sttl = sttl_packed << 5; // align left, reverse bits, then shift back
    sttl >>= 5;  // shift back to original 27-bit position

    std::cout << "STTL: " << sttl << " ms\n";

    // ================================
    // Decode other multi-byte fields
    // ================================
    uint32_t seqnum, acknum;
    memcpy(&seqnum, &packet[20], 4);
    memcpy(&acknum, &packet[24], 4);
    seqnum = seqnum;
    acknum = acknum;

    uint16_t window;
    memcpy(&window, &packet[28], 2);
    window = window;

    uint8_t fid = packet[30];
    uint8_t fo  = packet[31];

    std::cout << "SeqNum: " << seqnum << ", AckNum: " << acknum << ", Window: " << window << "\n";
    std::cout << "FID: " << (int)fid << ", FO: " << (int)fo << "\n";

    // ================================
    // Print Data (if present)
    // ================================
    if (show_data && packet.size() > 32) {
        size_t len = packet.size() - 32;
        std::cout << "Data (" << len << " bytes):\n";
        for (size_t i = 32; i < packet.size(); ++i) {
            printf("%02x ", packet[i]);
            if ((i - 32 + 1) % 16 == 0) std::cout << '\n';
        }
        std::cout << std::endl;  // Final newline after printing all characters
        for (size_t i = 32; i < packet.size(); ++i) {
            // Print each byte as a character
            std::cout << static_cast<char>(packet[i]);
        }
        std::cout << std::endl;  // Final newline after printing all characters
    }

    std::cout << "\n=======================\n";
}


std::vector<uint8_t> build_packet(UUID sid,
                                  uint8_t flags,
                                  uint32_t sttl, uint32_t seqnum, uint32_t acknum,
                                  uint16_t window, uint8_t fid, uint8_t fo,
                                  const std::vector<uint8_t>& data) {
    std::vector<uint8_t> packet(HEADER_SIZE + data.size());

    // ✅ Copy full UUID, including byte 15
    std::copy(sid.begin(), sid.end(), packet.begin());  // bytes 0–15

    // ✅ Set individual flags (bits 0–4)
    //uint8_t flags_byte = reverse_bits<uint8_t>(flags) >> 3;
    uint8_t flags_byte = flags;

    packet[16] = flags_byte;

    // ✅ Bit-level little endian for 27-bit sttl
    uint32_t sttl_reversed = sttl >> 5;  // keep only 27 bits

    // Place lower 3 bits of sttl in bits 5–7 of packet[16]
    packet[16] |= ((sttl_reversed & 0x07) << 5);

    // Place remaining sttl bits in packet[17–19]
    packet[17] = (sttl_reversed >> 3) & 0xFF;
    packet[18] = (sttl_reversed >> 11) & 0xFF;
    packet[19] = (sttl_reversed >> 19) & 0xFF;

    // ✅ Multi-byte fields: bit-level little endian
    uint32_t seqnum_rev = seqnum;
    uint32_t acknum_rev = acknum;
    uint16_t window_rev = window;

    memcpy(&packet[20], &seqnum_rev, 4);
    memcpy(&packet[24], &acknum_rev, 4);
    memcpy(&packet[28], &window_rev, 2);

    packet[30] = fid;
    packet[31] = fo;

    std::copy(data.begin(), data.end(), packet.begin() + HEADER_SIZE);
    return packet;
}


int create_socket(struct sockaddr_in& server) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "socket creation failed: " << strerror(errno) << std::endl;
        return -1;
    }

    // Prepare server address struct
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    if (inet_pton(AF_INET, CENTRAL_IP, &server.sin_addr) != 1) {
        std::cerr << "inet_pton failed for server IP" << std::endl;
        close(sock);
        return -1;
    }

    // Bind socket to local address (0.0.0.0) and ephemeral port (0)
    struct sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // 0.0.0.0
    local_addr.sin_port = 0;                         // ephemeral port

    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) == -1) {
        std::cerr << "bind failed: " << strerror(errno) << std::endl;
        close(sock);
        return -1;
    }

    return sock;
}

bool receive_response(int sock, std::vector<uint8_t>& buffer) {
    buffer.resize(1472);
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    struct timeval timeout{10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ssize_t len = recvfrom(sock, buffer.data(), buffer.size(), 0, (sockaddr*)&from, &fromlen);
    buffer.resize(len > 0 ? len : 0);
    if (len > 32 && receive_buffer.size() < LOCAL_RECV_BUF_CAPACITY) {
        std::vector<uint8_t> received_data(buffer.begin() + 32, buffer.end());
        receive_buffer.push(received_data);
    }
    return len > 0;
}

bool send_3way_connect(int sock, sockaddr_in& server, UUID& session_id, uint32_t& seqnum) {
    auto pkt = build_packet(nil_uuid(), CONNECT, 0, 0, 0, LOCAL_RECV_BUF_CAPACITY, 0, 0, {});
    if (debug) print_packet_info(pkt, "SENT: CONNECT");

    // Check if socket is valid (non-negative)
    if (sock < 0) {
        std::cerr << "Error: Invalid socket descriptor " << sock << std::endl;
        return false;
    }

    // Check and print local socket address
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr*)&local_addr, &addr_len) == -1) {
        std::cerr << "Warning: getsockname failed: " << strerror(errno) << std::endl;
    } else {
        char local_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_addr.sin_addr, local_ip_str, sizeof(local_ip_str));
        std::cout << "Socket bound to local address " << local_ip_str << ":" << ntohs(local_addr.sin_port) << std::endl;
    }

    // Print server (destination) address
    char server_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &server.sin_addr, server_ip_str, sizeof(server_ip_str));
    std::cout << "Server address is " << server_ip_str << ":" << ntohs(server.sin_port) << std::endl;

    // Send packet
    ssize_t sent_bytes = sendto(sock, pkt.data(), pkt.size(), 0, (sockaddr*)&server, sizeof(server));
    if (sent_bytes == -1) {
        std::cerr << "sendto failed: " << strerror(errno) << std::endl;
        return false;
    }
    if (sent_bytes < (ssize_t)pkt.size()) {
        std::cerr << "Warning: sendto sent fewer bytes (" << sent_bytes << ") than packet size (" << pkt.size() << ")" << std::endl;
    } else {
        if (debug) std::cout << "sendto succeeded, sent " << sent_bytes << " bytes" << std::endl;
    }

    std::vector<uint8_t> response;
    if (receive_response(sock, response)) {
        if (debug) print_packet_info(response, "RECEIVED: SETUP", true);
        bool accepted = response[16] & ACCEPT;
        if (accepted) {
            std::copy(response.begin(), response.begin() + 16, session_id.begin());
            memcpy(&seqnum, &response[20], 4);
            return true;
        }
    }

    return false;
}

bool send_data(int sock, sockaddr_in& server, UUID sid, uint32_t sttl, uint32_t& seqnum,
               uint32_t& acknum, std::vector<uint8_t> payload,
               uint8_t base_flags = ACK, const std::string& label = "DATA") {
    size_t offset = 0, fid = 1;
    const uint32_t initial_window = 64;
    uint32_t remote_window = initial_window;
    uint32_t last_ack = acknum;

    struct InFlight {
        uint32_t seq;
        uint32_t size;
        std::vector<uint8_t> packet;
    };

    std::deque<InFlight> inflight;

    while (offset < payload.size() || !inflight.empty()) {
        while (!inflight.empty() && inflight.front().seq < last_ack) inflight.pop_front();

        uint32_t in_flight_bytes = 0;
        for (auto& p : inflight) in_flight_bytes += p.size;

        if (offset < payload.size() && (in_flight_bytes < remote_window)) {
            size_t chunk = std::min<size_t>(MAX_DATA_SIZE, payload.size() - offset);
            if (chunk > remote_window - in_flight_bytes) chunk = remote_window - in_flight_bytes;

            std::vector<uint8_t> data(payload.begin() + offset, payload.begin() + offset + chunk);
            bool more = offset + chunk < payload.size();
            uint8_t flags = base_flags | (more ? MB : 0);

            uint16_t local_window = LOCAL_RECV_BUF_CAPACITY - receive_buffer.size();
            auto pkt = build_packet(sid, flags, sttl, seqnum, last_ack,
                                    local_window, fid, offset / MAX_DATA_SIZE, data);

            if (debug) print_packet_info(pkt, "SENT: " + label, true);

            sendto(sock, pkt.data(), pkt.size(), 0, (sockaddr*)&server, sizeof(server));
            inflight.push_back({seqnum, (uint32_t)data.size(), pkt});
            ++seqnum;
            offset += chunk;
        }

        std::vector<uint8_t> resp;
        if (receive_response(sock, resp)) {
            if (debug) print_packet_info(resp, "RECEIVED: " + label);
            uint32_t recv_acknum;
            memcpy(&recv_acknum, &resp[24], 4);
            recv_acknum = recv_acknum;
            if (recv_acknum > last_ack) {
                last_ack = recv_acknum;
                while (!inflight.empty() && inflight.front().seq <= recv_acknum) inflight.pop_front();
            }

            uint16_t recv_window;
            memcpy(&recv_window, &resp[28], 2);
            remote_window = recv_window;
            memcpy(&acknum, &last_ack, 4);
        } else {
            if (!inflight.empty()) {
                if (debug) std::cout << "[!] Timeout. Reenviando pacote: seq=" << inflight.front().seq << std::endl;
                sendto(sock, inflight.front().packet.data(), inflight.front().packet.size(), 0, (sockaddr*)&server, sizeof(server));
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }
    }
    return true;
}

void send_disconnect(int sock, sockaddr_in& server, UUID sid, uint32_t sttl, uint32_t& seqnum, uint32_t& acknum) {
    uint8_t flags = CONNECT | REVIVE | ACK;
    auto pkt = build_packet(sid, flags, sttl, seqnum, acknum, 0, 0, 0, {});
    if (debug) print_packet_info(pkt, "SENT: DISCONNECT");
    sendto(sock, pkt.data(), pkt.size(), 0, (sockaddr*)&server, sizeof(server));

    std::vector<uint8_t> response;
    if (receive_response(sock, response)) {
        if (debug) print_packet_info(response, "RECEIVED: FINAL ACK");
        memcpy(&acknum, &response[24], 4);
        acknum = acknum;
    }
    seqnum += 1;
}

int main() {
    sockaddr_in server{};
    int sock = create_socket(server);
    UUID session_id;
    uint32_t seqnum;
    uint32_t last_ack;

    std::cout << "[*] Conectando ao central...\n";
    if (!send_3way_connect(sock, server, session_id, last_ack)) {
        std::cerr << "[!] Falha na conexão 3-way.\n";
        return 1;
    }
    seqnum = last_ack + 1;

    std::cout << "[+] Sessão aceita! Enviando dados iniciais...\n";
    std::string mensagem = "Mensagem de teste com fragmentação e janela!";
    std::vector<uint8_t> payload(mensagem.begin(), mensagem.end());
    send_data(sock, server, session_id, 3000, seqnum, last_ack, payload, ACK, "DATA");

    std::cout << "[*] Enviando disconnect...\n";
    send_disconnect(sock, server, session_id, 3000, seqnum, last_ack);

    std::cout << "[*] Esperando antes de enviar novos dados via 0-way...\n";
    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::string nova_mensagem = "Mensagem enviada usando 0-way connect!";
    std::vector<uint8_t> nova_payload(nova_mensagem.begin(), nova_mensagem.end());
    send_data(sock, server, session_id, 3000, seqnum, last_ack, nova_payload, ACK | REVIVE, "0-WAY DATA");

    std::cout << "[*] Enviando disconnect...\n";
    send_disconnect(sock, server, session_id, 3000, seqnum, last_ack);

    close(sock);
    std::cout << "[✓] Finalizado.\n";
    return 0;
}
