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

// Definições básicas
using UUID = std::array<uint8_t, 16>;
constexpr uint16_t PORT = 7033;                       // Porta usada pelo servidor central
constexpr size_t MAX_PACKET_SIZE = 1472;              // Tamanho máximo do pacote UDP
constexpr size_t HEADER_SIZE = 32;                    // Tamanho do cabeçalho do protocolo SLOW
constexpr size_t MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE; // Dados por pacote
constexpr char CENTRAL_IP[] = "142.93.184.175";       // IP do servidor central
constexpr uint16_t LOCAL_RECV_BUF_CAPACITY = 1024;    // Capacidade do buffer local de recepção

// Fila de dados recebidos
std::queue<std::vector<uint8_t>> receive_buffer;

// Enumeração das flags do protocolo SLOW (5 bits)
enum SLOWFlags {
    CONNECT = 1 << 4,  // Solicitação de conexão
    REVIVE  = 1 << 3,  // Reviver sessão anterior (0-way connect)
    ACK     = 1 << 2,  // Confirmação de recebimento
    ACCEPT  = 1 << 1,  // Conexão aceita
    MB      = 1 << 0   // Mais fragmentos após esse
};

bool debug = true;  // Flag de depuração (ativa prints detalhados)

// Gera um UUID versão 8 com bits de versão e variante ajustados
UUID generate_uuid() {
    UUID uuid{};

    // ===== custom_a: 48 bits (valores fixos como inteiro) =====
    // Representa os primeiros 6 bytes do UUID
    uint64_t custom_a = 0xDEADBEEFCAFE;  // valor fixo de 48 bits

    for (int i = 0; i < 6; ++i)
        uuid[i] = (custom_a >> (8 * i)) & 0xFF;  // preenche uuid[0] até uuid[5]

    // ===== Byte 6: versão + parte alta de custom_a =====
    // Bits 4–7: versão (8 = 0b1000)
    // Bits 0–3: últimos 4 bits de custom_a (bits 48–51)
    uint8_t version = 0x8;
    uint8_t custom_a_high_nibble = (custom_a >> 48) & 0x0F;
    uuid[6] = (version << 4) | custom_a_high_nibble;

    // ===== Byte 7: custom_b (8 bits livre, aqui fixado) =====
    uuid[7] = 0xAB;

    // ===== custom_c: 62 bits (como inteiro) =====
    // Representa os últimos 62 bits do UUID (após o variant)
    uint64_t custom_c = 0x336699CC00112244 & 0x3FFFFFFFFFFFFFFF;  // máscara para manter só 62 bits

    // ===== Byte 8: variant + primeiros 6 bits de custom_c =====
    // Bits 0–1: variant (0b10)
    // Bits 2–7: bits 0–5 de custom_c
    uuid[8] = ((custom_c & 0xFC) | 0b10);  // variant nos bits menos significativos

    // ===== Bytes 9–15: bits 6–63 de custom_c =====
    for (int i = 1; i < 8; ++i)
        uuid[8 + i] = (custom_c >> (8 * i)) & 0xFF;

    return uuid;
}

// Retorna UUID nulo (todos os bytes zerados)
UUID nil_uuid() {
    UUID uuid{};
    uuid.fill(0);
    return uuid;
}

// Exibe informações do pacote recebido ou enviado (cabeçalho e dados)
void print_packet_info(const std::vector<uint8_t>& packet, const std::string& label, bool show_data = false) {
    std::cout << "\n=== " << label << " ===\n";

    UUID sid;
    std::copy(packet.begin(), packet.begin() + 16, sid.begin());
    printf("SID: "); for (auto b : sid) printf("%02x", b); std::cout << '\n';

    uint8_t flags_byte = packet[16];
    std::cout << "Flags: ";
    if (flags_byte & CONNECT) std::cout << "[CONNECT] ";
    if (flags_byte & REVIVE)  std::cout << "[REVIVE] ";
    if (flags_byte & ACK)     std::cout << "[ACK] ";
    if (flags_byte & ACCEPT)  std::cout << "[ACCEPT] ";
    if (flags_byte & MB)      std::cout << "[MB] ";
    std::cout << "\n";

    // Reconstrói o campo STTL (27 bits)
    uint32_t sttl_packed = ((packet[16] >> 5) & 0x07) | (packet[17] << 3) | (packet[18] << 11) | (packet[19] << 19);
    uint32_t sttl = (sttl_packed << 5) >> 5;  // Remove bits extras
    std::cout << "STTL: " << sttl << " ms\n";

    // Outros campos do cabeçalho
    uint32_t seqnum, acknum;
    memcpy(&seqnum, &packet[20], 4);
    memcpy(&acknum, &packet[24], 4);

    uint16_t window;
    memcpy(&window, &packet[28], 2);

    uint8_t fid = packet[30];
    uint8_t fo  = packet[31];

    std::cout << "SeqNum: " << seqnum << ", AckNum: " << acknum << ", Window: " << window << "\n";
    std::cout << "FID: " << (int)fid << ", FO: " << (int)fo << "\n";

    // Exibe dados, se houver
    if (show_data && packet.size() > HEADER_SIZE) {
        size_t len = packet.size() - HEADER_SIZE;
        std::cout << "Data (" << len << " bytes):\n";
        for (size_t i = HEADER_SIZE; i < packet.size(); ++i) {
            printf("%02x ", packet[i]);
            if ((i - HEADER_SIZE + 1) % 16 == 0) std::cout << '\n';
        }
        std::cout << std::endl;
        for (size_t i = HEADER_SIZE; i < packet.size(); ++i)
            std::cout << static_cast<char>(packet[i]);
        std::cout << std::endl;
    }
    std::cout << "\n=======================\n";
}

// Constroi um pacote SLOW com os campos fornecidos (UUID, flags, cabeçalho, dados)
std::vector<uint8_t> build_packet(UUID sid, uint8_t flags, uint32_t sttl,
                                  uint32_t seqnum, uint32_t acknum,
                                  uint16_t window, uint8_t fid, uint8_t fo,
                                  const std::vector<uint8_t>& data) {
    std::vector<uint8_t> packet(HEADER_SIZE + data.size());

    std::copy(sid.begin(), sid.end(), packet.begin());  // UUID nos bytes 0–15
    packet[16] = flags;  // flags (5 bits) + 3 bits iniciais do STTL

    uint32_t sttl_short = sttl >> 5;  // STTL com 27 bits
    packet[16] |= ((sttl_short & 0x07) << 5);
    packet[17] = (sttl_short >> 3) & 0xFF;
    packet[18] = (sttl_short >> 11) & 0xFF;
    packet[19] = (sttl_short >> 19) & 0xFF;

    memcpy(&packet[20], &seqnum, 4);
    memcpy(&packet[24], &acknum, 4);
    memcpy(&packet[28], &window, 2);
    packet[30] = fid;
    packet[31] = fo;

    std::copy(data.begin(), data.end(), packet.begin() + HEADER_SIZE);
    return packet;
}

// Cria e configura um socket UDP local, retornando seu descritor
int create_socket(struct sockaddr_in& server) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "socket creation failed: " << strerror(errno) << std::endl;
        return -1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    if (inet_pton(AF_INET, CENTRAL_IP, &server.sin_addr) != 1) {
        std::cerr << "inet_pton failed for server IP" << std::endl;
        close(sock);
        return -1;
    }

    struct sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = 0;

    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) == -1) {
        std::cerr << "bind failed: " << strerror(errno) << std::endl;
        close(sock);
        return -1;
    }

    return sock;
}


// Recebe uma resposta do servidor e adiciona os dados no buffer de recepção
bool receive_response(int sock, std::vector<uint8_t>& buffer) {
    buffer.resize(MAX_PACKET_SIZE);
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    struct timeval timeout{10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ssize_t len = recvfrom(sock, buffer.data(), buffer.size(), 0, (sockaddr*)&from, &fromlen);
    buffer.resize(len > 0 ? len : 0);

    if ((unsigned)len > (unsigned)HEADER_SIZE && receive_buffer.size() < LOCAL_RECV_BUF_CAPACITY) {
        std::vector<uint8_t> received_data(buffer.begin() + HEADER_SIZE, buffer.end());
        receive_buffer.push(received_data);
    }
    return len > 0;
}

// Função responsável por enviar dados para o servidor usando o protocolo SLOW.
// Essa função lida com fragmentação, janela deslizante e retransmissão em caso de timeout.
// Também pode ser usada tanto para uma conexão normal quanto para um 0-way connect, dependendo das flags recebidas.
bool send_data(int sock, sockaddr_in& server, UUID sid, uint32_t sttl, uint32_t& seqnum,
               uint32_t& acknum, std::vector<uint8_t> payload,
               uint8_t base_flags = ACK, const std::string& label = "DATA") {
    size_t offset = 0, fid = 1;

    // Janela inicial presumida do central
    const uint32_t initial_window = 64;
    uint32_t remote_window = initial_window;

    // Último ack conhecido
    uint32_t last_ack = acknum;

    // Estrutura que representa um pacote enviado, mas ainda não confirmado
    struct InFlight {
        uint32_t seq;
        uint32_t size;
        std::vector<uint8_t> packet;
    };

    std::deque<InFlight> inflight;

    // Continua enquanto ainda houver dados para enviar ou pacotes pendentes de ACK
    while (offset < payload.size() || !inflight.empty()) {

        // Remove pacotes da fila de envio que já foram confirmados
        while (!inflight.empty() && inflight.front().seq < last_ack)
            inflight.pop_front();

        // Soma total de bytes atualmente em trânsito
        uint32_t in_flight_bytes = 0;
        for (auto& p : inflight) in_flight_bytes += p.size;

        // Se ainda houver dados a enviar e a janela do receptor permitir, envie novo fragmento
        if (offset < payload.size() && (in_flight_bytes < remote_window)) {
            size_t chunk = std::min<size_t>(MAX_DATA_SIZE, payload.size() - offset);
            if (chunk > remote_window - in_flight_bytes)
                chunk = remote_window - in_flight_bytes;

            std::vector<uint8_t> data(payload.begin() + offset, payload.begin() + offset + chunk);
            bool more = offset + chunk < payload.size();

            // Seta as flags: base + MB se ainda houver mais fragmentos após esse
            uint8_t flags = base_flags | (more ? MB : 0);

            // Informa ao central quantos bytes ainda cabem no nosso buffer local
            uint16_t local_window = LOCAL_RECV_BUF_CAPACITY - receive_buffer.size();

            // Cria pacote para enviar
            auto pkt = build_packet(sid, flags, sttl, seqnum, last_ack,
                                    local_window, fid, offset / MAX_DATA_SIZE, data);

            if (debug) print_packet_info(pkt, "SENT: " + label, true);

            // Envia pacote
            sendto(sock, pkt.data(), pkt.size(), 0, (sockaddr*)&server, sizeof(server));

            // Armazena pacote na fila de inflight
            inflight.push_back({seqnum, (uint32_t)data.size(), pkt});
            ++seqnum;
            offset += chunk;
        }

        // Tenta receber ACK
        std::vector<uint8_t> resp;
        if (receive_response(sock, resp)) {
            if (debug) print_packet_info(resp, "RECEIVED: " + label);

            // Lê número de ACK do central
            uint32_t recv_acknum;
            memcpy(&recv_acknum, &resp[24], 4);

            // Atualiza o último ACK conhecido
            if (recv_acknum > last_ack) {
                last_ack = recv_acknum;

                // Remove todos os pacotes até o ack recebido
                while (!inflight.empty() && inflight.front().seq <= recv_acknum)
                    inflight.pop_front();
            }

            // Atualiza a janela do central com base na resposta
            uint16_t recv_window;
            memcpy(&recv_window, &resp[28], 2);

            // Atualiza acknum para envio no próximo pacote
            memcpy(&acknum, &last_ack, 4);
        } else {
            // Se não recebeu resposta, reenvia o pacote mais antigo pendente
            if (!inflight.empty()) {
                if (debug)
                    std::cout << "[!] Timeout. Reenviando pacote: seq=" << inflight.front().seq << std::endl;

                sendto(sock, inflight.front().packet.data(),
                       inflight.front().packet.size(), 0,
                       (sockaddr*)&server, sizeof(server));

                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }
    }

    return true;
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

// Envia mensagem de desconexão e espera ACK final para atualizar acknum
void send_disconnect(int sock, sockaddr_in& server, UUID sid, uint32_t sttl, uint32_t& seqnum, uint32_t& acknum) {
    uint8_t flags = CONNECT | REVIVE | ACK;  // Flags típicas para desconectar
    auto pkt = build_packet(sid, flags, sttl, seqnum, acknum, 0, 0, 0, {});
    if (debug) print_packet_info(pkt, "SENT: DISCONNECT");
    sendto(sock, pkt.data(), pkt.size(), 0, (sockaddr*)&server, sizeof(server));

    std::vector<uint8_t> response;
    if (receive_response(sock, response)) {
        if (debug) print_packet_info(response, "RECEIVED: FINAL ACK");
        memcpy(&acknum, &response[24], 4);
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
    std::string mensagem = "Mensagem de teste!";
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
