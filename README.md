# Protocolo SLOW

Este projeto implementa um cliente para o protocolo SLOW, conforme especificação do trabalho, fornecendo comunicação confiável sobre UDP, com controle de sessão, fragmentação, controle de janela e retransmissão.

## Integrantes
- Jean Michel Furtado M'Peko
- Thiago Prado Dalla Dea

## Funções Implementadas

### 1. `create_socket`
Cria e configura um socket UDP, já associado ao endereço local e preparado para comunicação com o servidor central do protocolo SLOW.

Como funciona:
- Inicializa o socket UDP.
- Preenche a estrutura do endereço do servidor.
- Faz o bind em uma porta efêmera local.

### 2. `build_packet`
Monta um pacote SLOW conforme o formato especificado:
- 16 bytes de UUID de sessão
- 5 bits de flags
- 27 bits de STTL (timeout)
- 4 bytes para SeqNum e 4 bytes para AckNum
- 2 bytes para janela
- 1 byte FID (fragment id) e 1 byte FO (fragment offset)
- Dados (opcional)

Como funciona:
- Organiza os campos no vetor de bytes, cuidando do alinhamento e codificação bit a bit onde necessário.

### 3. `send_3way_connect`
Realiza o handshake de conexão (3-way handshake):
- Envia pacote CONNECT para iniciar sessão.
- Aguarda resposta do servidor com ACCEPT, UUID de sessão e número de sequência inicial.
- Atualiza os parâmetros da sessão para uso posterior.

### 4. `send_data`
Envia dados de forma confiável, com fragmentação e controle de janela:
- Fragmenta o payload em blocos de até 1440 bytes (limite do protocolo).
- Para cada fragmento, monta pacote com flags apropriadas (`ACK` e `MB` se houver mais fragmentos).
- Gerencia janela de envio e confirmações (acknowledgments).
- Retransmite fragmentos em caso de timeout.
- Atualiza os números de sequência e confirmações conforme o servidor responde.

### 5. `send_disconnect`
Finaliza a sessão com o servidor:
- Envia pacote de disconnect (flags CONNECT|REVIVE|ACK).
- Aguarda confirmação do servidor.
- Atualiza sequência local.

### 6. `receive_response`
Recebe pacotes do servidor e armazena dados recebidos em buffer local, respeitando o limite de capacidade do protocolo.

### 7. `print_packet_info`
Imprime o conteúdo detalhado de um pacote (útil para depuração e validação dos campos do protocolo).

### 8. `generate_uuid`
Gera um UUID (identificador único universal) da versão 8 conforme especificado.

Como funciona:
- Define valores fixos para custom_a, custom_b e custom_c
- Define os bits de versão (byte 6, bits 4-7) para o valor 8 (`1000` em binário)
- Define os bits de variante (byte 8, bits 6-7) para `0b10`, de acordo com a RFC 9562
- Garante compatibilidade com o formato UUID padrão usado para identificação de sessões no protocolo

### 9. `nil_uuid`
Retorna um UUID nulo.

## Exemplo de Uso

```cpp
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
```
