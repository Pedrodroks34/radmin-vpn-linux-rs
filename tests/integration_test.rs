use radmin_vpn::crypto::FamatechCipherState;
use radmin_vpn::protocol::framing::FrameParser;
use radmin_vpn::protocol::tlv::{TlvMessage, TlvTag};
use radmin_vpn::transport::{ChannelConfig, TcpChannel, TcpChannelListener};

#[tokio::test]
async fn test_e2e_ethernet_pipeline() {
    // 1. Configurar chave de sessão compartilhada (negociada via RSA)
    let session_key = [0x5A; 32];

    // 2. Criar canal TCP de loopback (simulando conexão cliente-servidor / peer-to-peer)
    let listener = TcpChannelListener::bind("127.0.0.1:0", ChannelConfig::default())
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let mut client_ch = TcpChannel::connect(&addr.to_string(), ChannelConfig::default())
        .await
        .expect("connect client");
    let mut server_ch = listener.accept().await.expect("accept server");

    // 3. Ativar criptografia proprietária Famatech em ambos os canais
    client_ch.enable_encryption(session_key);
    server_ch.enable_encryption(session_key);

    // 4. Quadro Ethernet ARP legítimo (64 bytes)
    let arp_ethernet_frame: Vec<u8> = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dest: Broadcast
        0x00, 0x15, 0x5d, 0x12, 0x34, 0x56, // Src: Virtual MAC
        0x08, 0x06, // EtherType: ARP
        0x00, 0x01, // Hardware type: Ethernet
        0x08, 0x00, // Protocol type: IPv4
        0x06, // Hardware size: 6
        0x04, // Protocol size: 4
        0x00, 0x01, // Opcode: Request (1)
        0x00, 0x15, 0x5d, 0x12, 0x34, 0x56, // Sender MAC
        0x1a, 0x1b, 0x1c, 0x1d, // Sender IP (26.27.28.29)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
        0x1a, 0x1b, 0x1c, 0xfe, // Target IP (26.27.28.254)
        0x00, 0x00, 0x00, 0x00, // Padding até 64 bytes
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // 5. Cliente envia quadro através do canal seguro
    client_ch
        .send_secure(&arp_ethernet_frame)
        .await
        .expect("envio seguro de quadro Ethernet");

    // 6. Servidor recebe e valida descriptografia + integridade
    let received_frame = server_ch.receive_secure().await.expect("recepção segura");

    assert_eq!(
        received_frame, arp_ethernet_frame,
        "Quadro recebido deve ser idêntico ao quadro Ethernet transmitido"
    );

    // 7. Envio reverso: servidor envia pacote IP
    let ip_packet = vec![
        0x00, 0x15, 0x5d, 0x12, 0x34, 0x56, 0x00, 0x15, 0x5d, 0x99, 0x88, 0x77, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x1a, 0x1b, 0x1c, 0xfe,
        0x1a, 0x1b, 0x1c, 0x1d,
    ];

    server_ch
        .send_secure(&ip_packet)
        .await
        .expect("servidor envia pacote");

    let client_received = client_ch
        .receive_secure()
        .await
        .expect("cliente recebe pacote");

    assert_eq!(client_received, ip_packet);
}

#[tokio::test]
async fn test_e2e_crypto_tampering_resilience() {
    let key = [0x78; 32];
    let mut enc = FamatechCipherState::new(key);
    let mut dec = FamatechCipherState::new(key);

    let original_payload = b"Payload seguro de teste contra adulteracao".to_vec();
    let mut ciphertext = enc.encrypt(&original_payload).expect("cifrar");

    // Adulterar um byte intermediário do ciphertext
    ciphertext[10] ^= 0x01;

    // Decifragem deve falhar na checagem de padding ou trailer sem panicar
    let res = dec.decrypt(&ciphertext);
    assert!(
        res.is_err(),
        "Ciphertext adulterado deve ser rejeitado na verificação de integridade"
    );
}

#[tokio::test]
async fn test_e2e_real_captured_packet_686_validation() {
    let pcap_hex = "0000012000000004010001df00000001000000040100032b0000000200000100090001ca705f461c05ec79e7a71b736ceacefb245c31906b29a6d686397b5efc8eaba571884ad7615dbf80ccefd5bdc26a33c22c2f77930a555dec9fd8398550f258edbb876e3832bae01d6db3e88095a91662c95b9e0c282e603682471a46a0c68c37f9204364b580468995edaea45d77bc591f3fd288b74162fd5d282bcf87dafbce10865f8afa57ef60abfd407d2c300435fb576960afc30b86fb4688e20dbc9f4f8bd30b130f9957ddd52603bdda9983ec8867caee864b055649df6532b7400b76bbf8f93789bbb4c785d07768db835241d990b8b40c2ec91d369faa0997e768183d75252b7a35937b63842631e860dafbb19036d38b67d5da90df92283ecc7add65";
    let raw: Vec<u8> = (0..pcap_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&pcap_hex[i..i + 2], 16).unwrap())
        .collect();

    // Validar framing externo
    let mut parser = FrameParser::new();
    let frames = parser.feed(&raw).expect("parser de frame");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].payload.len(), 288);

    // Validar TLV interno
    let tlv = TlvMessage::parse(&frames[0].payload).expect("parser TLV");
    assert_eq!(tlv.records.len(), 3);
    assert_eq!(tlv.get_u32(TlvTag::TAG_SESSION_TOKEN), Some(1));
    assert_eq!(tlv.get_u32(TlvTag::TAG_PEER_STATUS), Some(2));

    let rsa_pub = tlv
        .get_buffer(TlvTag::TAG_RSA_PUBLIC_KEY)
        .expect("rsa pub key");
    assert_eq!(rsa_pub.len(), 256);

    // Re-serializar e comparar byte a byte com o frame capturado
    let reserialized = tlv.to_bytes();
    assert_eq!(reserialized, frames[0].payload);
}
