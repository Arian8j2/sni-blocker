use anyhow::{bail, Context};
use clap::Parser;
use log::LevelFilter;
use pcap::Capture;
use simple_logger::SimpleLogger;
use smoltcp::wire::{EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, TcpPacket};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    ffi::CString,
    net::{Ipv4Addr, SocketAddrV4},
};
use tls_parser::{
    SNIType, TlsExtension, TlsMessage, TlsMessageHandshake, TlsRecordType, TlsVersion,
};

/// Data link type that is commonly used that doesn't have ethernet header
const DLT_RAW: i32 = 12;

const SUPPORTED_TLS_VERSIONS: [TlsVersion; 4] = [
    TlsVersion::Tls10,
    TlsVersion::Tls11,
    TlsVersion::Tls12,
    TlsVersion::Tls13,
];

#[derive(clap::Parser)]
struct Args {
    /// Name of interface to inspect
    #[arg(short, long)]
    interface: Option<String>,
    /// List of sni domains to block
    #[arg(short, long, required = true)]
    sni_domains: Vec<String>,
}

#[derive(Debug)]
struct Handshake {
    payload: Vec<u8>,
    total_len: u16,
}

#[derive(Hash, PartialEq, Eq, Debug)]
struct ConnectionId {
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
}

fn main() -> anyhow::Result<()> {
    let Args {
        interface,
        sni_domains,
    } = Args::parse();

    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .with_context(|| "couldn't setup logger")?;

    let device = if let Some(interface) = interface {
        let devices =
            pcap::Device::list().with_context(|| "couldn't fetch list of network interfaces")?;
        match devices.into_iter().find(|device| device.name == interface) {
            Some(device) => device,
            None => {
                bail!("couldn't find network interface with name '{interface}'")
            }
        }
    } else {
        pcap::Device::lookup()
            .with_context(|| "couldn't lookup default network interface")?
            .ok_or(anyhow::anyhow!("no default interface"))?
    };

    log::info!("capturing '{}'", device.name);
    let mut capture = Capture::from_device(device.clone())?
        .immediate_mode(true)
        .open()
        .with_context(|| "couldn't open for capture")?;
    capture
        .direction(pcap::Direction::Out)
        .with_context(|| "couldn't set pcap cature direction")?;
    capture
        .filter("tcp", true)
        .with_context(|| "couldn't set bpf filter")?;

    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
        .with_context(|| "couldn't create raw socket")?;

    let if_name = CString::new(device.name).unwrap();
    socket.bind_device(Some(if_name.as_bytes()))?;
    socket.set_header_included_v4(true)?;

    let has_eth_header = capture.get_datalink() != pcap::Linktype(DLT_RAW);
    let mut conn_to_handshake: HashMap<ConnectionId, Handshake> = HashMap::with_capacity(2048);
    loop {
        let Ok(packet) = capture.next_packet() else {
            continue;
        };
        handle_packet(
            has_eth_header,
            &mut conn_to_handshake,
            &sni_domains,
            &socket,
            packet.data,
        );
    }
}

fn handle_packet(
    has_eth_header: bool,
    conn_to_handshake: &mut HashMap<ConnectionId, Handshake>,
    sni_blocked_domains: &[String],
    socket: &Socket,
    packet: &[u8],
) -> Option<()> {
    let packet = if has_eth_header {
        let eth_header = EthernetFrame::new_checked(packet).ok()?;
        if eth_header.ethertype() != EthernetProtocol::Ipv4 {
            return None;
        }
        eth_header.payload()
    } else {
        packet
    };

    let ip_header = Ipv4Packet::new_checked(packet).ok()?;
    if ip_header.next_header() != IpProtocol::Tcp {
        return None;
    }

    let tcp_packet = TcpPacket::new_checked(ip_header.payload()).ok()?;
    let handshake_payload = complete_tls_handshake(conn_to_handshake, &ip_header, &tcp_packet)?;
    let sni = parse_sni(&handshake_payload)?;

    if !sni_blocked_domains
        .iter()
        .any(|blocked_sni| sni.ends_with(blocked_sni))
    {
        return None;
    }
    log::info!(
        "blocking {}:{} -({sni})-> {}:{}",
        ip_header.src_addr(),
        tcp_packet.src_port(),
        ip_header.dst_addr(),
        tcp_packet.dst_port(),
    );

    let mut buffer = strip_tcp_payload(packet, &tcp_packet);
    // order is important
    send_rst_to_server(socket, &mut buffer, &tcp_packet);
    send_rst_to_client(socket, &mut buffer, &tcp_packet);
    Some(())
}

fn complete_tls_handshake(
    conn_to_handshake: &mut HashMap<ConnectionId, Handshake>,
    ip_header: &Ipv4Packet<&[u8]>,
    tcp_packet: &TcpPacket<&[u8]>,
) -> Option<Vec<u8>> {
    let conn_id = ConnectionId {
        src_addr: ip_header.src_addr(),
        src_port: tcp_packet.src_port(),
        dst_addr: ip_header.dst_addr(),
        dst_port: tcp_packet.dst_port(),
    };
    let tcp_payload = tcp_packet.payload();
    match conn_to_handshake.get_mut(&conn_id) {
        None => {
            let (_, tls_header) = tls_parser::parse_tls_record_header(tcp_payload).ok()?;
            if tls_header.record_type != TlsRecordType::Handshake
                || !SUPPORTED_TLS_VERSIONS.contains(&tls_header.version)
                || tls_header.len > tls_parser::MAX_RECORD_LEN
            {
                return None;
            }
            // tls handshake is in multiple segments
            if tls_header.len > tcp_payload.len() as u16 {
                let mut payload_buffer = Vec::with_capacity(tls_header.len as usize);
                payload_buffer.extend(tcp_payload);
                conn_to_handshake.insert(
                    conn_id,
                    Handshake {
                        payload: payload_buffer,
                        total_len: tls_header.len,
                    },
                );
                return None;
            }
            Some(tcp_payload.to_vec())
        }
        Some(handshake_buffer) => {
            if tcp_packet.rst() || tcp_packet.fin() {
                conn_to_handshake.remove(&conn_id).unwrap();
                return None;
            }
            handshake_buffer.payload.extend(tcp_payload);
            if handshake_buffer.payload.len() < handshake_buffer.total_len as usize {
                // still needs more segments to complete handshake
                return None;
            }
            let buffer = conn_to_handshake.remove(&conn_id).unwrap();
            Some(buffer.payload)
        }
    }
}

fn strip_tcp_payload(packet: &[u8], sni_packet: &TcpPacket<&[u8]>) -> Vec<u8> {
    let new_len = packet.len() - sni_packet.payload().len();
    let mut buffer = packet[..new_len].to_vec();
    let mut new_ip_header = Ipv4Packet::new_unchecked(buffer.as_mut_slice());
    new_ip_header.set_total_len(new_len as u16);
    buffer
}

fn send_rst_to_server(socket: &Socket, buffer: &mut [u8], sni_packet: &TcpPacket<&[u8]>) {
    let mut new_ip_header = Ipv4Packet::new_unchecked(buffer);
    new_ip_header.fill_checksum();
    let src_addr = new_ip_header.src_addr();
    let dst_addr = new_ip_header.dst_addr();

    let mut new_tcp_packet = TcpPacket::new_unchecked(new_ip_header.payload_mut());
    new_tcp_packet.set_seq_number(sni_packet.seq_number() + sni_packet.payload().len());
    new_tcp_packet.set_rst(true);
    new_tcp_packet.set_psh(false); // typical RST ACK doesn't include PSH but it's not that important
    new_tcp_packet.set_ack_number(sni_packet.ack_number());
    new_tcp_packet.fill_checksum(&src_addr.into(), &dst_addr.into());
    let dst_socket_addr = SocketAddrV4::new(dst_addr, new_tcp_packet.dst_port());
    if let Err(error) = socket.send_to(new_ip_header.into_inner(), &dst_socket_addr.into()) {
        log::warn!("couldn't send RST to server: {error:?}");
    }
}

fn send_rst_to_client(socket: &Socket, buffer: &mut [u8], sni_packet: &TcpPacket<&[u8]>) {
    let mut new_ip_header = Ipv4Packet::new_unchecked(buffer);
    let src_addr = new_ip_header.src_addr();
    let dst_addr = new_ip_header.dst_addr();
    new_ip_header.set_src_addr(dst_addr);
    new_ip_header.set_dst_addr(src_addr);
    new_ip_header.fill_checksum();

    let mut new_tcp_packet = TcpPacket::new_unchecked(new_ip_header.payload_mut());
    new_tcp_packet.set_src_port(sni_packet.dst_port());
    new_tcp_packet.set_dst_port(sni_packet.src_port());
    new_tcp_packet.set_seq_number(sni_packet.ack_number());
    new_tcp_packet.set_rst(true);
    new_tcp_packet.set_ack_number(sni_packet.seq_number() + sni_packet.payload().len());
    new_tcp_packet.fill_checksum(&dst_addr.into(), &src_addr.into());
    let dst_socket_addr = SocketAddrV4::new(src_addr, new_tcp_packet.dst_port());
    if let Err(error) = socket.send_to(new_ip_header.into_inner(), &dst_socket_addr.into()) {
        log::warn!("couldn't send RST to client: {error:?}");
    }
}

fn parse_sni(tcp_payload: &[u8]) -> Option<String> {
    let (_, tls) = tls_parser::parse_tls_plaintext(tcp_payload).ok()?;
    for message in tls.msg {
        // all messages must have same type
        let TlsMessage::Handshake(handshake) = message else {
            return None;
        };
        let TlsMessageHandshake::ClientHello(client_hello_content) = handshake else {
            continue;
        };
        let Some(extension) = client_hello_content.ext else {
            continue;
        };
        let (_, extensions) = tls_parser::parse_tls_extensions(extension).ok()?;
        for ext in extensions {
            let TlsExtension::SNI(snis) = ext else {
                continue;
            };
            // we only care about one sni
            let (sni_type, sni) = snis.first()?;
            if *sni_type != SNIType::HostName {
                continue;
            }
            let sni = String::from_utf8(sni.to_vec()).ok()?;
            return Some(sni);
        }
    }
    None
}
