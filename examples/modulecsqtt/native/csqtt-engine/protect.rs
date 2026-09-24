// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//
// Protect-hook for CSQTT sockets when the engine runs inside an AntiNet helper.
// The Go helper registers a C callback that is either AntiNet SCM_RIGHTS (Android)
// or off-TUN bind to the physical NIC (desktop). Without it, TURN/DNS sockets
// loop back into the AntiNet TUN.

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io,
    net::SocketAddr,
    sync::OnceLock,
};
use tokio::net::{TcpStream, UdpSocket};

pub type ProtectCb = extern "C" fn(i64) -> i32;

static CALLBACK: OnceLock<ProtectCb> = OnceLock::new();
static HTTP_PROXY: OnceLock<String> = OnceLock::new();

pub fn set_protect(cb: ProtectCb) {
    let _ = CALLBACK.set(cb);
}

pub fn set_http_proxy(url: impl Into<String>) {
    let url = url.into();
    if url.is_empty() {
        return;
    }
    let _ = HTTP_PROXY.set(url);
}

pub fn with_http_proxy(builder: primp::ClientBuilder) -> primp::ClientBuilder {
    let Some(url) = HTTP_PROXY.get() else {
        return builder;
    };
    match primp::Proxy::all(url) {
        Ok(proxy) => builder.proxy(proxy),
        Err(_) => builder,
    }
}

fn call(fd: i64) {
    if let Some(cb) = CALLBACK.get() {
        let _ = cb(fd);
    }
}

pub fn protect_udp(socket: &UdpSocket) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        call(socket.as_raw_fd() as i64);
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        call(socket.as_raw_socket() as i64);
    }
}

fn protect_socket2(socket: &Socket) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        call(socket.as_raw_fd() as i64);
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        call(socket.as_raw_socket() as i64);
    }
}

pub async fn connect_tcp(server: SocketAddr) -> io::Result<TcpStream> {
    let domain = if server.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    protect_socket2(&socket);
    let addr = SockAddr::from(server);
    match socket.connect(&addr) {
        Ok(()) => {}
        Err(error) if would_block(&error) => {}
        Err(error) => return Err(error),
    }
    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    stream.writable().await?;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(stream)
}

fn would_block(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    ) || {
        #[cfg(unix)]
        {
            error.raw_os_error() == Some(libc::EINPROGRESS)
        }
        #[cfg(windows)]
        {
            error.raw_os_error() == Some(10035) /* WSAEWOULDBLOCK */
                || error.raw_os_error() == Some(10036) /* WSAEINPROGRESS */
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }
}
