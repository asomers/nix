#![allow(missing_debug_implementations, missing_copy_implementations)]

use super::*;

/// Received version of
/// [`ControlMessage::ScmRights`][#enum.ControlMessage.html#variant.ScmRights]
pub struct ScmRights(pub Vec<RawFd>);

impl ControlMessage for ScmRights {
    fn decode(header: &cmsghdr, buf: &[u8]) -> Option<Self> {
        if let (libc::SOL_SOCKET, libc::SCM_RIGHTS) = (header.cmsg_level, header.cmsg_type) {
            let n = buf.len() / mem::size_of::<RawFd>();
            let p = buf.as_ptr() as *const RawFd;
            let mut fds = Vec::with_capacity(n);
            for i in 0..n {
                unsafe {
                    let fdp = p.offset(i as isize);
                    fds.push(ptr::read_unaligned(fdp));
                }
            }
            Some(ScmRights(fds))
        } else {
            None
        }
    }
}

impl ControlMessageEncode for ScmRights {
    fn data(&self) -> *const u8 { self.0.as_ptr() as *const _ }
    fn len(&self) -> usize { mem::size_of_val(&self.0) }
    fn cmsg_level(&self) -> libc::c_int { libc::SOL_SOCKET }
    fn cmsg_type(&self) -> libc::c_int { libc::SCM_RIGHTS }
}

/// Received version of
/// [`ControlMessage::ScmCredentials`][#enum.ControlMessage.html#variant.ScmCredentials]
#[cfg(any(target_os = "android", target_os = "linux"))]
pub struct ScmCredentials(pub libc::ucred);

#[cfg(any(target_os = "android", target_os = "linux"))]
impl ControlMessage for ScmCredentials {
    fn decode(header: &cmsghdr, buf: &[u8]) -> Option<Self> {
        if let (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) = (header.cmsg_level, header.cmsg_type) {
            let cred: libc::ucred = unsafe { ptr::read_unaligned(buf.as_ptr() as *const _) };
            Some(ScmCredentials(cred))
        } else {
            None
        }
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
impl ControlMessageEncode for ScmCredentials {
    fn data(&self) -> *const u8 { &self.0 as *const libc::ucred as *const _ }
    fn len(&self) -> usize { mem::size_of_val(&self.0) }
    fn cmsg_level(&self) -> libc::c_int { libc::SOL_SOCKET }
    fn cmsg_type(&self) -> libc::c_int { libc::SCM_CREDENTIALS }
}

/// A message of type `SCM_TIMESTAMP`, containing the time the
/// packet was received by the kernel.
///
/// See the kernel's explanation in "SO_TIMESTAMP" of
/// [networking/timestamping](https://www.kernel.org/doc/Documentation/networking/timestamping.txt).
///
/// # Examples
///
// Disable this test on FreeBSD i386
// https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=222039
#[cfg_attr(not(all(target_os = "freebsd", target_arch = "x86")), doc = " ```")]
#[cfg_attr(all(target_os = "freebsd", target_arch = "x86"), doc = " ```no_run")]
/// # #[macro_use] extern crate nix;
/// # use nix::sys::socket::*;
/// # use nix::sys::uio::IoVec;
/// # use nix::sys::time::*;
/// # use std::time::*;
/// # fn main() {
/// // Set up
/// let message = "Ohayō!".as_bytes();
/// let in_socket = socket(
///     AddressFamily::Inet,
///     SockType::Datagram,
///     SockFlag::empty(),
///     None).unwrap();
/// setsockopt(in_socket, sockopt::ReceiveTimestamp, &true).unwrap();
/// let localhost = InetAddr::new(IpAddr::new_v4(127, 0, 0, 1), 0);
/// bind(in_socket, &SockAddr::new_inet(localhost)).unwrap();
/// let address = getsockname(in_socket).unwrap();
/// // Get initial time
/// let time0 = SystemTime::now();
/// // Send the message
/// let iov = [IoVec::from_slice(message)];
/// let flags = MsgFlags::empty();
/// let l = sendmsg(in_socket, &iov, &[], flags, Some(&address)).unwrap();
/// assert_eq!(message.len(), l);
/// // Receive the message
/// let mut buffer = vec![0u8; message.len()];
/// let mut cmsgspace = cmsg_space!(TimeVal);
/// let iov = [IoVec::from_mut_slice(&mut buffer)];
/// let r = recvmsg(in_socket, &iov, Some(&mut cmsgspace), flags).unwrap();
/// let rtime = match r.cmsgs().next() {
///     Some(ControlMessageOwned::ScmTimestamp(rtime)) => rtime,
///     Some(_) => panic!("Unexpected control message"),
///     None => panic!("No control message")
/// };
/// // Check the final time
/// let time1 = SystemTime::now();
/// // the packet's received timestamp should lie in-between the two system
/// // times, unless the system clock was adjusted in the meantime.
/// let rduration = Duration::new(rtime.tv_sec() as u64,
///                               rtime.tv_usec() as u32 * 1000);
/// assert!(time0.duration_since(UNIX_EPOCH).unwrap() <= rduration);
/// assert!(rduration <= time1.duration_since(UNIX_EPOCH).unwrap());
/// // Close socket
/// nix::unistd::close(in_socket).unwrap();
/// # }
/// ```
pub struct ScmTimestamp(pub TimeVal);

impl ControlMessage for ScmTimestamp {
    fn decode(header: &cmsghdr, buf: &[u8]) -> Option<Self> {
        if let (libc::SOL_SOCKET, libc::SCM_TIMESTAMP) = (header.cmsg_level, header.cmsg_type) {
            let tv: libc::timeval = unsafe { ptr::read_unaligned(buf.as_ptr() as *const _) };
            Some(ScmTimestamp(TimeVal::from(tv)))
        } else {
            None
        }
    }
}

impl ControlMessageEncode for ScmTimestamp {
    fn data(&self) -> *const u8 { &(self.0).0 as *const libc::timeval as *const _ }
    fn len(&self) -> usize { mem::size_of_val(&self.0) }
    fn cmsg_level(&self) -> libc::c_int { libc::SOL_SOCKET }
    fn cmsg_type(&self) -> libc::c_int { libc::SCM_TIMESTAMP }
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos"
))]
pub struct Ipv4PacketInfo(pub libc::in_pktinfo);

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos"
))]
impl ControlMessage for Ipv4PacketInfo {
    fn decode(header: &cmsghdr, buf: &[u8]) -> Option<Self> {
        if let (libc::IPPROTO_IP, libc::IP_PKTINFO) = (header.cmsg_level, header.cmsg_type) {
            let info = unsafe { ptr::read_unaligned(buf.as_ptr() as *const libc::in_pktinfo) };
            Some(Ipv4PacketInfo(info))
        } else {
            None
        }
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos"
))]
impl ControlMessageEncode for Ipv4PacketInfo {
    fn data(&self) -> *const u8 { &self.0 as *const libc::in_pktinfo as *const _ }
    fn len(&self) -> usize { mem::size_of_val(&self.0) }
    fn cmsg_level(&self) -> libc::c_int { libc::IPPROTO_IP }
    fn cmsg_type(&self) -> libc::c_int { libc::IP_PKTINFO }
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd",
))]
pub struct Ipv6PacketInfo(pub libc::in6_pktinfo);

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd",
))]
impl ControlMessage for Ipv6PacketInfo {
    fn decode(header: &cmsghdr, buf: &[u8]) -> Option<Self> {
        if let (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) = (header.cmsg_level, header.cmsg_type) {
            let info = unsafe { ptr::read_unaligned(buf.as_ptr() as *const libc::in6_pktinfo) };
            Some(Ipv6PacketInfo(info))
        } else {
            None
        }
    }
}

#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd",
))]
impl ControlMessageEncode for Ipv6PacketInfo {
    fn data(&self) -> *const u8 { &self.0 as *const libc::in6_pktinfo as *const _ }
    fn len(&self) -> usize { mem::size_of_val(&self.0) }
    fn cmsg_level(&self) -> libc::c_int { libc::IPPROTO_IPV6 }
    fn cmsg_type(&self) -> libc::c_int { libc::IPV6_PKTINFO }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
))]
pub struct Ipv4RecvIf(pub libc::sockaddr_dl);

#[cfg(any(
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
))]
impl ControlMessage for Ipv4RecvIf {
    fn decode(header: &cmsghdr, buf: &[u8]) -> Option<Self> {
        if let (libc::IPPROTO_IP, libc::IP_RECVIF) = (header.cmsg_level, header.cmsg_type) {
            let dl = ptr::read_unaligned(buf.as_ptr() as *const libc::sockaddr_dl);
            Some(Ipv4RecvIf(dl))
        } else {
            None
        }
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
))]
impl ControlMessageEncode for Ipv4RecvIf {
    fn data(&self) -> *const u8 { &self.0 as *const libc::sockaddr_dl as *const _ }
    fn len(&self) -> usize { mem::size_of_val(&self.0) }
    fn cmsg_level(&self) -> libc::c_int { libc::IPPROTO_IP }
    fn cmsg_type(&self) -> libc::c_int { libc::IP_RECVIF }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
))]
pub struct Ipv4RecvDstAddr(pub libc::in_addr);

#[cfg(any(
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
))]
impl ControlMessage for Ipv4RecvDstAddr {
    fn decode(header: &cmsghdr, buf: &[u8]) -> Option<Self> {
        if let (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) = (header.cmsg_level, header.cmsg_type) {
            let dl = ptr::read_unaligned(buf.as_ptr() as *const libc::in_addr);
            Some(Ipv4RecvDstAddr(dl))
        } else {
            None
        }
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
))]
impl ControlMessageEncode for Ipv4RecvDstAddr {
    fn data(&self) -> *const u8 { &self.0 as *const libc::in_addr as *const _ }
    fn len(&self) -> usize { mem::size_of_val(&self.0) }
    fn cmsg_level(&self) -> libc::c_int { libc::IPPROTO_IP }
    fn cmsg_type(&self) -> libc::c_int { libc::IP_RECVDSTADDR }
}
