//! Socket interface functions
//!
//! [Further reading](http://man7.org/linux/man-pages/man7/socket.7.html)
use {Error, Result};
use errno::Errno;
use libc::{self, c_void, c_int, iovec, socklen_t, size_t,
        CMSG_FIRSTHDR, CMSG_NXTHDR, CMSG_DATA, CMSG_LEN};
use std::{fmt, mem, ptr, slice};
use std::os::unix::io::RawFd;
use std::marker::PhantomData;
use sys::time::TimeVal;
use sys::uio::IoVec;
use sys::socket::cmsg::*;

mod addr;
pub mod sockopt;
pub mod cmsg;

/*
 *
 * ===== Re-exports =====
 *
 */

pub use self::addr::{
    AddressFamily,
    SockAddr,
    InetAddr,
    UnixAddr,
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    LinkAddr,
};
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use ::sys::socket::addr::netlink::NetlinkAddr;

pub use libc::{
    cmsghdr,
    msghdr,
    sa_family_t,
    sockaddr,
    sockaddr_in,
    sockaddr_in6,
    sockaddr_storage,
    sockaddr_un,
};

// Needed by the cmsg_space macro
#[doc(hidden)]
pub use libc::{c_uint, CMSG_SPACE};

/// These constants are used to specify the communication semantics
/// when creating a socket with [`socket()`](fn.socket.html)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum SockType {
    /// Provides sequenced, reliable, two-way, connection-
    /// based byte streams.  An out-of-band data transmission
    /// mechanism may be supported.
    Stream = libc::SOCK_STREAM,
    /// Supports datagrams (connectionless, unreliable
    /// messages of a fixed maximum length).
    Datagram = libc::SOCK_DGRAM,
    /// Provides a sequenced, reliable, two-way connection-
    /// based data transmission path for datagrams of fixed
    /// maximum length; a consumer is required to read an
    /// entire packet with each input system call.
    SeqPacket = libc::SOCK_SEQPACKET,
    /// Provides raw network protocol access.
    Raw = libc::SOCK_RAW,
    /// Provides a reliable datagram layer that does not
    /// guarantee ordering.
    Rdm = libc::SOCK_RDM,
}

/// Constants used in [`socket`](fn.socket.html) and [`socketpair`](fn.socketpair.html)
/// to specify the protocol to use.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SockProtocol {
    /// TCP protocol ([ip(7)](http://man7.org/linux/man-pages/man7/ip.7.html))
    Tcp = libc::IPPROTO_TCP,
    /// UDP protocol ([ip(7)](http://man7.org/linux/man-pages/man7/ip.7.html))
    Udp = libc::IPPROTO_UDP,
    /// Allows applications and other KEXTs to be notified when certain kernel events occur
    /// ([ref](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/NKEConceptual/control/control.html))
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    KextEvent = libc::SYSPROTO_EVENT,
    /// Allows applications to configure and control a KEXT
    /// ([ref](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/NKEConceptual/control/control.html))
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    KextControl = libc::SYSPROTO_CONTROL,
}

libc_bitflags!{
    /// Additional socket options
    pub struct SockFlag: c_int {
        /// Set non-blocking mode on the new socket
        #[cfg(any(target_os = "android",
                  target_os = "dragonfly",
                  target_os = "freebsd",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "openbsd"))]
        SOCK_NONBLOCK;
        /// Set close-on-exec on the new descriptor
        #[cfg(any(target_os = "android",
                  target_os = "dragonfly",
                  target_os = "freebsd",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "openbsd"))]
        SOCK_CLOEXEC;
        /// Return `EPIPE` instead of raising `SIGPIPE`
        #[cfg(target_os = "netbsd")]
        SOCK_NOSIGPIPE;
        /// For domains `AF_INET(6)`, only allow `connect(2)`, `sendto(2)`, or `sendmsg(2)`
        /// to the DNS port (typically 53)
        #[cfg(target_os = "openbsd")]
        SOCK_DNS;
    }
}

libc_bitflags!{
    /// Flags for send/recv and their relatives
    pub struct MsgFlags: c_int {
        /// Sends or requests out-of-band data on sockets that support this notion
        /// (e.g., of type [`Stream`](enum.SockType.html)); the underlying protocol must also
        /// support out-of-band data.
        MSG_OOB;
        /// Peeks at an incoming message. The data is treated as unread and the next
        /// [`recv()`](fn.recv.html)
        /// or similar function shall still return this data.
        MSG_PEEK;
        /// Enables nonblocking operation; if the operation would block,
        /// `EAGAIN` or `EWOULDBLOCK` is returned.  This provides similar
        /// behavior to setting the `O_NONBLOCK` flag
        /// (via the [`fcntl`](../../fcntl/fn.fcntl.html)
        /// `F_SETFL` operation), but differs in that `MSG_DONTWAIT` is a per-
        /// call option, whereas `O_NONBLOCK` is a setting on the open file
        /// description (see [open(2)](http://man7.org/linux/man-pages/man2/open.2.html)),
        /// which will affect all threads in
        /// the calling process and as well as other processes that hold
        /// file descriptors referring to the same open file description.
        MSG_DONTWAIT;
        /// Receive flags: Control Data was discarded (buffer too small)
        MSG_CTRUNC;
        /// For raw ([`Packet`](addr/enum.AddressFamily.html)), Internet datagram
        /// (since Linux 2.4.27/2.6.8),
        /// netlink (since Linux 2.6.22) and UNIX datagram (since Linux 3.4)
        /// sockets: return the real length of the packet or datagram, even
        /// when it was longer than the passed buffer. Not implemented for UNIX
        /// domain ([unix(7)](https://linux.die.net/man/7/unix)) sockets.
        ///
        /// For use with Internet stream sockets, see [tcp(7)](https://linux.die.net/man/7/tcp).
        MSG_TRUNC;
        /// Terminates a record (when this notion is supported, as for
        /// sockets of type [`SeqPacket`](enum.SockType.html)).
        MSG_EOR;
        /// This flag specifies that queued errors should be received from
        /// the socket error queue. (For more details, see
        /// [recvfrom(2)](https://linux.die.net/man/2/recvfrom))
        #[cfg(any(target_os = "android", target_os = "linux"))]
        MSG_ERRQUEUE;
        /// Set the `close-on-exec` flag for the file descriptor received via a UNIX domain
        /// file descriptor using the `SCM_RIGHTS` operation (described in
        /// [unix(7)](https://linux.die.net/man/7/unix)).
        /// This flag is useful for the same reasons as the `O_CLOEXEC` flag of
        /// [open(2)](http://pubs.opengroup.org/onlinepubs/9699919799/functions/open.html).
        ///
        /// Only used in [`recvmsg`](fn.recvmsg.html) function.
        #[cfg(any(target_os = "android",
                  target_os = "dragonfly",
                  target_os = "freebsd",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "openbsd"))]
        MSG_CMSG_CLOEXEC;
    }
}

cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        /// Unix credentials of the sending process.
        ///
        /// This struct is used with the `SO_PEERCRED` ancillary message for UNIX sockets.
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct UnixCredentials(libc::ucred);

        impl UnixCredentials {
            /// Returns the process identifier
            pub fn pid(&self) -> libc::pid_t {
                self.0.pid
            }

            /// Returns the user identifier
            pub fn uid(&self) -> libc::uid_t {
                self.0.uid
            }

            /// Returns the group identifier
            pub fn gid(&self) -> libc::gid_t {
                self.0.gid
            }
        }

        impl PartialEq for UnixCredentials {
            fn eq(&self, other: &Self) -> bool {
                self.0.pid == other.0.pid && self.0.uid == other.0.uid && self.0.gid == other.0.gid
            }
        }
        impl Eq for UnixCredentials {}

        impl From<libc::ucred> for UnixCredentials {
            fn from(cred: libc::ucred) -> Self {
                UnixCredentials(cred)
            }
        }

        impl Into<libc::ucred> for UnixCredentials {
            fn into(self) -> libc::ucred {
                self.0
            }
        }

        impl fmt::Debug for UnixCredentials {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_struct("UnixCredentials")
                    .field("pid", &self.0.pid)
                    .field("uid", &self.0.uid)
                    .field("gid", &self.0.gid)
                    .finish()
            }
        }
    }
}

/// Request for multicast socket operations
///
/// This is a wrapper type around `ip_mreq`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpMembershipRequest(libc::ip_mreq);

impl IpMembershipRequest {
    /// Instantiate a new `IpMembershipRequest`
    ///
    /// If `interface` is `None`, then `Ipv4Addr::any()` will be used for the interface.
    pub fn new(group: Ipv4Addr, interface: Option<Ipv4Addr>) -> Self {
        IpMembershipRequest(libc::ip_mreq {
            imr_multiaddr: group.0,
            imr_interface: interface.unwrap_or_else(Ipv4Addr::any).0,
        })
    }
}

impl PartialEq for IpMembershipRequest {
    fn eq(&self, other: &Self) -> bool {
        self.0.imr_multiaddr.s_addr == other.0.imr_multiaddr.s_addr
            && self.0.imr_interface.s_addr == other.0.imr_interface.s_addr
    }
}
impl Eq for IpMembershipRequest {}

impl fmt::Debug for IpMembershipRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mref = &self.0.imr_multiaddr;
        let maddr = mref.s_addr;
        let iref = &self.0.imr_interface;
        let ifaddr = iref.s_addr;
        f.debug_struct("IpMembershipRequest")
            .field("imr_multiaddr", &maddr)
            .field("imr_interface", &ifaddr)
            .finish()
    }
}

/// Request for ipv6 multicast socket operations
///
/// This is a wrapper type around `ipv6_mreq`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6MembershipRequest(libc::ipv6_mreq);

impl Ipv6MembershipRequest {
    /// Instantiate a new `Ipv6MembershipRequest`
    pub fn new(group: Ipv6Addr) -> Self {
        Ipv6MembershipRequest(libc::ipv6_mreq {
            ipv6mr_multiaddr: group.0,
            ipv6mr_interface: 0,
        })
    }
}

impl PartialEq for Ipv6MembershipRequest {
    fn eq(&self, other: &Self) -> bool {
        self.0.ipv6mr_multiaddr.s6_addr == other.0.ipv6mr_multiaddr.s6_addr &&
            self.0.ipv6mr_interface == other.0.ipv6mr_interface
    }
}
impl Eq for Ipv6MembershipRequest {}

impl fmt::Debug for Ipv6MembershipRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Ipv6MembershipRequest")
            .field("ipv6mr_multiaddr", &self.0.ipv6mr_multiaddr.s6_addr)
            .field("ipv6mr_interface", &self.0.ipv6mr_interface)
            .finish()
    }
}

cfg_if! {
    // Darwin and DragonFly BSD always align struct cmsghdr to 32-bit only.
    if #[cfg(any(target_os = "dragonfly", target_os = "ios", target_os = "macos"))] {
        type align_of_cmsg_data = u32;
    } else {
        type align_of_cmsg_data = size_t;
    }
}

/// A type that can be used to store ancillary data received by
/// [`recvmsg`](fn.recvmsg.html)
pub trait CmsgBuffer {
    fn as_bytes_mut(&mut self) -> &mut [u8];
}

/// Create a buffer large enough for storing some control messages as returned
/// by [`recvmsg`](fn.recvmsg.html).
///
/// # Examples
///
/// ```
/// # #[macro_use] extern crate nix;
/// # use nix::sys::time::TimeVal;
/// # use std::os::unix::io::RawFd;
/// # fn main() {
/// // Create a buffer for a `ControlMessageOwned::ScmTimestamp` message
/// let _ = cmsg_space!(TimeVal);
/// // Create a buffer big enough for a `ControlMessageOwned::ScmRights` message
/// // with two file descriptors
/// let _ = cmsg_space!([RawFd; 2]);
/// // Create a buffer big enough for a `ControlMessageOwned::ScmRights` message
/// // and a `ControlMessageOwned::ScmTimestamp` message
/// let _ = cmsg_space!(RawFd, TimeVal);
/// # }
/// ```
// Unfortunately, CMSG_SPACE isn't a const_fn, or else we could return a
// stack-allocated array.
#[macro_export]
macro_rules! cmsg_space {
    ( $( $x:ty ),* ) => {
        {
            use nix::sys::socket::{c_uint, CMSG_SPACE};
            use std::mem;
            let mut space = 0;
            $(
                // CMSG_SPACE is always safe
                space += unsafe {
                    CMSG_SPACE(mem::size_of::<$x>() as c_uint)
                } as usize;
            )*
            let mut v = Vec::<u8>::with_capacity(space);
            // safe because any bit pattern is a valid u8
            unsafe {v.set_len(space)};
            v
        }
    }
}

/// A structure used to make room in a cmsghdr passed to recvmsg. The
/// size and alignment match that of a cmsghdr followed by a T, but the
/// fields are not accessible, as the actual types will change on a call
/// to recvmsg.
///
/// To make room for multiple messages, nest the type parameter with
/// tuples:
///
/// ```
/// use std::os::unix::io::RawFd;
/// use nix::sys::socket::CmsgSpace;
/// let cmsg: CmsgSpace<([RawFd; 3], CmsgSpace<[RawFd; 2]>)> = CmsgSpace::new();
/// ```
#[repr(C)]
#[allow(missing_debug_implementations)]
pub struct CmsgSpace<T> {
    _hdr: cmsghdr,
    _pad: [align_of_cmsg_data; 0],
    _data: T,
}

impl<T> CmsgSpace<T> {
    /// Create a CmsgSpace<T>. The structure is used only for space, so
    /// the fields are uninitialized.
    #[deprecated( since="0.14.0", note="Use the cmsg_space! macro instead")]
    pub fn new() -> Self {
        // Safe because the fields themselves aren't accessible.
        unsafe { mem::uninitialized() }
    }
}

impl<T> CmsgBuffer for CmsgSpace<T> {
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // Safe because nothing ever attempts to access CmsgSpace's fields
        unsafe {
            slice::from_raw_parts_mut(self as *mut CmsgSpace<T> as *mut u8,
                                      mem::size_of::<Self>())
        }
    }
}

impl CmsgBuffer for Vec<u8> {
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self[..]
    }
}

#[allow(missing_debug_implementations)] // msghdr isn't Debug
pub struct RecvMsg<'a> {
    cmsghdr: Option<&'a cmsghdr>,
    pub address: Option<SockAddr>,
    pub flags: MsgFlags,
    mhdr: msghdr,
}

impl<'a> RecvMsg<'a> {
    /// Iterate over the valid control messages pointed to by this
    /// msghdr.
    pub fn cmsgs(&self) -> CmsgIterator {
        CmsgIterator {
            cmsghdr: self.cmsghdr,
            mhdr: &self.mhdr,
        }
    }
}

#[allow(missing_debug_implementations)] // msghdr isn't Debug
pub struct CmsgIterator<'a> {
    /// Control message buffer to decode from. Must adhere to cmsg alignment.
    cmsghdr: Option<&'a cmsghdr>,
    mhdr: &'a msghdr
}

#[allow(missing_debug_implementations)] // msghdr isn't Debug
pub struct TypedCmsgIterator<'a, T>(CmsgIterator<'a>, PhantomData<T>);

impl<'a> CmsgIterator<'a> {
    pub fn next<T: ControlMessage>(&mut self) -> Option<T> {
        unsafe {
            let hdr = self.cmsghdr?;
            let p = CMSG_DATA(hdr);
            let len = hdr as *const _ as usize + hdr.cmsg_len as usize
                - p as usize;

            let cm = T::decode(hdr, slice::from_raw_parts(p, len));

            self.cmsghdr = {
                let p = CMSG_NXTHDR(self.mhdr as *const _, hdr as *const _);
                p.as_ref()
            };
            cm
        }
    }

    pub fn typed<T: ControlMessage>(self) -> TypedCmsgIterator<'a, T> {
        TypedCmsgIterator(self, PhantomData)
    }
}

impl<'a, T: ControlMessage> Iterator for TypedCmsgIterator<'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.0.next::<T>()
    }
}


/// A type-safe wrapper around a single control message, as used with
/// [`recvmsg`](#fn.recvmsg).
///
/// [Further reading](http://man7.org/linux/man-pages/man3/cmsg.3.html)
//  Nix version 0.13.0 and earlier used ControlMessage for both recvmsg and
//  sendmsg.  However, on some platforms the messages returned by recvmsg may be
//  unaligned.  ControlMessageOwned takes those messages by copy, obviating any
//  alignment issues.
//
//  See https://github.com/nix-rust/nix/issues/999
pub trait ControlMessage: Sized {
    fn decode(header: &cmsghdr, buf: &[u8]) -> Option<Self>;
}

pub trait ControlMessageEncode {
    unsafe fn encode_into(&self, cmsg: *mut cmsghdr) {
        (*cmsg).cmsg_level = self.cmsg_level();
        (*cmsg).cmsg_type = self.cmsg_type();
        (*cmsg).cmsg_len = self.cmsg_len();
        let data = self.data();
        ptr::copy_nonoverlapping(
            data,
            CMSG_DATA(cmsg),
            self.len()
        );
    }

    /// The value of CMSG_SPACE on this message.
    /// Safe because CMSG_SPACE is always safe
    fn space(&self) -> usize {
        unsafe{
            CMSG_SPACE(self.len() as libc::c_uint) as usize
        }
    }

    /// The value of CMSG_LEN on this message.
    /// Safe because CMSG_LEN is always safe
    #[cfg(any(target_os = "android",
              all(target_os = "linux", not(target_env = "musl"))))]
    fn cmsg_len(&self) -> usize {
        unsafe{
            CMSG_LEN(self.len() as libc::c_uint) as usize
        }
    }

    #[cfg(not(any(target_os = "android",
                  all(target_os = "linux", not(target_env = "musl")))))]
    fn cmsg_len(&self) -> libc::c_uint {
        unsafe{
            CMSG_LEN(self.len() as libc::c_uint)
        }
    }

    /// Return a reference to the payload data as a byte pointer
    fn data(&self) -> *const u8;

    /// The size of the payload, excluding its cmsghdr
    fn len(&self) -> usize;

    /// Returns the value to put into the `cmsg_level` field of the header.
    fn cmsg_level(&self) -> libc::c_int;

    /// Returns the value to put into the `cmsg_type` field of the header.
    fn cmsg_type(&self) -> libc::c_int;
}

#[allow(missing_debug_implementations)]
pub enum ControlMessageOwned {
    ScmRights(ScmRights),
    #[cfg(any(target_os = "android", target_os = "linux"))]
    ScmCredentials(ScmCredentials),
    ScmTimestamp(ScmTimestamp),
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos"
    ))]
    Ipv4PacketInfo(Ipv4PacketInfo),
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
    Ipv6PacketInfo(Ipv6PacketInfo),
    #[cfg(any(
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    Ipv4RecvIf(Ipv4RecvIf),
    #[cfg(any(
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    Ipv4RecvDstAddr(Ipv4RecvDstAddr),
    /// Catch-all variant for unimplemented cmsg types.
    #[doc(hidden)]
    Unknown(UnknownCmsg),
}

impl ControlMessage for ControlMessageOwned {
    fn decode(header: &cmsghdr, buf: &[u8]) -> Option<Self> {
        macro_rules! ok {
            ( $t:ident ) => { ok!($t, $t) };
            ( $t:ident, $name:ident ) => {
                if let Some(cmsg) = $t::decode(header, buf) {
                    return Some(ControlMessageOwned::$name(cmsg));
                }
            };
        }

        ok!(ScmRights);

        #[cfg(any(target_os = "android", target_os = "linux"))]
        ok!(ScmCredentials);

        ok!(ScmTimestamp);

        #[cfg(any(
            target_os = "android",
            target_os = "ios",
            target_os = "linux",
            target_os = "macos"
        ))]
        ok!(Ipv4PacketInfo);

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
        ok!(Ipv6PacketInfo);

        #[cfg(any(
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
        ))]
        ok!(Ipv4RecvIf);

        #[cfg(any(
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd",
        ))]
        ok!(Ipv4RecvDstAddr);

        Some(ControlMessageOwned::Unknown(UnknownCmsg(*header, buf.into())))
    }
}

#[allow(missing_debug_implementations)]
pub enum ControlMessageRef<'a> {
    ScmRights(&'a [RawFd]),

    #[cfg(any(target_os = "android", target_os = "linux"))]
    ScmCredentials(&'a libc::ucred)
}

impl<'a> ControlMessageEncode for ControlMessageRef<'a> {
    fn data(&self) -> *const u8 {
        match self {
            &ControlMessageRef::ScmRights(fds) => fds.as_ptr() as *const _,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            &ControlMessageRef::ScmCredentials(ucred) => ucred as *const libc::ucred as *const _
        }
    }

    fn len(&self) -> usize {
        match self {
            &ControlMessageRef::ScmRights(fds) => mem::size_of_val(fds),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            &ControlMessageRef::ScmCredentials(ucred) => mem::size_of_val(ucred)
        }
    }
    fn cmsg_level(&self) -> libc::c_int {
        match self {
            &ControlMessageRef::ScmRights(_) => libc::SOL_SOCKET,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            &ControlMessageRef::ScmCredentials(_) => libc::SOL_SOCKET
        }
    }

    fn cmsg_type(&self) -> libc::c_int {
        match self {
            &ControlMessageRef::ScmRights(_) => libc::SCM_RIGHTS,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            &ControlMessageRef::ScmCredentials(_) => libc::SCM_CREDENTIALS
        }
    }
}


// An opaque structure used to prevent cmsghdr from being a public type
#[doc(hidden)]
#[allow(missing_debug_implementations)]
pub struct UnknownCmsg(pub cmsghdr, pub Vec<u8>);

/// Send data in scatter-gather vectors to a socket, possibly accompanied
/// by ancillary data. Optionally direct the message at the given address,
/// as with sendto.
///
/// Allocates if cmsgs is nonempty.
pub fn sendmsg(fd: RawFd, iov: &[IoVec<&[u8]>], cmsgs: &[ControlMessageRef],
               flags: MsgFlags, addr: Option<&SockAddr>) -> Result<usize>
{
    let capacity = cmsgs.iter().map(|c| c.space()).sum();

    // First size the buffer needed to hold the cmsgs.  It must be zeroed,
    // because subsequent code will not clear the padding bytes.
    let cmsg_buffer = vec![0u8; capacity];

    // Next encode the sending address, if provided
    let (name, namelen) = match addr {
        Some(addr) => {
            let (x, y) = unsafe { addr.as_ffi_pair() };
            (x as *const _, y)
        },
        None => (ptr::null(), 0),
    };

    // The message header must be initialized before the individual cmsgs.
    let cmsg_ptr = if capacity > 0 {
        cmsg_buffer.as_ptr() as *mut c_void
    } else {
        ptr::null_mut()
    };

    let mhdr = {
        // Musl's msghdr has private fields, so this is the only way to
        // initialize it.
        let mut mhdr: msghdr = unsafe{mem::uninitialized()};
        mhdr.msg_name = name as *mut _;
        mhdr.msg_namelen = namelen;
        // transmute iov into a mutable pointer.  sendmsg doesn't really mutate
        // the buffer, but the standard says that it takes a mutable pointer
        mhdr.msg_iov = iov.as_ptr() as *mut _;
        mhdr.msg_iovlen = iov.len() as _;
        mhdr.msg_control = cmsg_ptr;
        mhdr.msg_controllen = capacity as _;
        mhdr.msg_flags = 0;
        mhdr
    };

    // Encode each cmsg.  This must happen after initializing the header because
    // CMSG_NEXT_HDR and friends read the msg_control and msg_controllen fields.
    // CMSG_FIRSTHDR is always safe
    let mut pmhdr: *mut cmsghdr = unsafe{CMSG_FIRSTHDR(&mhdr as *const msghdr)};
    for cmsg in cmsgs {
        assert_ne!(pmhdr, ptr::null_mut());
        // Safe because we know that pmhdr is valid, and we initialized it with
        // sufficient space
        unsafe { cmsg.encode_into(pmhdr) };
        // Safe because mhdr is valid
        pmhdr = unsafe{CMSG_NXTHDR(&mhdr as *const msghdr, pmhdr)};
    }

    let ret = unsafe { libc::sendmsg(fd, &mhdr, flags.bits()) };

    Errno::result(ret).map(|r| r as usize)
}

/// Receive message in scatter-gather vectors from a socket, and
/// optionally receive ancillary data into the provided buffer.
/// If no ancillary data is desired, use () as the type parameter.
///
/// # References
/// [recvmsg(2)](http://pubs.opengroup.org/onlinepubs/9699919799/functions/recvmsg.html)
pub fn recvmsg<'a>(fd: RawFd, iov: &[IoVec<&mut [u8]>],
                   cmsg_buffer: Option<&'a mut CmsgBuffer>,
                   flags: MsgFlags) -> Result<RecvMsg<'a>>
{
    let mut address: sockaddr_storage = unsafe { mem::uninitialized() };
    let (msg_control, msg_controllen) = match cmsg_buffer {
        Some(cmsgspace) => {
            let msg_buf = cmsgspace.as_bytes_mut();
            (msg_buf.as_mut_ptr(), msg_buf.len())
        },
        None => (ptr::null_mut(), 0),
    };
    let mut mhdr = {
        // Musl's msghdr has private fields, so this is the only way to
        // initialize it.
        let mut mhdr: msghdr = unsafe{mem::uninitialized()};
        mhdr.msg_name = &mut address as *mut sockaddr_storage as *mut c_void;
        mhdr.msg_namelen = mem::size_of::<sockaddr_storage>() as socklen_t;
        mhdr.msg_iov = iov.as_ptr() as *mut iovec;
        mhdr.msg_iovlen = iov.len() as _;
        mhdr.msg_control = msg_control as *mut c_void;
        mhdr.msg_controllen = msg_controllen as _;
        mhdr.msg_flags = 0;
        mhdr
    };

    let ret = unsafe { libc::recvmsg(fd, &mut mhdr, flags.bits()) };

    Errno::result(ret).map(|_| {
        let cmsghdr = unsafe {
            if mhdr.msg_controllen > 0 {
                // got control message(s)
                debug_assert!(!mhdr.msg_control.is_null());
                debug_assert!(msg_controllen >= mhdr.msg_controllen as usize);
                CMSG_FIRSTHDR(&mhdr as *const msghdr)
            } else {
                ptr::null()
            }.as_ref()
        };

        let address = unsafe {
            sockaddr_storage_to_addr(&address, mhdr.msg_namelen as usize).ok()
        };
        RecvMsg {
            cmsghdr,
            address,
            flags: MsgFlags::from_bits_truncate(mhdr.msg_flags),
            mhdr,
        }
    })
}


/// Create an endpoint for communication
///
/// The `protocol` specifies a particular protocol to be used with the
/// socket.  Normally only a single protocol exists to support a
/// particular socket type within a given protocol family, in which case
/// protocol can be specified as `None`.  However, it is possible that many
/// protocols may exist, in which case a particular protocol must be
/// specified in this manner.
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html)
pub fn socket<T: Into<Option<SockProtocol>>>(domain: AddressFamily, ty: SockType, flags: SockFlag, protocol: T) -> Result<RawFd> {
    let protocol = match protocol.into() {
        None => 0,
        Some(p) => p as c_int,
    };

    // SockFlags are usually embedded into `ty`, but we don't do that in `nix` because it's a
    // little easier to understand by separating it out. So we have to merge these bitfields
    // here.
    let mut ty = ty as c_int;
    ty |= flags.bits();

    let res = unsafe { libc::socket(domain as c_int, ty, protocol) };

    Errno::result(res)
}

/// Create a pair of connected sockets
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/socketpair.html)
pub fn socketpair<T: Into<Option<SockProtocol>>>(domain: AddressFamily, ty: SockType, protocol: T,
                  flags: SockFlag) -> Result<(RawFd, RawFd)> {
    let protocol = match protocol.into() {
        None => 0,
        Some(p) => p as c_int,
    };

    // SockFlags are usually embedded into `ty`, but we don't do that in `nix` because it's a
    // little easier to understand by separating it out. So we have to merge these bitfields
    // here.
    let mut ty = ty as c_int;
    ty |= flags.bits();

    let mut fds = [-1, -1];

    let res = unsafe { libc::socketpair(domain as c_int, ty, protocol, fds.as_mut_ptr()) };
    Errno::result(res)?;

    Ok((fds[0], fds[1]))
}

/// Listen for connections on a socket
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/listen.html)
pub fn listen(sockfd: RawFd, backlog: usize) -> Result<()> {
    let res = unsafe { libc::listen(sockfd, backlog as c_int) };

    Errno::result(res).map(drop)
}

/// Bind a name to a socket
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html)
pub fn bind(fd: RawFd, addr: &SockAddr) -> Result<()> {
    let res = unsafe {
        let (ptr, len) = addr.as_ffi_pair();
        libc::bind(fd, ptr, len)
    };

    Errno::result(res).map(drop)
}

/// Accept a connection on a socket
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/accept.html)
pub fn accept(sockfd: RawFd) -> Result<RawFd> {
    let res = unsafe { libc::accept(sockfd, ptr::null_mut(), ptr::null_mut()) };

    Errno::result(res)
}

/// Accept a connection on a socket
///
/// [Further reading](http://man7.org/linux/man-pages/man2/accept.2.html)
#[cfg(any(target_os = "android",
          target_os = "freebsd",
          target_os = "linux",
          target_os = "openbsd"))]
pub fn accept4(sockfd: RawFd, flags: SockFlag) -> Result<RawFd> {
    let res = unsafe { libc::accept4(sockfd, ptr::null_mut(), ptr::null_mut(), flags.bits()) };

    Errno::result(res)
}

/// Initiate a connection on a socket
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html)
pub fn connect(fd: RawFd, addr: &SockAddr) -> Result<()> {
    let res = unsafe {
        let (ptr, len) = addr.as_ffi_pair();
        libc::connect(fd, ptr, len)
    };

    Errno::result(res).map(drop)
}

/// Receive data from a connection-oriented socket. Returns the number of
/// bytes read
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/recv.html)
pub fn recv(sockfd: RawFd, buf: &mut [u8], flags: MsgFlags) -> Result<usize> {
    unsafe {
        let ret = libc::recv(
            sockfd,
            buf.as_ptr() as *mut c_void,
            buf.len() as size_t,
            flags.bits());

        Errno::result(ret).map(|r| r as usize)
    }
}

/// Receive data from a connectionless or connection-oriented socket. Returns
/// the number of bytes read and the socket address of the sender.
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/recvfrom.html)
pub fn recvfrom(sockfd: RawFd, buf: &mut [u8]) -> Result<(usize, SockAddr)> {
    unsafe {
        let addr: sockaddr_storage = mem::zeroed();
        let mut len = mem::size_of::<sockaddr_storage>() as socklen_t;

        let ret = Errno::result(libc::recvfrom(
            sockfd,
            buf.as_ptr() as *mut c_void,
            buf.len() as size_t,
            0,
            mem::transmute(&addr),
            &mut len as *mut socklen_t))?;

        sockaddr_storage_to_addr(&addr, len as usize)
            .map(|addr| (ret as usize, addr))
    }
}

/// Send a message to a socket
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/sendto.html)
pub fn sendto(fd: RawFd, buf: &[u8], addr: &SockAddr, flags: MsgFlags) -> Result<usize> {
    let ret = unsafe {
        let (ptr, len) = addr.as_ffi_pair();
        libc::sendto(fd, buf.as_ptr() as *const c_void, buf.len() as size_t, flags.bits(), ptr, len)
    };

    Errno::result(ret).map(|r| r as usize)
}

/// Send data to a connection-oriented socket. Returns the number of bytes read
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/send.html)
pub fn send(fd: RawFd, buf: &[u8], flags: MsgFlags) -> Result<usize> {
    let ret = unsafe {
        libc::send(fd, buf.as_ptr() as *const c_void, buf.len() as size_t, flags.bits())
    };

    Errno::result(ret).map(|r| r as usize)
}

/*
 *
 * ===== Socket Options =====
 *
 */

/// The protocol level at which to get / set socket options. Used as an
/// argument to `getsockopt` and `setsockopt`.
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/setsockopt.html)
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SockLevel {
    Socket = libc::SOL_SOCKET,
    Tcp = libc::IPPROTO_TCP,
    Ip = libc::IPPROTO_IP,
    Ipv6 = libc::IPPROTO_IPV6,
    Udp = libc::IPPROTO_UDP,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    Netlink = libc::SOL_NETLINK,
}

/// Represents a socket option that can be accessed or set. Used as an argument
/// to `getsockopt`
pub trait GetSockOpt : Copy {
    type Val;

    #[doc(hidden)]
    fn get(&self, fd: RawFd) -> Result<Self::Val>;
}

/// Represents a socket option that can be accessed or set. Used as an argument
/// to `setsockopt`
pub trait SetSockOpt : Copy {
    type Val;

    #[doc(hidden)]
    fn set(&self, fd: RawFd, val: &Self::Val) -> Result<()>;
}

/// Get the current value for the requested socket option
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockopt.html)
pub fn getsockopt<O: GetSockOpt>(fd: RawFd, opt: O) -> Result<O::Val> {
    opt.get(fd)
}

/// Sets the value for the requested socket option
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/setsockopt.html)
///
/// # Examples
///
/// ```
/// use nix::sys::socket::setsockopt;
/// use nix::sys::socket::sockopt::KeepAlive;
/// use std::net::TcpListener;
/// use std::os::unix::io::AsRawFd;
///
/// let listener = TcpListener::bind("0.0.0.0:0").unwrap();
/// let fd = listener.as_raw_fd();
/// let res = setsockopt(fd, KeepAlive, &true);
/// assert!(res.is_ok());
/// ```
pub fn setsockopt<O: SetSockOpt>(fd: RawFd, opt: O, val: &O::Val) -> Result<()> {
    opt.set(fd, val)
}

/// Get the address of the peer connected to the socket `fd`.
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html)
pub fn getpeername(fd: RawFd) -> Result<SockAddr> {
    unsafe {
        let addr: sockaddr_storage = mem::uninitialized();
        let mut len = mem::size_of::<sockaddr_storage>() as socklen_t;

        let ret = libc::getpeername(fd, mem::transmute(&addr), &mut len);

        Errno::result(ret)?;

        sockaddr_storage_to_addr(&addr, len as usize)
    }
}

/// Get the current address to which the socket `fd` is bound.
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockname.html)
pub fn getsockname(fd: RawFd) -> Result<SockAddr> {
    unsafe {
        let addr: sockaddr_storage = mem::uninitialized();
        let mut len = mem::size_of::<sockaddr_storage>() as socklen_t;

        let ret = libc::getsockname(fd, mem::transmute(&addr), &mut len);

        Errno::result(ret)?;

        sockaddr_storage_to_addr(&addr, len as usize)
    }
}

/// Return the appropriate `SockAddr` type from a `sockaddr_storage` of a certain
/// size.  In C this would usually be done by casting.  The `len` argument
/// should be the number of bytes in the `sockaddr_storage` that are actually
/// allocated and valid.  It must be at least as large as all the useful parts
/// of the structure.  Note that in the case of a `sockaddr_un`, `len` need not
/// include the terminating null.
pub unsafe fn sockaddr_storage_to_addr(
    addr: &sockaddr_storage,
    len: usize) -> Result<SockAddr> {

    if len < mem::size_of_val(&addr.ss_family) {
        return Err(Error::Sys(Errno::ENOTCONN));
    }

    match addr.ss_family as c_int {
        libc::AF_INET => {
            assert!(len as usize == mem::size_of::<sockaddr_in>());
            let ret = *(addr as *const _ as *const sockaddr_in);
            Ok(SockAddr::Inet(InetAddr::V4(ret)))
        }
        libc::AF_INET6 => {
            assert!(len as usize == mem::size_of::<sockaddr_in6>());
            Ok(SockAddr::Inet(InetAddr::V6(*(addr as *const _ as *const sockaddr_in6))))
        }
        libc::AF_UNIX => {
            let sun = *(addr as *const _ as *const sockaddr_un);
            let pathlen = len - offset_of!(sockaddr_un, sun_path);
            Ok(SockAddr::Unix(UnixAddr(sun, pathlen)))
        }
        #[cfg(any(target_os = "android", target_os = "linux"))]
        libc::AF_NETLINK => {
            use libc::sockaddr_nl;
            Ok(SockAddr::Netlink(NetlinkAddr(*(addr as *const _ as *const sockaddr_nl))))
        }
        af => panic!("unexpected address family {}", af),
    }
}


#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Shutdown {
    /// Further receptions will be disallowed.
    Read,
    /// Further  transmissions will be disallowed.
    Write,
    /// Further receptions and transmissions will be disallowed.
    Both,
}

/// Shut down part of a full-duplex connection.
///
/// [Further reading](http://pubs.opengroup.org/onlinepubs/9699919799/functions/shutdown.html)
pub fn shutdown(df: RawFd, how: Shutdown) -> Result<()> {
    unsafe {
        use libc::shutdown;

        let how = match how {
            Shutdown::Read  => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both  => libc::SHUT_RDWR,
        };

        Errno::result(shutdown(df, how)).map(drop)
    }
}
