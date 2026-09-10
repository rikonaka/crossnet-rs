use libc::c_int;
use libc::c_void;
use std::fmt;
use std::io;
use std::mem::size_of;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ptr;
use subnetwork::IpPool;
use subnetwork::Ipv4Pool;
use subnetwork::Ipv6Pool;
use subnetwork::NetmaskExt;

use crate::error::CrossNetError;
use crate::iface::MacAddr;
use crate::iface::NetFamily;
use crate::route::NetRoute;
use crate::route::NetRouteAddr;
use crate::route::NetRouteType;

#[derive(Debug, Clone)]
struct RouteEntry {
    destination: Option<IpAddr>,
    src: Option<IpAddr>,
    gateway: Option<GatewayAddr>,
    netmask: Option<IpAddr>,
    ifname: Option<String>,
    is_gateway: bool,
}

/// For MacOS, the gateway address can be an IP address or a MAC address.
#[derive(Clone)]
enum GatewayAddr {
    IpAddr(IpAddr),
    MacAddr(MacAddr),
}

impl fmt::Display for GatewayAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayAddr::IpAddr(ip) => write!(f, "{}", ip),
            GatewayAddr::MacAddr(mac) => write!(f, "{}", mac),
        }
    }
}

impl fmt::Debug for GatewayAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;
// const RTAX_GENMASK: usize = 3;
const RTAX_IFP: usize = 4;
const RTAX_IFA: usize = 5;
// const RTAX_AUTHOR: usize = 6;
// const RTAX_BRD: usize = 7;
const RTAX_MAX: usize = 8;

#[inline]
fn roundup_sa(len: usize) -> usize {
    // macOS / BSD kernel enforces 4‑byte alignment (sizeof(uint32_t))
    if len == 0 {
        4 // When sa_len is zero, occupies 4 bytes
    } else {
        (len + 3) & !3 // Round up to next multiple of 4
    }
}

fn parse_sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    let fam = unsafe { (*sa).sa_family as c_int };
    match fam {
        libc::AF_INET => {
            let sin: *const libc::sockaddr_in = sa as *const libc::sockaddr_in;
            let octets = unsafe { (*sin).sin_addr.s_addr.to_le_bytes() };
            let s = IpAddr::V4(Ipv4Addr::from(octets));
            Some(s)
        }
        libc::AF_INET6 => {
            let sin6: *const libc::sockaddr_in6 = sa as *const libc::sockaddr_in6;
            let octets = unsafe { (*sin6).sin6_addr.s6_addr };
            let s = IpAddr::V6(Ipv6Addr::from(octets));
            Some(s)
        }
        _ => {
            // println!("unknown address family: {}", fam);
            None
        }
    }
}

fn parse_sockaddr_gateway(sa: *const libc::sockaddr) -> Option<GatewayAddr> {
    if sa.is_null() {
        return None;
    }
    let fam = unsafe { (*sa).sa_family as c_int };
    match fam {
        libc::AF_INET => {
            let sin: *const libc::sockaddr_in = sa as *const libc::sockaddr_in;
            let octets = unsafe { (*sin).sin_addr.s_addr.to_le_bytes() };
            let s = IpAddr::V4(Ipv4Addr::from(octets));
            Some(GatewayAddr::IpAddr(s))
        }
        libc::AF_INET6 => {
            let sin6: *const libc::sockaddr_in6 = sa as *const libc::sockaddr_in6;
            let octets = unsafe { (*sin6).sin6_addr.s6_addr };
            let s = IpAddr::V6(Ipv6Addr::from(octets));
            Some(GatewayAddr::IpAddr(s))
        }
        libc::AF_LINK => {
            let lladr = parse_lladdr(sa);
            match lladr {
                Some(l) => match MacAddr::from_str(&l) {
                    Ok(m) => Some(GatewayAddr::MacAddr(m)),
                    Err(e) => {
                        eprintln!("failed to parse mac address: {}", e);
                        None
                    }
                },
                _ => None,
            }
        }
        _ => {
            // println!("unknown address family: {}", fam);
            None
        }
    }
}

fn parse_ifname(sa: *const libc::sockaddr) -> Option<String> {
    if sa.is_null() || unsafe { (*sa).sa_family as c_int } != libc::AF_LINK {
        return None;
    }
    let sdl = sa as *const libc::sockaddr_dl;
    let nlen = unsafe { (*sdl).sdl_nlen as usize };
    if nlen == 0 {
        return None;
    }
    let base = unsafe { (*sdl).sdl_data.as_ptr() as *const i8 };
    let bytes = unsafe { std::slice::from_raw_parts(base as *const u8, nlen) };
    Some(String::from_utf8_lossy(bytes).to_string())
}

fn parse_lladdr(sa: *const libc::sockaddr) -> Option<String> {
    if sa.is_null() || unsafe { (*sa).sa_family as c_int } != libc::AF_LINK {
        return None;
    }
    let sdl = sa as *const libc::sockaddr_dl;
    let nlen = unsafe { (*sdl).sdl_nlen as usize };
    let alen = unsafe { (*sdl).sdl_alen as usize };
    if alen == 0 {
        return None;
    }

    let base = unsafe { (*sdl).sdl_data.as_ptr() as *const u8 };
    let mac_ptr = unsafe { base.add(nlen) };
    let mac = unsafe { std::slice::from_raw_parts(mac_ptr, alen) };

    Some(
        mac.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn list_routes() -> io::Result<Vec<RouteEntry>> {
    // CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_UNSPEC,
        libc::NET_RT_DUMP,
        0,
    ];

    let mut needed: usize = 0;
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            ptr::null_mut(),
            &mut needed,
            ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut buf = vec![0u8; needed];
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            buf.as_mut_ptr() as *mut c_void,
            &mut needed,
            ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    buf.truncate(needed);

    let mut routes = Vec::new();
    let mut off = 0usize;

    while off + size_of::<libc::rt_msghdr>() <= buf.len() {
        let rtm = unsafe { &*(buf.as_ptr().add(off) as *const libc::rt_msghdr) };
        let msglen = rtm.rtm_msglen as usize;
        if msglen == 0 || off + msglen > buf.len() {
            break;
        }

        if rtm.rtm_version != libc::RTM_VERSION as u8 {
            off += msglen;
            continue;
        }

        // RTM_GET/RTM_ADD/RTM_CHANGE
        let mut addrs: [*const libc::sockaddr; RTAX_MAX] = [ptr::null(); RTAX_MAX];
        let mut p =
            unsafe { (buf.as_ptr().add(off) as *const u8).add(size_of::<libc::rt_msghdr>()) };
        let addrs_mask = rtm.rtm_addrs as i32;

        for i in 0..RTAX_MAX {
            if (addrs_mask & (1 << i)) != 0 {
                let sa = p as *const libc::sockaddr;
                addrs[i] = sa;

                let sa_len = unsafe { (*sa).sa_len as usize };
                p = unsafe { p.add(roundup_sa(sa_len)) };
            }
        }

        let destination = parse_sockaddr_ip(addrs[RTAX_DST]);
        let gateway = parse_sockaddr_gateway(addrs[RTAX_GATEWAY]);
        let netmask = parse_sockaddr_ip(addrs[RTAX_NETMASK]);
        let ifname = parse_ifname(addrs[RTAX_IFP]);
        let src = parse_sockaddr_ip(addrs[RTAX_IFA]);

        // println!(
        //     "destination: {:?}, src: {:?}, gateway: {:?}, netmask: {:?}, ifname: {:?}",
        //     destination, src, gateway, netmask, ifname
        // );

        let flags = rtm.rtm_flags as i32;
        let is_gateway = (flags & libc::RTF_GATEWAY) != 0;

        routes.push(RouteEntry {
            destination,
            src,
            gateway,
            netmask,
            ifname,
            is_gateway,
        });

        off += msglen;
    }

    Ok(routes)
}

pub fn get_net_routes() -> Result<Vec<NetRoute>, CrossNetError> {
    let routes = list_routes()?;
    let mut rets = Vec::new();
    for r in routes {
        let prefix = match r.netmask {
            Some(netmask) => {
                let netmask_ext = NetmaskExt::from_addr(netmask);
                let prefix = netmask_ext.get_prefix();
                prefix
            }
            None => 0,
        };
        let (dst, family, ntype) = match r.destination {
            Some(dst) => {
                let n = if dst.is_unspecified() && r.is_gateway {
                    NetRouteType::Default
                } else {
                    NetRouteType::Normal
                };
                match dst {
                    IpAddr::V4(ipv4) => {
                        let a = match prefix {
                            32 | 0 => {
                                // For example
                                // 127 127.0.0.1 UCS lo0
                                // 192.168.5 link#22 UC bridge101 !
                                let octets = ipv4.octets();
                                let zero = octets.iter().filter(|o| **o == 0).count();

                                let prefix = match zero {
                                    1 => 24,
                                    2 => 16,
                                    3 => 8,
                                    _ => 0,
                                };

                                if zero == 4 || prefix == 0 {
                                    Some(NetRouteAddr::IpAddr(dst))
                                } else {
                                    let pool = Ipv4Pool::new(ipv4, prefix)?;
                                    Some(NetRouteAddr::IpPool(IpPool::V4(pool)))
                                }
                            }
                            _ => {
                                let pool = Ipv4Pool::new(ipv4, prefix)?;
                                Some(NetRouteAddr::IpPool(IpPool::V4(pool)))
                            }
                        };
                        (a, NetFamily::Ipv4, n)
                    }
                    IpAddr::V6(ipv6) => {
                        let d = match prefix {
                            128 | 0 => Some(NetRouteAddr::IpAddr(dst)),
                            _ => {
                                let pool = Ipv6Pool::new(ipv6, prefix)?;
                                Some(NetRouteAddr::IpPool(IpPool::V6(pool)))
                            }
                        };
                        (d, NetFamily::Ipv6, n)
                    }
                }
            }
            None => (None, NetFamily::Ipv4, NetRouteType::Normal),
        };
        let gateway = match r.gateway {
            Some(g) => match g {
                GatewayAddr::IpAddr(i) => Some(NetRouteAddr::IpAddr(i)),
                GatewayAddr::MacAddr(m) => Some(NetRouteAddr::MacAddr(m)),
            },
            None => None,
        };
        let src = match r.src {
            Some(s) => Some(NetRouteAddr::IpAddr(s)),
            None => None,
        };
        let route = NetRoute {
            dst,
            src,
            gateway,
            ntype,
            family,
            ifname: r.ifname,
            // For macOS, the metric is not directly available
            // in the rt_msghdr structure. You may need to use
            // other methods to retrieve the metric if needed.
            metric: 0,
        };
        rets.push(route);
    }
    Ok(rets)
}

#[cfg(target_os = "macos")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_bsd() {
        let rets = get_net_routes().unwrap();
        println!("rets len: {:?}", rets.len());
        println!("=============================");
        for ret in rets {
            if let Some(dst) = &ret.dst {
                println!("dst: {}", dst);
            }
            if let Some(src) = &ret.src {
                println!("src: {}", src);
            }
            if let Some(gateway) = &ret.gateway {
                println!("gateway: {}", gateway);
            }
            if let Some(ifname) = &ret.ifname {
                println!("ifname: {}", ifname);
            }
            println!("ntype: {:?}", ret.ntype);
            println!("=================================");
        }
    }
}
