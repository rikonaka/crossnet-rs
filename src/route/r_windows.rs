use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use subnetwork::IpPool;
use windows::Win32::NetworkManagement::IpHelper::FreeMibTable;
use windows::Win32::NetworkManagement::IpHelper::GetIpForwardTable2;
use windows::Win32::NetworkManagement::IpHelper::MIB_IPFORWARD_TABLE2;
use windows::Win32::Networking::WinSock::ADDRESS_FAMILY;
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::Networking::WinSock::AF_INET6;
use windows::Win32::Networking::WinSock::SOCKADDR_INET;

use crate::error::CrossNetError;
use crate::route::NetFamily;
use crate::route::NetRoute;
use crate::route::NetRouteAddr;
use crate::route::NetRouteType;

pub(crate) fn get_net_routes() -> Result<Vec<NetRoute>, CrossNetError> {
    let mut rets = Vec::new();
    unsafe {
        let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        GetIpForwardTable2(ADDRESS_FAMILY(0), &mut table_ptr).ok()?;

        let table_ref = &*table_ptr;
        let num = table_ref.NumEntries as usize;
        let rows_ptr = table_ref.Table.as_ptr(); // *const MIB_IPFORWARD_ROW2
        let rows = std::slice::from_raw_parts(rows_ptr, num);

        for row in rows {
            let si_family = row.DestinationPrefix.Prefix.si_family;
            let family = if si_family == AF_INET {
                NetFamily::Ipv4
            } else if si_family == AF_INET6 {
                NetFamily::Ipv6
            } else {
                #[cfg(feature = "debug")]
                eprintln!("unknown family: {:?}", si_family);
                continue;
            };

            let prefix_len = row.DestinationPrefix.PrefixLength;
            let prefix = &row.DestinationPrefix.Prefix;
            let next_hop = &row.NextHop;
            let metric = row.Metric;

            if prefix_len == 0 {
                let g = sockaddr_inet_to_ipaddr(next_hop)?;
                let gateway = match g {
                    Some(addr) => Some(NetRouteAddr::IpAddr(addr)),
                    None => None,
                };

                let nr = NetRoute {
                    dst: None,
                    src: None,
                    gateway,
                    ntype: NetRouteType::Default,
                    family,
                    metric,
                };
                rets.push(nr);
            } else {
                let prefix_addr = sockaddr_inet_to_ipaddr(prefix)?;
                let net_hop_addr = sockaddr_inet_to_ipaddr(next_hop)?;

                let dst = match prefix_addr {
                    Some(addr) => match addr {
                        IpAddr::V4(_) => {
                            if prefix_len == 32 {
                                Some(NetRouteAddr::IpAddr(addr))
                            } else {
                                let pool = IpPool::new(addr, prefix_len as u8)?;
                                Some(NetRouteAddr::IpPool(pool))
                            }
                        }
                        IpAddr::V6(_) => {
                            if prefix_len == 128 {
                                Some(NetRouteAddr::IpAddr(addr))
                            } else {
                                let pool = IpPool::new(addr, prefix_len as u8)?;
                                Some(NetRouteAddr::IpPool(pool))
                            }
                        }
                    },
                    None => None,
                };
                let gateway = match net_hop_addr {
                    Some(addr) => Some(NetRouteAddr::IpAddr(addr)),
                    None => None,
                };

                let nr = NetRoute {
                    dst,
                    src: None,
                    gateway,
                    ntype: NetRouteType::Normal,
                    family,
                    metric,
                };
                rets.push(nr);
            }
        }

        FreeMibTable(table_ptr as _);
    }

    Ok(rets)
}

fn sockaddr_inet_to_ipaddr(addr: &SOCKADDR_INET) -> Result<Option<IpAddr>, CrossNetError> {
    unsafe {
        let family = addr.si_family;

        if family == AF_INET {
            let ipv4 = &addr.Ipv4;
            let octets = ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
            Ok(Some(IpAddr::V4(Ipv4Addr::from(octets))))
        } else if family == AF_INET6 {
            let ipv6 = &addr.Ipv6;
            let octets = ipv6.sin6_addr.u.Byte;
            Ok(Some(IpAddr::V6(Ipv6Addr::from(octets))))
        } else {
            Ok(None)
        }
    }
}

#[cfg(target_os = "windows")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_windows() {
        let rets = get_net_routes().unwrap();
        for r in rets {
            println!("{}", r);
        }
    }
}
