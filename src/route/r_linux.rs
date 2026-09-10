use futures::stream::TryStreamExt;
use rtnetlink::new_connection;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::RouteAddress;
use rtnetlink::packet_route::route::RouteAttribute;
use rtnetlink::packet_route::route::RouteMessage;
use rtnetlink::packet_route::route::RouteType;
use std::net::IpAddr;
use subnetwork::IpPool;
use subnetwork::Ipv4Pool;
use subnetwork::Ipv6Pool;
use tokio::runtime::Runtime;

use crate::error::CrossNetError;
use crate::iface::NetFamily;
use crate::route::NetRoute;
use crate::route::NetRouteAddr;
use crate::route::NetRouteType;

async fn get_route_async() -> Result<Vec<NetRoute>, CrossNetError> {
    let (connection, handle, _r) = new_connection()?;
    tokio::spawn(connection);

    let req = RouteMessage::default();
    // ipv4 only
    // req.header.address_family = AddressFamily::Inet;
    let mut routes = handle.route().get(req).execute();
    let mut rets = Vec::new();

    while let Some(msg) = routes.try_next().await? {
        match msg.header.kind {
            RouteType::Unicast | RouteType::Local => (),
            _ => continue,
        }

        let ntype = match msg.header.destination_prefix_length {
            0 => NetRouteType::Default,
            _ => NetRouteType::Normal,
        };

        let family = match msg.header.address_family {
            AddressFamily::Inet => NetFamily::Ipv4,
            AddressFamily::Inet6 => NetFamily::Ipv6,
            _ => continue,
        };

        let dst_prefix = msg.header.destination_prefix_length;
        let src_prefix = msg.header.source_prefix_length;

        let mut dst_addr = None;
        let mut src_addr = None;
        let mut gateway_addr = None;
        let mut metric = 0;

        // println!("header: {:?}", msg.header);
        // println!("attributes: {:?}", msg.attributes);
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 0, source_prefix_length: 0, tos: 0, table: 254, protocol: Boot, scope: Universe, kind: Unicast, flags: RouteFlags(Onlink) }
        // attributes: [Table(254), Gateway(Inet(192.168.5.2)), Oif(2)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 24, source_prefix_length: 0, tos: 0, table: 254, protocol: Kernel, scope: Link, kind: Unicast, flags: RouteFlags(0x0) }
        // attributes: [Table(254), Destination(Inet(192.168.5.0)), PrefSource(Inet(192.168.5.3)), Oif(2)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 8, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel,scope: Host, kind: Local, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet(127.0.0.0)), PrefSource(Inet(127.0.0.1)), Oif(1)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 32, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel, scope: Host, kind: Local, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet(127.0.0.1)), PrefSource(Inet(127.0.0.1)), Oif(1)]
        // header: RouteHeader { address_family: Inet, destination_prefix_length: 32, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel, scope: Host, kind: Local, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet(192.168.5.3)), PrefSource(Inet(192.168.5.3)), Oif(2)]
        // header: RouteHeader { address_family: Inet6, destination_prefix_length: 64, source_prefix_length: 0, tos: 0, table: 254, protocol: Kernel, scope: Universe, kind: Unicast, flags: RouteFlags(0x0) }
        // attributes: [Table(254), Destination(Inet6(fe80::)), Priority(256), Oif(2), CacheInfo(RouteCacheInfo { clntref: 0, last_use: 0, expires:0, error: 0, used: 0, id: 0, ts: 0, ts_age: 0 }), Preference(Medium)]
        // header: RouteHeader { address_family: Inet6, destination_prefix_length: 128, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel, scope: Universe, kind: Local, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet6(::1)), Priority(0), Oif(1), CacheInfo(RouteCacheInfo { clntref: 0, last_use: 0, expires: 0, error: 0, used: 0, id: 0, ts: 0, ts_age: 0 }), Preference(Medium)]
        // header: RouteHeader { address_family: Inet6, destination_prefix_length: 128, source_prefix_length: 0, tos: 0, table: 255, protocol: Kernel, scope: Universe, kind: Local, flags: RouteFlags(0x0) }
        // attributes: [Table(255), Destination(Inet6(fe80::20c:29ff:fec4:b88c)), Priority(0), Oif(2), CacheInfo(RouteCacheInfo { clntref: 0, last_use: 0, expires: 0, error: 0, used: 0, id: 0, ts: 0, ts_age: 0 }), Preference(Medium)]

        for ra in msg.attributes {
            match ra {
                RouteAttribute::Priority(m) => {
                    metric = m;
                }
                RouteAttribute::Destination(d) => match d {
                    RouteAddress::Inet(ipv4) => {
                        dst_addr = Some(IpAddr::V4(ipv4));
                    }
                    RouteAddress::Inet6(ipv6) => {
                        dst_addr = Some(IpAddr::V6(ipv6));
                    }
                    _ => (),
                },
                RouteAttribute::Gateway(g) => match g {
                    RouteAddress::Inet(ipv4) => {
                        gateway_addr = Some(IpAddr::V4(ipv4));
                    }
                    RouteAddress::Inet6(ipv6) => {
                        gateway_addr = Some(IpAddr::V6(ipv6));
                    }
                    _ => (),
                },
                RouteAttribute::PrefSource(s) => match s {
                    RouteAddress::Inet(ipv4) => {
                        src_addr = Some(IpAddr::V4(ipv4));
                    }
                    RouteAddress::Inet6(ipv6) => {
                        src_addr = Some(IpAddr::V6(ipv6));
                    }
                    _ => (),
                },
                _ => {}
            }
        }

        let convert_addr =
            |addr: Option<IpAddr>, prefix: u8| -> Result<Option<NetRouteAddr>, CrossNetError> {
                if let Some(a) = addr {
                    if prefix != 0 {
                        let pool = match a {
                            IpAddr::V4(ipv4) => {
                                let pool = Ipv4Pool::new(ipv4, prefix)?;
                                IpPool::V4(pool)
                            }
                            IpAddr::V6(ipv6) => {
                                let pool = Ipv6Pool::new(ipv6, prefix)?;
                                IpPool::V6(pool)
                            }
                        };
                        Ok(Some(NetRouteAddr::IpPool(pool)))
                    } else {
                        Ok(Some(NetRouteAddr::IpAddr(a)))
                    }
                } else {
                    Ok(None)
                }
            };

        let dst = convert_addr(dst_addr, dst_prefix)?;
        let src = convert_addr(src_addr, src_prefix)?;
        let gateway = convert_addr(gateway_addr, 0)?;

        let nr = NetRoute {
            dst,
            src,
            gateway,
            ntype,
            family,
            metric,
        };
        if !rets.contains(&nr) {
            rets.push(nr);
        }
    }

    Ok(rets)
}

pub(crate) fn get_net_routes() -> Result<Vec<NetRoute>, CrossNetError> {
    let rt = Runtime::new()?;
    rt.block_on(async { get_route_async().await })
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_linux() {
        let rets = get_net_routes().unwrap();
        println!("len: {:?}", rets.len());
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
            println!("ntype: {:?}", ret.ntype);
            println!("=================================");
        }
    }
}
