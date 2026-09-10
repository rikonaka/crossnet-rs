use std::fmt;
use std::net::IpAddr;
use subnetwork::IpPool;

use crate::error::CrossNetError;
use crate::iface::{MacAddr, NetFamily};

#[cfg(target_os = "linux")]
pub mod r_linux;
#[cfg(target_os = "linux")]
use r_linux::get_net_routes;

#[cfg(target_os = "windows")]
pub mod r_windows;
#[cfg(target_os = "windows")]
use r_windows::get_net_routes;

#[cfg(target_os = "macos")]
pub mod r_macos;
#[cfg(target_os = "macos")]
use r_macos::get_net_routes;

#[derive(Clone, Hash)]
pub enum NetRouteAddr {
    IpPool(IpPool),
    IpAddr(IpAddr),
    MacAddr(MacAddr),
}

impl PartialEq for NetRouteAddr {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NetRouteAddr::IpPool(p1), NetRouteAddr::IpPool(p2)) => p1 == p2,
            (NetRouteAddr::IpAddr(a1), NetRouteAddr::IpAddr(a2)) => a1 == a2,
            _ => false,
        }
    }
}

impl Eq for NetRouteAddr {}

impl fmt::Display for NetRouteAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetRouteAddr::IpPool(pool) => write!(f, "{}", pool),
            NetRouteAddr::IpAddr(addr) => write!(f, "{}", addr),
            NetRouteAddr::MacAddr(addr) => write!(f, "{}", addr),
        }
    }
}

impl fmt::Debug for NetRouteAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Indicates the type of network route,
/// default route or normal route.
/// Default route is the route that has no destination address,
/// and it is used when there is no other route that matches the destination address of a packet.
/// Normal route is the route that has a specific destination address,
/// and it is used when there is a matching route for the destination address of a packet.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetRouteType {
    Normal,
    Default,
}

#[derive(Clone)]
pub struct NetRoute {
    pub dst: Option<NetRouteAddr>,
    pub src: Option<NetRouteAddr>,
    pub gateway: Option<NetRouteAddr>,
    pub ntype: NetRouteType,
    pub family: NetFamily,
    pub metric: u32,
    #[cfg(target_os = "macos")]
    pub ifname: Option<String>,
}

impl fmt::Display for NetRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = Vec::new();
        if let Some(dst) = &self.dst {
            output.push(format!("dst: {}", dst));
        }
        if let Some(src) = &self.src {
            output.push(format!("src: {}", src));
        }
        if let Some(gateway) = &self.gateway {
            output.push(format!("gateway: {}", gateway));
        }
        #[cfg(target_os = "macos")]
        if let Some(ifname) = &self.ifname {
            output.push(format!("ifname: {}", ifname));
        }
        let output = output.join(", ");
        write!(f, "{}", output)?;
        Ok(())
    }
}

impl fmt::Debug for NetRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl PartialEq for NetRoute {
    fn eq(&self, other: &Self) -> bool {
        self.dst == other.dst
    }
}

impl NetRoute {
    /// Get the prefix length of the destination address if it is an IP pool.
    pub fn dst_prefix(&self) -> Option<u128> {
        match &self.dst {
            Some(NetRouteAddr::IpPool(pool)) => Some(pool.prefix()),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct RouteCache(Vec<NetRoute>);

impl fmt::Display for RouteCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for route in &self.0 {
            write!(f, "{}\n", route)?;
        }
        Ok(())
    }
}

impl fmt::Debug for RouteCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl RouteCache {
    pub fn get_default_route(&self) -> Option<NetRoute> {
        let mut default_route: Option<NetRoute> = None;
        for route in &self.0 {
            if route.ntype == NetRouteType::Default {
                match &mut default_route {
                    Some(dr) => {
                        if route.metric < dr.metric {
                            *dr = route.clone();
                        }
                    }
                    None => default_route = Some(route.clone()),
                }
            }
        }
        default_route
    }
    /// Get the best route for the given destination address from the system route cache.
    pub fn search_route(&self, dst_addr: &IpAddr) -> Option<NetRoute> {
        let mut best_route: Option<NetRoute> = None;
        for route in &self.0 {
            match &route.dst {
                Some(NetRouteAddr::IpPool(pool)) => {
                    if pool.contains(dst_addr) {
                        match &best_route {
                            Some(br) => match br.dst_prefix() {
                                Some(br_prefix) => {
                                    if pool.prefix() > br_prefix {
                                        best_route = Some(route.clone());
                                    }
                                }
                                None => {
                                    best_route = Some(route.clone());
                                }
                            },
                            None => {
                                best_route = Some(route.clone());
                            }
                        }
                    }
                }
                Some(NetRouteAddr::IpAddr(addr)) => {
                    if addr == dst_addr {
                        best_route = Some(route.clone());
                    }
                }
                // The Mac address is not used for target route search.
                Some(NetRouteAddr::MacAddr(_mac)) => (),
                None => {}
            }
        }

        if best_route.is_some() {
            return best_route;
        }

        // no route found for the given destination address
        // now we use the default route if it exists
        for route in &self.0 {
            match dst_addr {
                IpAddr::V4(_) => {
                    if route.ntype == NetRouteType::Default && route.family == NetFamily::Ipv4 {
                        return Some(route.clone());
                    }
                }
                IpAddr::V6(_) => {
                    if route.ntype == NetRouteType::Default && route.family == NetFamily::Ipv6 {
                        return Some(route.clone());
                    }
                }
            }
        }
        None
    }
}

pub fn get_route_cache() -> Result<RouteCache, CrossNetError> {
    let ret = get_net_routes()?;
    let mut rets = Vec::new();
    for route in ret {
        rets.push(route);
    }
    let route_cache = RouteCache(rets);
    Ok(route_cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn test_route() {
        let routes = get_route_cache().unwrap();
        let mut dst_addrs = Vec::new();

        let dst_addr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        dst_addrs.push(dst_addr);
        let dst_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 5, 78));
        dst_addrs.push(dst_addr);

        for dst_addr in dst_addrs {
            let route = routes.search_route(&dst_addr);
            match route {
                Some(r) => println!("{}", r),
                None => {
                    println!("no route found for {}", dst_addr);
                }
            }
        }
    }
}
