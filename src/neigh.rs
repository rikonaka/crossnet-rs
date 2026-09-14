use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use crate::error::CrossNetError;
use crate::iface::MacAddr;

#[cfg(target_os = "windows")]
pub mod n_windows;
#[cfg(target_os = "windows")]
use n_windows::get_net_ifs;
#[cfg(target_os = "windows")]
use n_windows::get_net_neighs;

#[cfg(target_os = "linux")]
pub mod n_linux;
#[cfg(target_os = "linux")]
use n_linux::get_net_ifs;
#[cfg(target_os = "linux")]
use n_linux::get_net_neighs;

#[cfg(target_os = "macos")]
pub mod n_macos;
#[cfg(target_os = "macos")]
use n_macos::get_net_neighs;

#[derive(Debug, Clone)]
pub struct NetIf {
    pub ifname: String,
    pub ifindex: u32,
}

impl PartialEq for NetIf {
    fn eq(&self, other: &Self) -> bool {
        self.ifindex == other.ifindex
    }
}

#[derive(Debug, Clone)]
pub struct MacInfo {
    mac: MacAddr,
    /// The interface name associated with the MAC address, if available.
    /// On Linux and MacOS, this is usually interface name, on Windows, this is usually interface index.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    ifindex: Option<u32>,
    #[cfg(target_os = "macos")]
    ifname: Option<String>,
}

impl MacInfo {
    /// On Linux and Windows, we can get the interface name from the interface index.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub fn get_ifname(&self) -> Result<Option<String>, CrossNetError> {
        let net_ifs = get_net_ifs()?;
        if let Some(iface) = &self.ifindex {
            for net_if in &net_ifs {
                if iface == &net_if.ifindex {
                    return Ok(Some(net_if.ifname.clone()));
                }
            }
        }
        Ok(None)
    }
    #[cfg(target_os = "macos")]
    pub fn get_ifname(&self) -> Result<Option<String>, CrossNetError> {
        Ok(self.ifname.clone())
    }
}

#[derive(Clone)]
pub struct NeighborCache(HashMap<IpAddr, MacInfo>);

impl fmt::Display for NeighborCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (ip, mac_info) in &self.0 {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            let iface_str = match &mac_info.ifindex {
                Some(iface) => iface.to_string(),
                None => "N/A".to_string(),
            };
            #[cfg(target_os = "macos")]
            let iface_str = match &mac_info.ifname {
                Some(iface) => iface.clone(),
                None => "N/A".to_string(),
            };
            write!(f, "{}:{}({})", ip, mac_info.mac.to_string(), iface_str)?;
        }
        Ok(())
    }
}

impl fmt::Debug for NeighborCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl NeighborCache {
    /// Search for the MAC address of the given IP address in the system neighbor cache.
    pub fn search_mac(&self, ip: &IpAddr) -> Option<MacAddr> {
        self.0.get(ip).map(|mac_info| mac_info.mac)
    }
    /// Search for the interface name of the given IP address in the system neighbor cache.
    pub fn search_ifname(&self, ip: &IpAddr) -> Result<Option<String>, CrossNetError> {
        if let Some(mac_info) = self.0.get(ip) {
            mac_info.get_ifname()
        } else {
            Ok(None)
        }
    }
}

pub fn get_neighbor_cache() -> Result<NeighborCache, CrossNetError> {
    let net_neighs = get_net_neighs()?;
    let mut rets = HashMap::new();

    for n in net_neighs {
        let mac_info = MacInfo {
            mac: n.mac,
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            ifindex: Some(n.ifindex),
            #[cfg(target_os = "macos")]
            ifname: n.ifname,
        };
        rets.insert(n.ip, mac_info);
    }

    let neighbor_cache = NeighborCache(rets);
    Ok(neighbor_cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn test_get_neighbor_cache() {
        let neighbor_cache = get_neighbor_cache().unwrap();
        for (ip, mac_info) in &neighbor_cache.0 {
            let ind = match &mac_info.ifindex {
                Some(iface) => iface.to_string(),
                None => "N/A".to_string(),
            };
            let name = match mac_info.get_ifname() {
                Ok(i) => match i {
                    Some(n) => n,
                    None => "N/A".to_string(),
                },
                Err(e) => e.to_string(),
            };
            println!(
                "ip: {}, mac: {}, ind: {}, name: {}",
                ip,
                mac_info.mac.to_string(),
                ind,
                name
            );
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn test_get_neighbor_cache() {
        let neighbor_cache = get_neighbor_cache().unwrap();
        for (ip, mac_info) in &neighbor_cache.0 {
            let name = match &mac_info.ifname {
                Some(iface) => iface.clone(),
                None => "none".to_string(),
            };
            println!(
                "ip: {}, mac: {}, name: {}",
                ip,
                mac_info.mac.to_string(),
                name
            );
        }
    }
}
