#![forbid(unsafe_code)]

//! Autonomous Global Anycast BGP Peering & EVPN-VXLAN Edge Transit Fabric Engine.
//!
//! Provides BGP-4 & MP-BGP protocol message framing, EVPN route types (1-5),
//! Route Distinguishers, Route Targets, VXLAN 24-bit VNI encapsulation over UDP 4789,
//! BGP Finite State Machine (Idle..Established), VRF multi-tenant routing, and
//! autonomous health-driven anycast traffic engineering.

pub mod evpn;
pub mod message;
pub mod orchestrator;
pub mod peer;
pub mod rib;
pub mod vxlan;

pub use message::{
    AsPathSegment, AsPathSegmentType, BgpMessage, BgpOrigin, BgpPathAttributes, BgpPrefix,
    ATTR_AGGREGATOR, ATTR_AS_PATH, ATTR_COMMUNITIES, ATTR_EXTENDED_COMMUNITIES, ATTR_LOCAL_PREF,
    ATTR_MP_REACH_NLRI, ATTR_MP_UNREACH_NLRI, ATTR_MULTI_EXIT_DISC, ATTR_NEXT_HOP, ATTR_ORIGIN,
    BGP_HEADER_LEN, BGP_HEADER_MARKER, BGP_MSG_KEEPALIVE, BGP_MSG_NOTIFICATION, BGP_MSG_OPEN,
    BGP_MSG_ROUTE_REFRESH, BGP_MSG_UPDATE, BGP_TCP_PORT, COMMUNITY_BLACKHOLE,
    COMMUNITY_NO_ADVERTISE, COMMUNITY_NO_EXPORT, ORIGIN_EGP, ORIGIN_IGP, ORIGIN_INCOMPLETE,
};

pub use evpn::{
    EthernetSegmentId, EvpnRoute, MacAddress, RouteDistinguisher, RouteTarget, AFI_L2VPN,
    EVPN_TYPE_ETHERNET_AD, EVPN_TYPE_ETHERNET_SEGMENT, EVPN_TYPE_INCLUSIVE_MULTICAST,
    EVPN_TYPE_IP_PREFIX, EVPN_TYPE_MAC_IP_ADV, SAFI_EVPN,
};

pub use vxlan::{
    FdbEntry, VtepEngine, VxlanDatagram, VxlanHeader, VXLAN_FLAGS_VALID_VNI, VXLAN_UDP_PORT,
};

pub use peer::{BgpEvent, BgpFsmState, BgpPeer};

pub use rib::{BgpRibEntry, BgpRibManager, VrfTable};

pub use orchestrator::{AnycastAction, AnycastOrchestrator, AnycastVip, PopHealthStatus};
