// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::inet::unspecified::Unspecified;
use core::fmt;
use s2n_codec::zerocopy::U16;

const ADDR_LEN: usize = 6;

pub mod types {
    pub const IP_V4: u16 = 0x0800;
    pub const IP_V6: u16 = 0x86DD;
}

define_inet_type!(
    pub struct Address {
        octets: [u8; ADDR_LEN],
    }
);

impl Unspecified for Address {
    fn is_unspecified(&self) -> bool {
        self.octets == [0u8; ADDR_LEN]
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ethernet::Address")
            .field(&format_args!("{}", self))
            .finish()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let v = &self.octets;

        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            v[0], v[1], v[2], v[3], v[4], v[5]
        )
    }
}

define_inet_type!(
    pub struct Header {
        destination: Address,
        source: Address,
        ty: Type,
    }
);

impl Header {
    pub fn ty(&self) -> Type {
        self.ty
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ethernet::Header")
            .field("destination", &self.destination)
            .field("source", &self.source)
            .field("type", &self.ty)
            .finish()
    }
}

define_inet_type!(
    pub struct Type {
        value: U16,
    }
);

impl Type {
    #[inline]
    pub fn is_ipv4(self) -> bool {
        self.value == types::IP_V4
    }

    #[inline]
    pub fn is_ipv6(self) -> bool {
        self.value == types::IP_V6
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_ipv4() {
            write!(f, "ethernet::Type::IPv4")
        } else {
            let value: u16 = self.value.into();
            f.debug_tuple("ethernet::Type")
                .field(&format_args!("{:02x}", value))
                .finish()
        }
    }
}
