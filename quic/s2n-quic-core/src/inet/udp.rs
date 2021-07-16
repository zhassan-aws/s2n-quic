// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use core::fmt;
use s2n_codec::zerocopy::U16;

define_inet_type!(
    pub struct Header {
        source: U16,
        destination: U16,
        len: U16,
        checksum: U16,
    }
);

impl Header {
    #[inline]
    pub fn source(&self) -> u16 {
        self.source.into()
    }

    #[inline]
    pub fn destination(&self) -> u16 {
        self.destination.into()
    }

    #[inline]
    pub fn len(&self) -> u16 {
        self.len.into()
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        self.checksum.into()
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("udp::Header")
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("len", &self.len)
            .field("checksum", &self.checksum)
            .finish()
    }
}
