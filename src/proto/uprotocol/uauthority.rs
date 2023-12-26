/********************************************************************************
 * Copyright (c) 2023 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

use crate::uprotocol::{Remote, UAuthority};

use crate::uri::validator::ValidationError;

pub enum IpConformance {
    NonConformal,
    IPv4,
    IPv6,
}

const REMOTE_IPV4_BYTES: usize = 4;
const REMOTE_IPV6_BYTES: usize = 16;
const REMOTE_ID_MINIMUM_BYTES: usize = 1;
const REMOTE_ID_MAXIMUM_BYTES: usize = 255;

/// Helper functions to deal with `UAuthority::Remote` structure
impl UAuthority {
    pub fn has_name(&self) -> bool {
        matches!(self.remote, Some(Remote::Name(_)))
    }

    pub fn has_ip(&self) -> bool {
        matches!(self.remote, Some(Remote::Ip(_)))
    }

    pub fn has_id(&self) -> bool {
        matches!(self.remote, Some(Remote::Id(_)))
    }

    pub fn get_name(&self) -> Option<&str> {
        match &self.remote {
            Some(Remote::Name(name)) => Some(name),
            _ => None,
        }
    }

    pub fn get_ip(&self) -> Option<&[u8]> {
        match &self.remote {
            Some(Remote::Ip(ip)) => Some(ip),
            _ => None,
        }
    }

    pub fn get_id(&self) -> Option<&[u8]> {
        match &self.remote {
            Some(Remote::Id(id)) => Some(id),
            _ => None,
        }
    }

    pub fn set_name<T>(&mut self, name: T) -> &mut Self
    where
        T: Into<String>,
    {
        self.remote = Some(Remote::Name(name.into()));
        self
    }

    pub fn set_ip(&mut self, ip: Vec<u8>) -> &mut Self {
        self.remote = Some(Remote::Ip(ip));
        self
    }

    pub fn set_id(&mut self, id: Vec<u8>) -> &mut Self {
        self.remote = Some(Remote::Id(id));
        self
    }

    pub fn remote_ip_conforms(&self) -> Result<IpConformance, ValidationError> {
        if let Some(_remote) = self.remote.as_ref() {
            match &self.remote {
                Some(Remote::Ip(ip)) => Ok(match ip.len() {
                    REMOTE_IPV4_BYTES => IpConformance::IPv4,
                    REMOTE_IPV6_BYTES => IpConformance::IPv6,
                    _ => IpConformance::NonConformal,
                }),
                _ => Err(ValidationError::new("Remote is not IP")),
            }
        } else {
            Err(ValidationError::new("No remote"))
        }
    }

    pub fn remote_id_conforms(&self) -> Result<bool, ValidationError> {
        if let Some(_remote) = self.remote.as_ref() {
            match &self.remote {
                Some(Remote::Id(id)) => Ok(match id.len() {
                    REMOTE_ID_MINIMUM_BYTES..=REMOTE_ID_MAXIMUM_BYTES => true,
                    _ => false,
                }),
                _ => Err(ValidationError::new("Remote is not ID")),
            }
        } else {
            Err(ValidationError::new("No remote"))
        }
    }
}
