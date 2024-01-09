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

use byteorder::WriteBytesExt;
use std::io::Cursor;
use std::io::Write;

use crate::uprotocol::{Remote, UAuthority, UEntity, UUri};
use crate::uri::builder::resourcebuilder::UResourceBuilder;
use crate::uri::serializer::{SerializationError, UriSerializer};
use crate::uri::validator::UriValidator;

const LOCAL_MICRO_URI_LENGTH: usize = 8; // local micro URI length
const IPV4_MICRO_URI_LENGTH: usize = 12; // IPv4 micro URI length
const IPV6_MICRO_URI_LENGTH: usize = 24; // IPv6 micro URI length
const UP_VERSION: u8 = 0x1; // UP version

#[derive(Debug, Copy, Clone, PartialEq)]
enum AddressType {
    Local = 0,
    IPv4 = 1,
    IPv6 = 2,
    ID = 3,
}

impl AddressType {
    fn value(self) -> u8 {
        self as u8
    }

    fn from(value: u8) -> Option<AddressType> {
        match value {
            0 => Some(AddressType::Local),
            1 => Some(AddressType::IPv4),
            2 => Some(AddressType::IPv6),
            3 => Some(AddressType::ID),
            _ => None,
        }
    }
}

impl TryFrom<i32> for AddressType {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        if let Ok(v) = u8::try_from(value) {
            AddressType::from(v).ok_or(())
        } else {
            Err(())
        }
    }
}

/// `UriSerializer` that serializes a `UUri` to byte[] (micro format) per
///  <https://github.com/eclipse-uprotocol/uprotocol-spec/blob/main/basics/uri.adoc>
pub struct MicroUriSerializer;

impl UriSerializer<Vec<u8>> for MicroUriSerializer {
    /// Serializes a `UUri` into a `Vec<u8>` following the Micro-URI specifications.
    ///
    /// # Parameters
    /// * `uri`: A reference to the `UUri` data object.
    ///
    /// # Returns
    /// A `Vec<u8>` representing the serialized `UUri`.
    #[allow(clippy::cast_possible_truncation)]
    fn serialize(uri: &UUri) -> Result<Vec<u8>, SerializationError> {
        if UriValidator::is_empty(uri) || !UriValidator::is_micro_form(uri) {
            return Err(SerializationError::new("URI is empty or not in micro form"));
        }

        let mut cursor = Cursor::new(Vec::new());
        let mut address_type = AddressType::Local;
        let mut authority_id: Option<Vec<u8>> = None;
        let mut remote_ip: Option<Vec<u8>> = None;

        // UP_VERSION
        cursor.write_u8(UP_VERSION).unwrap();

        // ADDRESS_TYPE
        if let Some(authority) = &uri.authority {
            if authority.remote.is_none() {
                address_type = AddressType::Local;
            } else if let Some(id) = UAuthority::get_id(authority) {
                authority_id = Some(id.to_vec());
                address_type = AddressType::ID;
            } else if let Some(ip) = UAuthority::get_ip(authority) {
                match ip.len() {
                    4 => address_type = AddressType::IPv4,
                    16 => address_type = AddressType::IPv6,
                    _ => return Err(SerializationError::new("Invalid IP address")),
                }
                remote_ip = Some(ip.to_vec());
            }
        }

        cursor.write_u8(address_type.value()).unwrap();

        // URESOURCE_ID
        uri.resource
            .as_ref()
            .ok_or_else(|| SerializationError::new("UResource must exist to populate micro UURIs"))?
            .id_fits_micro_uri()
            .map_err(|e| {
                SerializationError::new(format!(
                    "UResource id must be populated for micro UURIs: {}",
                    e
                ))
            })?
            .then(|| {
                uri.resource.as_ref().and_then(|resource| {
                    resource.id.map(|id| {
                        cursor.write_all(&[(id >> 8) as u8, id as u8]).unwrap();
                    })
                })
            })
            .ok_or_else(|| SerializationError::new("UResource id larger than allotted 16 bits"))?;

        let entity = uri
            .entity
            .as_ref()
            .ok_or_else(|| SerializationError::new("UEntity must exist to populate micro UURIs"))?;

        // UENTITY_ID
        entity
            .id_fits_micro_uri()
            .map_err(|e| {
                SerializationError::new(format!(
                    "UEntity id must be populated for micro UURIs: {}",
                    e
                ))
            })?
            .then(|| {
                entity.id.map(|id| {
                    cursor.write_all(&[(id >> 8) as u8, id as u8]).unwrap();
                })
            })
            .ok_or_else(|| SerializationError::new("UEntity id larger than allotted 16 bits"))?;

        // UENTITY_VERSION
        entity
            .version_fits_micro_uri()
            .map_err(|e| {
                SerializationError::new(format!("Major version validation failed: {}", e))
            })?
            .then(|| {
                entity.version_major.map(|version| {
                    cursor.write_u8(version as u8).unwrap();
                })
            })
            .ok_or_else(|| SerializationError::new("Major version does not fit micro URI"))?;

        // UNUSED
        cursor.write_u8(0).unwrap();

        // UAUTHORITY
        if address_type != AddressType::Local {
            if address_type == AddressType::ID && authority_id.is_some() {
                let len = authority_id.as_ref().unwrap().len() as u8;
                cursor.write_u8(len).unwrap();
            }

            if let Some(id) = authority_id {
                cursor.write_all(&id).unwrap();
            } else if let Some(ip) = remote_ip {
                cursor.write_all(&ip).unwrap();
            }
        }

        Ok(cursor.into_inner())
    }

    /// Creates a `UUri` data object from a uProtocol micro URI.
    ///
    /// # Arguments
    ///
    /// * `micro_uri` - A byte vec representing the uProtocol micro URI.
    ///
    /// # Returns
    ///
    /// Returns a `UUri` data object.
    fn deserialize(micro_uri: Vec<u8>) -> Result<UUri, SerializationError> {
        if micro_uri.len() < LOCAL_MICRO_URI_LENGTH {
            return Err(SerializationError::new("URI is empty or not in micro form"));
        }

        // Need to be version 1
        if micro_uri[0] != 0x1 {
            return Err(SerializationError::new("URI is not version 1"));
        }

        // RESOURCE_ID
        let uresource_id = u16::from_be_bytes(micro_uri[2..4].try_into().unwrap());

        let address_type = AddressType::from(micro_uri[1]);
        if address_type.is_none() {
            return Err(SerializationError::new("Invalid address type"));
        }

        match address_type.unwrap() {
            AddressType::Local => {
                if micro_uri.len() != LOCAL_MICRO_URI_LENGTH {
                    return Err(SerializationError::new("Invalid micro URI length"));
                }
            }
            AddressType::IPv4 => {
                if micro_uri.len() != IPV4_MICRO_URI_LENGTH {
                    return Err(SerializationError::new("Invalid micro URI length"));
                }
            }
            AddressType::IPv6 => {
                if micro_uri.len() != IPV6_MICRO_URI_LENGTH {
                    return Err(SerializationError::new("Invalid micro URI length"));
                }
            }
            AddressType::ID => {}
        }

        // UENTITY_ID
        let ue_id = u16::from_be_bytes(micro_uri[4..6].try_into().unwrap());

        // VERSION_ID
        let ue_version = u32::from(micro_uri[6]);

        // Calculate uAuthority
        let mut authority: Option<UAuthority> = None;
        match address_type.unwrap() {
            AddressType::IPv4 => {
                let slice: [u8; 4] = micro_uri[8..12].try_into().expect("Wrong slice length");
                authority = Some(UAuthority {
                    remote: Some(Remote::Ip(slice.to_vec())),
                });
            }
            AddressType::IPv6 => {
                let slice: [u8; 16] = micro_uri[8..24].try_into().expect("Wrong slice length");
                authority = Some(UAuthority {
                    remote: Some(Remote::Ip(slice.to_vec())),
                });
            }
            AddressType::ID => {
                authority = Some(UAuthority {
                    remote: Some(Remote::Id(micro_uri[9..].to_vec())),
                });
            }
            AddressType::Local => {}
        }

        Ok(UUri {
            authority,
            entity: Some(UEntity {
                id: Some(ue_id.into()),
                version_major: Some(ue_version),
                ..Default::default()
            }),
            resource: Some(UResourceBuilder::from_id(u32::from(uresource_id))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::uprotocol::UResource;
    use crate::uri::builder::resourcebuilder::UResourceBuilder;

    #[test]
    fn test_empty() {
        let uri = UUri::default();
        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "URI is empty or not in micro form"
        );
    }

    #[test]
    fn test_serialize_uri() {
        let uri = UUri {
            entity: Some(UEntity {
                id: Some(29999),
                version_major: Some(254),
                ..Default::default()
            }),
            resource: Some(UResource {
                id: Some(19999),
                ..Default::default()
            }),
            ..Default::default()
        };
        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.is_ok());
        let uri2 = MicroUriSerializer::deserialize(uprotocol_uri.unwrap());
        assert!(uri2.is_ok());
        assert_eq!(uri, uri2.unwrap())
    }

    #[test]
    fn test_serialize_remote_uri_without_address() {
        let uri = UUri {
            authority: Some(UAuthority {
                remote: Some(Remote::Name("vcu.vin".to_string())),
            }),
            entity: Some(UEntity {
                id: Some(29999),
                version_major: Some(254),
                ..Default::default()
            }),
            resource: Some(UResource {
                id: Some(19999),
                ..Default::default()
            }),
        };
        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "URI is empty or not in micro form"
        );
    }

    #[test]
    fn test_serialize_uri_missing_ids() {
        let uri = UUri {
            entity: Some(UEntity {
                name: "kaputt".to_string(),
                ..Default::default()
            }),
            resource: Some(UResourceBuilder::for_rpc_response()),
            ..Default::default()
        };
        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "URI is empty or not in micro form"
        );
    }

    #[test]
    fn test_serialize_uri_missing_resource_ids() {
        let uri = UUri {
            entity: Some(UEntity {
                name: "kaputt".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "URI is empty or not in micro form"
        );
    }

    #[test]
    fn test_deserialize_bad_microuri_length() {
        let bad_uri: Vec<u8> = vec![0x1, 0x0, 0x0, 0x0, 0x0];
        let uprotocol_uri = MicroUriSerializer::deserialize(bad_uri);
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "URI is empty or not in micro form"
        );
    }

    #[test]
    fn test_deserialize_bad_microuri_not_version_1() {
        let bad_uri: Vec<u8> = vec![0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        let uprotocol_uri = MicroUriSerializer::deserialize(bad_uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "URI is not version 1"
        );
    }

    #[test]
    fn test_deserialize_bad_microuri_not_valid_address_type() {
        let bad_uri: Vec<u8> = vec![0x1, 0x5, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        let uprotocol_uri = MicroUriSerializer::deserialize(bad_uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "Invalid address type"
        );
    }

    #[test]
    fn test_deserialize_bad_microuri_valid_address_type_invalid_length() {
        let bad_uri: Vec<u8> = vec![0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        let uprotocol_uri = MicroUriSerializer::deserialize(bad_uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "Invalid micro URI length"
        );

        let bad_uri: Vec<u8> = vec![0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        let uprotocol_uri = MicroUriSerializer::deserialize(bad_uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "Invalid micro URI length"
        );

        let bad_uri: Vec<u8> = vec![0x1, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
        let uprotocol_uri = MicroUriSerializer::deserialize(bad_uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "Invalid micro URI length"
        );
    }

    #[test]
    fn test_serialize_good_ipv4_based_authority() {
        let address: Ipv4Addr = "10.0.3.3".parse().unwrap();
        let uri = UUri {
            authority: Some(UAuthority {
                remote: Some(Remote::Ip(address.octets().to_vec())),
            }),
            entity: Some(UEntity {
                id: Some(29999),
                version_major: Some(254),
                ..Default::default()
            }),
            resource: Some(UResourceBuilder::for_rpc_request(None, Some(99))),
        };

        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(!uprotocol_uri.as_ref().unwrap().is_empty());
        let uri2 = MicroUriSerializer::deserialize(uprotocol_uri.unwrap());
        assert!(uri2.as_ref().is_ok());
        assert!(UriValidator::is_micro_form(&uri));
        assert!(UriValidator::is_micro_form(uri2.as_ref().unwrap()));
        assert_eq!(uri.to_string(), uri2.as_ref().unwrap().to_string());
        assert_eq!(uri, uri2.unwrap());
    }

    #[test]
    fn test_serialize_good_ipv6_based_authority() {
        let address: Ipv6Addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap();
        let uri = UUri {
            authority: Some(UAuthority {
                remote: Some(Remote::Ip(address.octets().to_vec())),
            }),
            entity: Some(UEntity {
                id: Some(29999),
                version_major: Some(254),
                ..Default::default()
            }),
            resource: Some(UResource {
                id: Some(19999),
                ..Default::default()
            }),
        };

        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.as_ref().is_ok());
        assert!(!uprotocol_uri.as_ref().unwrap().is_empty());
        let uri2 = MicroUriSerializer::deserialize(uprotocol_uri.unwrap());
        assert!(uri2.as_ref().is_ok());
        assert!(UriValidator::is_micro_form(&uri));
        assert!(UriValidator::is_micro_form(uri2.as_ref().unwrap()));
        assert_eq!(uri.to_string(), uri2.as_ref().unwrap().to_string());
        assert_eq!(uri, uri2.unwrap());
    }

    #[test]
    fn test_serialize_id_based_authority() {
        let size = 13;
        let bytes: Vec<u8> = (0..size).map(|i| i as u8).collect();

        let uri = UUri {
            authority: Some(UAuthority {
                remote: Some(Remote::Id(bytes)),
            }),
            entity: Some(UEntity {
                id: Some(29999),
                version_major: Some(254),
                ..Default::default()
            }),
            resource: Some(UResource {
                id: Some(19999),
                ..Default::default()
            }),
        };

        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.as_ref().is_ok());
        assert!(!uprotocol_uri.as_ref().unwrap().is_empty());
        let uri2 = MicroUriSerializer::deserialize(uprotocol_uri.unwrap());
        assert!(uri2.is_ok());
        assert!(UriValidator::is_micro_form(&uri));
        assert!(UriValidator::is_micro_form(uri2.as_ref().unwrap()));
        assert_eq!(uri.to_string(), uri2.as_ref().unwrap().to_string());
        assert_eq!(uri, uri2.unwrap());
    }

    #[test]
    fn test_serialize_bad_length_ip_based_authority() {
        let bad_bytes: Vec<u8> = vec![127, 1, 23, 123, 12, 6];
        let uri = UUri {
            authority: Some(UAuthority {
                remote: Some(Remote::Ip(bad_bytes)),
            }),
            entity: Some(UEntity {
                id: Some(29999),
                version_major: Some(254),
                ..Default::default()
            }),
            resource: Some(UResourceBuilder::for_rpc_request(None, Some(99))),
        };
        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(uprotocol_uri.unwrap_err().to_string(), "Invalid IP address");
    }

    #[test]
    fn test_serialize_id_size_255_based_authority() {
        let size = 129;
        let bytes: Vec<u8> = (0..size).map(|i| i as u8).collect();

        let uri = UUri {
            authority: Some(UAuthority {
                remote: Some(Remote::Id(bytes)),
            }),
            entity: Some(UEntity {
                id: Some(29999),
                version_major: Some(254),
                ..Default::default()
            }),
            resource: Some(UResource {
                id: Some(19999),
                ..Default::default()
            }),
        };

        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.as_ref().is_ok());
        assert_eq!(uprotocol_uri.as_ref().unwrap().len(), 9 + size);
        let uri2 = MicroUriSerializer::deserialize(uprotocol_uri.unwrap());
        assert!(uri2.is_ok());
        assert!(UriValidator::is_micro_form(&uri));
        assert!(UriValidator::is_micro_form(uri2.as_ref().unwrap()));
        assert_eq!(uri, uri2.unwrap());
    }

    #[test]
    fn test_serialize_uri_overflow_resource_id() {
        let uri = UUri {
            entity: Some(UEntity {
                id: Some(29999),
                version_major: Some(254),
                ..Default::default()
            }),
            resource: Some(UResource {
                id: Some(0x10000),
                ..Default::default()
            }),
            ..Default::default()
        };
        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "URI is empty or not in micro form"
        );
    }

    #[test]
    fn test_serialize_uri_overflow_entity_id() {
        let uri = UUri {
            entity: Some(UEntity {
                id: Some(0x10000),
                version_major: Some(254),
                ..Default::default()
            }),
            resource: Some(UResource {
                id: Some(29999),
                ..Default::default()
            }),
            ..Default::default()
        };
        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "URI is empty or not in micro form"
        );
    }

    #[test]
    fn test_serialize_version_overflow_entity_version() {
        let uri = UUri {
            entity: Some(UEntity {
                id: Some(29999),
                version_major: Some(0x100),
                ..Default::default()
            }),
            resource: Some(UResource {
                id: Some(29999),
                ..Default::default()
            }),
            ..Default::default()
        };
        let uprotocol_uri = MicroUriSerializer::serialize(&uri);
        assert!(uprotocol_uri.is_err());
        assert_eq!(
            uprotocol_uri.unwrap_err().to_string(),
            "URI is empty or not in micro form"
        );
    }
}
