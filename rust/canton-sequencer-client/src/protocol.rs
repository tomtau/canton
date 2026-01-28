// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canton Protocol Version definitions.
//!
//! Protocol versions define how Canton nodes communicate with each other.
//! This module provides constants for the supported protocol versions that
//! should be used when connecting to a Canton sequencer.
//!
//! # Example
//!
//! ```
//! use canton_sequencer_client::protocol::{ProtocolVersion, LATEST_STABLE_VERSION};
//!
//! // Use the latest stable protocol version
//! let version = LATEST_STABLE_VERSION;
//! assert_eq!(version, ProtocolVersion::V34);
//!
//! // Get the version as an integer for the challenge request
//! let version_int: i32 = version.into();
//! assert_eq!(version_int, 34);
//! ```

/// The latest stable protocol version.
/// This should be used as the default when connecting to a sequencer.
pub const LATEST_STABLE_VERSION: ProtocolVersion = ProtocolVersion::V34;

/// The minimum supported protocol version.
pub const MINIMUM_STABLE_VERSION: ProtocolVersion = ProtocolVersion::V34;

/// Canton Protocol Version.
///
/// Protocol versions define how Canton nodes communicate. Each version represents
/// a snapshot of the Canton protocols at a point in time.
///
/// When connecting to a sequencer, you should typically use [`LATEST_STABLE_VERSION`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum ProtocolVersion {
    /// Protocol version 34 (latest stable)
    V34 = 34,
    /// Protocol version 35 (alpha)
    V35 = 35,
}

impl ProtocolVersion {
    /// Get all stable protocol versions.
    pub const fn stable_versions() -> &'static [ProtocolVersion] {
        &[ProtocolVersion::V34]
    }

    /// Get all supported protocol versions (stable + alpha/beta).
    pub const fn supported_versions() -> &'static [ProtocolVersion] {
        &[ProtocolVersion::V34, ProtocolVersion::V35]
    }

    /// Check if this is a stable protocol version.
    pub fn is_stable(self) -> bool {
        matches!(self, ProtocolVersion::V34)
    }

    /// Check if this is an alpha protocol version.
    pub fn is_alpha(self) -> bool {
        matches!(self, ProtocolVersion::V35)
    }

    /// Get the version as an integer.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl From<ProtocolVersion> for i32 {
    fn from(version: ProtocolVersion) -> Self {
        version as i32
    }
}

impl TryFrom<i32> for ProtocolVersion {
    type Error = ProtocolVersionError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            34 => Ok(ProtocolVersion::V34),
            35 => Ok(ProtocolVersion::V35),
            _ => Err(ProtocolVersionError::Unsupported(value)),
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_i32())
    }
}

/// Error when parsing or using protocol versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolVersionError {
    /// The protocol version is not supported.
    Unsupported(i32),
}

impl std::fmt::Display for ProtocolVersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolVersionError::Unsupported(v) => {
                write!(
                    f,
                    "protocol version {} is not supported; supported versions: {:?}",
                    v,
                    ProtocolVersion::supported_versions()
                        .iter()
                        .map(|v| v.as_i32())
                        .collect::<Vec<_>>()
                )
            }
        }
    }
}

impl std::error::Error for ProtocolVersionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_values() {
        assert_eq!(ProtocolVersion::V34.as_i32(), 34);
        assert_eq!(ProtocolVersion::V35.as_i32(), 35);
    }

    #[test]
    fn test_latest_stable() {
        assert_eq!(LATEST_STABLE_VERSION, ProtocolVersion::V34);
        assert!(LATEST_STABLE_VERSION.is_stable());
    }

    #[test]
    fn test_try_from() {
        assert_eq!(ProtocolVersion::try_from(34).unwrap(), ProtocolVersion::V34);
        assert_eq!(ProtocolVersion::try_from(35).unwrap(), ProtocolVersion::V35);
        assert!(ProtocolVersion::try_from(99).is_err());
    }

    #[test]
    fn test_into_i32() {
        let v: i32 = ProtocolVersion::V34.into();
        assert_eq!(v, 34);
    }

    #[test]
    fn test_stable_versions() {
        let stable = ProtocolVersion::stable_versions();
        assert_eq!(stable, &[ProtocolVersion::V34]);
    }

    #[test]
    fn test_is_stable() {
        assert!(ProtocolVersion::V34.is_stable());
        assert!(!ProtocolVersion::V35.is_stable());
    }

    #[test]
    fn test_is_alpha() {
        assert!(!ProtocolVersion::V34.is_alpha());
        assert!(ProtocolVersion::V35.is_alpha());
    }
}
