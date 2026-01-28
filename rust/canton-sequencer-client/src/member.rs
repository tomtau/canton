// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canton Member ID types and generation.
//!
//! This module provides types for representing Canton member identifiers (participants,
//! mediators, sequencers) and utilities to generate them from signing keys.
//!
//! # Member ID Format
//!
//! A Member ID follows the format: `<CODE>::<identifier>::<namespace_fingerprint>`
//!
//! Where:
//! - `CODE` is a 3-letter type code:
//!   - `PAR` for Participants
//!   - `MED` for Mediators  
//!   - `SEQ` for Sequencers
//! - `identifier` is a human-readable name (max 185 chars)
//! - `namespace_fingerprint` is a SHA-256 fingerprint (64 hex chars)
//!
//! # Example
//!
//! ```
//! use canton_sequencer_client::member::{ParticipantId, UniqueIdentifier, Member};
//! use canton_sequencer_client::signing::Ed25519Signer;
//!
//! // Generate a signing key
//! let signer = Ed25519Signer::generate();
//!
//! // Create a participant ID using the key's fingerprint as namespace
//! let uid = UniqueIdentifier::new("myparticipant", &signer.fingerprint()).unwrap();
//! let participant_id = ParticipantId::new(uid);
//!
//! // Get the string representation for use with sequencer
//! println!("Participant ID: {}", participant_id.to_proto_primitive());
//! // Output: PAR::myparticipant::a1b2c3...
//! ```

use std::fmt;

/// Delimiter used to separate parts of identifiers.
pub const DELIMITER: &str = "::";

/// Maximum length for the identifier part.
pub const MAX_IDENTIFIER_LENGTH: usize = 185;

/// Maximum length for the full Member ID string (CODE + :: + id + :: + fingerprint).
/// This is used by Canton for string length limits (String300).
#[allow(dead_code)]
pub const MAX_MEMBER_LENGTH: usize = 300;

/// Error type for member ID operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberError {
    /// The identifier is empty.
    EmptyIdentifier,
    /// The identifier is too long.
    IdentifierTooLong(usize),
    /// The identifier contains the reserved delimiter.
    IdentifierContainsDelimiter,
    /// The identifier contains invalid characters.
    InvalidIdentifierChars(String),
    /// The fingerprint is invalid.
    InvalidFingerprint(String),
    /// Failed to parse a member string.
    ParseError(String),
}

impl fmt::Display for MemberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemberError::EmptyIdentifier => write!(f, "identifier cannot be empty"),
            MemberError::IdentifierTooLong(len) => {
                write!(f, "identifier too long: {} > {}", len, MAX_IDENTIFIER_LENGTH)
            }
            MemberError::IdentifierContainsDelimiter => {
                write!(f, "identifier cannot contain reserved delimiter '{}'", DELIMITER)
            }
            MemberError::InvalidIdentifierChars(msg) => {
                write!(f, "identifier contains invalid characters: {}", msg)
            }
            MemberError::InvalidFingerprint(msg) => {
                write!(f, "invalid fingerprint: {}", msg)
            }
            MemberError::ParseError(msg) => write!(f, "parse error: {}", msg),
        }
    }
}

impl std::error::Error for MemberError {}

/// A namespace identified by a fingerprint (typically SHA-256 of a public key).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Namespace {
    fingerprint: String,
}

impl Namespace {
    /// Create a namespace from a fingerprint string.
    ///
    /// The fingerprint should be a hex-encoded string (typically 64 characters for SHA-256).
    pub fn new(fingerprint: impl Into<String>) -> Result<Self, MemberError> {
        let fingerprint = fingerprint.into();
        
        // Validate fingerprint is hex
        if fingerprint.is_empty() {
            return Err(MemberError::InvalidFingerprint("fingerprint cannot be empty".to_string()));
        }
        
        if !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(MemberError::InvalidFingerprint(
                "fingerprint must be hex encoded".to_string(),
            ));
        }
        
        Ok(Self { fingerprint })
    }

    /// Get the fingerprint string.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Convert to proto primitive format.
    pub fn to_proto_primitive(&self) -> &str {
        &self.fingerprint
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.fingerprint)
    }
}

/// A unique identifier within a namespace.
///
/// Format: `<identifier>::<namespace_fingerprint>`
///
/// - `identifier`: human-readable name (max 185 chars, valid LF party ID chars)
/// - `namespace_fingerprint`: hex-encoded fingerprint (typically SHA-256)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UniqueIdentifier {
    identifier: String,
    namespace: Namespace,
}

impl UniqueIdentifier {
    /// Create a new UniqueIdentifier.
    ///
    /// # Arguments
    /// * `identifier` - Human-readable identifier (max 185 chars)
    /// * `fingerprint` - Hex-encoded namespace fingerprint
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::member::UniqueIdentifier;
    ///
    /// let uid = UniqueIdentifier::new("mynode", "abc123def456").unwrap();
    /// assert_eq!(uid.to_proto_primitive(), "mynode::abc123def456");
    /// ```
    pub fn new(identifier: impl Into<String>, fingerprint: impl Into<String>) -> Result<Self, MemberError> {
        let identifier = identifier.into();
        
        // Validate identifier
        if identifier.is_empty() {
            return Err(MemberError::EmptyIdentifier);
        }
        
        if identifier.len() > MAX_IDENTIFIER_LENGTH {
            return Err(MemberError::IdentifierTooLong(identifier.len()));
        }
        
        if identifier.contains(DELIMITER) {
            return Err(MemberError::IdentifierContainsDelimiter);
        }
        
        // Basic validation for LF party ID compatible characters
        // Allowed: alphanumeric, dash, underscore, dot
        if !identifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
            return Err(MemberError::InvalidIdentifierChars(
                "only alphanumeric, dash, underscore, and dot allowed".to_string(),
            ));
        }
        
        let namespace = Namespace::new(fingerprint)?;
        
        Ok(Self { identifier, namespace })
    }

    /// Create a UniqueIdentifier from the full string representation.
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::member::UniqueIdentifier;
    ///
    /// let uid = UniqueIdentifier::from_proto_primitive("mynode::abc123").unwrap();
    /// assert_eq!(uid.identifier(), "mynode");
    /// ```
    pub fn from_proto_primitive(s: &str) -> Result<Self, MemberError> {
        let parts: Vec<&str> = s.splitn(2, DELIMITER).collect();
        
        if parts.len() != 2 {
            return Err(MemberError::ParseError(format!(
                "invalid unique identifier '{}': expected format 'identifier::fingerprint'",
                s
            )));
        }
        
        Self::new(parts[0], parts[1])
    }

    /// Get the identifier part.
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Get the namespace.
    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// Convert to proto primitive format.
    pub fn to_proto_primitive(&self) -> String {
        format!("{}{}{}", self.identifier, DELIMITER, self.namespace.fingerprint())
    }
}

impl fmt::Display for UniqueIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_proto_primitive())
    }
}

/// Three-letter member type code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberCode {
    /// Participant (PAR)
    Participant,
    /// Mediator (MED)
    Mediator,
    /// Sequencer (SEQ)
    Sequencer,
}

impl MemberCode {
    /// Get the three-letter code string.
    pub fn as_str(&self) -> &'static str {
        match self {
            MemberCode::Participant => "PAR",
            MemberCode::Mediator => "MED",
            MemberCode::Sequencer => "SEQ",
        }
    }

    /// Parse from a three-letter code.
    pub fn parse(s: &str) -> Result<Self, MemberError> {
        match s {
            "PAR" => Ok(MemberCode::Participant),
            "MED" => Ok(MemberCode::Mediator),
            "SEQ" => Ok(MemberCode::Sequencer),
            _ => Err(MemberError::ParseError(format!("unknown member code: {}", s))),
        }
    }
}

impl std::str::FromStr for MemberCode {
    type Err = MemberError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for MemberCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Trait for member types (Participant, Mediator, Sequencer).
pub trait Member: fmt::Display + Clone {
    /// Get the member type code.
    fn code(&self) -> MemberCode;
    
    /// Get the unique identifier.
    fn uid(&self) -> &UniqueIdentifier;
    
    /// Convert to proto primitive format.
    ///
    /// Format: `CODE::identifier::fingerprint`
    fn to_proto_primitive(&self) -> String {
        format!("{}{}{}", self.code().as_str(), DELIMITER, self.uid().to_proto_primitive())
    }
}

/// A participant identifier.
///
/// Format: `PAR::identifier::fingerprint`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParticipantId {
    uid: UniqueIdentifier,
}

impl ParticipantId {
    /// Create a new ParticipantId.
    pub fn new(uid: UniqueIdentifier) -> Self {
        Self { uid }
    }

    /// Create a ParticipantId from identifier and fingerprint.
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::member::{ParticipantId, Member};
    ///
    /// let pid = ParticipantId::create("myparticipant", "abc123def456").unwrap();
    /// assert!(pid.to_proto_primitive().starts_with("PAR::"));
    /// ```
    pub fn create(identifier: impl Into<String>, fingerprint: impl Into<String>) -> Result<Self, MemberError> {
        Ok(Self::new(UniqueIdentifier::new(identifier, fingerprint)?))
    }

    /// Parse from the full proto primitive string.
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::member::{ParticipantId, Member};
    ///
    /// let pid = ParticipantId::from_proto_primitive("PAR::myparticipant::abc123").unwrap();
    /// assert_eq!(pid.uid().identifier(), "myparticipant");
    /// ```
    pub fn from_proto_primitive(s: &str) -> Result<Self, MemberError> {
        let (code, uid) = parse_member_string(s)?;
        if code != MemberCode::Participant {
            return Err(MemberError::ParseError(format!(
                "expected PAR code, got {}",
                code.as_str()
            )));
        }
        Ok(Self::new(uid))
    }
}

impl Member for ParticipantId {
    fn code(&self) -> MemberCode {
        MemberCode::Participant
    }

    fn uid(&self) -> &UniqueIdentifier {
        &self.uid
    }
}

impl fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_proto_primitive())
    }
}

/// A mediator identifier.
///
/// Format: `MED::identifier::fingerprint`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MediatorId {
    uid: UniqueIdentifier,
}

impl MediatorId {
    /// Create a new MediatorId.
    pub fn new(uid: UniqueIdentifier) -> Self {
        Self { uid }
    }

    /// Create a MediatorId from identifier and fingerprint.
    pub fn create(identifier: impl Into<String>, fingerprint: impl Into<String>) -> Result<Self, MemberError> {
        Ok(Self::new(UniqueIdentifier::new(identifier, fingerprint)?))
    }

    /// Parse from the full proto primitive string.
    pub fn from_proto_primitive(s: &str) -> Result<Self, MemberError> {
        let (code, uid) = parse_member_string(s)?;
        if code != MemberCode::Mediator {
            return Err(MemberError::ParseError(format!(
                "expected MED code, got {}",
                code.as_str()
            )));
        }
        Ok(Self::new(uid))
    }
}

impl Member for MediatorId {
    fn code(&self) -> MemberCode {
        MemberCode::Mediator
    }

    fn uid(&self) -> &UniqueIdentifier {
        &self.uid
    }
}

impl fmt::Display for MediatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_proto_primitive())
    }
}

/// A sequencer identifier.
///
/// Format: `SEQ::identifier::fingerprint`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SequencerId {
    uid: UniqueIdentifier,
}

impl SequencerId {
    /// Create a new SequencerId.
    pub fn new(uid: UniqueIdentifier) -> Self {
        Self { uid }
    }

    /// Create a SequencerId from identifier and fingerprint.
    pub fn create(identifier: impl Into<String>, fingerprint: impl Into<String>) -> Result<Self, MemberError> {
        Ok(Self::new(UniqueIdentifier::new(identifier, fingerprint)?))
    }

    /// Parse from the full proto primitive string.
    pub fn from_proto_primitive(s: &str) -> Result<Self, MemberError> {
        let (code, uid) = parse_member_string(s)?;
        if code != MemberCode::Sequencer {
            return Err(MemberError::ParseError(format!(
                "expected SEQ code, got {}",
                code.as_str()
            )));
        }
        Ok(Self::new(uid))
    }
}

impl Member for SequencerId {
    fn code(&self) -> MemberCode {
        MemberCode::Sequencer
    }

    fn uid(&self) -> &UniqueIdentifier {
        &self.uid
    }
}

impl fmt::Display for SequencerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_proto_primitive())
    }
}

/// Parse a member string into code and unique identifier.
///
/// Expected format: `CODE::identifier::fingerprint`
fn parse_member_string(s: &str) -> Result<(MemberCode, UniqueIdentifier), MemberError> {
    // Format: CODE::identifier::fingerprint
    // Minimum: CODE (3) + :: (2) + id (1) + :: (2) + fingerprint (1) = 9 chars
    
    if s.len() < 3 + DELIMITER.len() * 2 + 2 {
        return Err(MemberError::ParseError(format!(
            "invalid member '{}': too short",
            s
        )));
    }
    
    // First 3 chars are the code
    let code_str = &s[..3];
    let code = MemberCode::parse(code_str)?;
    
    // Check delimiter after code
    let after_code = &s[3..];
    if !after_code.starts_with(DELIMITER) {
        return Err(MemberError::ParseError(format!(
            "expected '{}' after member code in '{}'",
            DELIMITER, s
        )));
    }
    
    // Rest is the unique identifier
    let uid_str = &after_code[DELIMITER.len()..];
    let uid = UniqueIdentifier::from_proto_primitive(uid_str)?;
    
    Ok((code, uid))
}

/// Generic member that can be any type (Participant, Mediator, Sequencer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyMember {
    Participant(ParticipantId),
    Mediator(MediatorId),
    Sequencer(SequencerId),
}

impl AnyMember {
    /// Parse from proto primitive string.
    pub fn from_proto_primitive(s: &str) -> Result<Self, MemberError> {
        let (code, uid) = parse_member_string(s)?;
        match code {
            MemberCode::Participant => Ok(AnyMember::Participant(ParticipantId::new(uid))),
            MemberCode::Mediator => Ok(AnyMember::Mediator(MediatorId::new(uid))),
            MemberCode::Sequencer => Ok(AnyMember::Sequencer(SequencerId::new(uid))),
        }
    }

    /// Get the member code.
    pub fn code(&self) -> MemberCode {
        match self {
            AnyMember::Participant(_) => MemberCode::Participant,
            AnyMember::Mediator(_) => MemberCode::Mediator,
            AnyMember::Sequencer(_) => MemberCode::Sequencer,
        }
    }

    /// Get the unique identifier.
    pub fn uid(&self) -> &UniqueIdentifier {
        match self {
            AnyMember::Participant(p) => &p.uid,
            AnyMember::Mediator(m) => &m.uid,
            AnyMember::Sequencer(s) => &s.uid,
        }
    }

    /// Convert to proto primitive format.
    pub fn to_proto_primitive(&self) -> String {
        match self {
            AnyMember::Participant(p) => p.to_proto_primitive(),
            AnyMember::Mediator(m) => m.to_proto_primitive(),
            AnyMember::Sequencer(s) => s.to_proto_primitive(),
        }
    }
}

impl fmt::Display for AnyMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_proto_primitive())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace() {
        let ns = Namespace::new("abc123def456").unwrap();
        assert_eq!(ns.fingerprint(), "abc123def456");
    }

    #[test]
    fn test_namespace_invalid() {
        assert!(Namespace::new("").is_err());
        assert!(Namespace::new("not-hex!").is_err());
    }

    #[test]
    fn test_unique_identifier() {
        let uid = UniqueIdentifier::new("mynode", "abc123def456").unwrap();
        assert_eq!(uid.identifier(), "mynode");
        assert_eq!(uid.namespace().fingerprint(), "abc123def456");
        assert_eq!(uid.to_proto_primitive(), "mynode::abc123def456");
    }

    #[test]
    fn test_unique_identifier_from_proto() {
        let uid = UniqueIdentifier::from_proto_primitive("mynode::abc123").unwrap();
        assert_eq!(uid.identifier(), "mynode");
        assert_eq!(uid.namespace().fingerprint(), "abc123");
    }

    #[test]
    fn test_unique_identifier_invalid() {
        // Empty identifier
        assert!(UniqueIdentifier::new("", "abc123").is_err());
        
        // Contains delimiter
        assert!(UniqueIdentifier::new("my::node", "abc123").is_err());
        
        // Invalid characters
        assert!(UniqueIdentifier::new("my node", "abc123").is_err());
    }

    #[test]
    fn test_participant_id() {
        let pid = ParticipantId::create("myparticipant", "abc123def456").unwrap();
        assert_eq!(pid.code(), MemberCode::Participant);
        assert_eq!(pid.to_proto_primitive(), "PAR::myparticipant::abc123def456");
    }

    #[test]
    fn test_participant_id_from_proto() {
        let pid = ParticipantId::from_proto_primitive("PAR::myparticipant::abc123").unwrap();
        assert_eq!(pid.uid().identifier(), "myparticipant");
    }

    #[test]
    fn test_mediator_id() {
        let mid = MediatorId::create("mymediator", "abc123").unwrap();
        assert_eq!(mid.code(), MemberCode::Mediator);
        assert!(mid.to_proto_primitive().starts_with("MED::"));
    }

    #[test]
    fn test_sequencer_id() {
        let sid = SequencerId::create("mysequencer", "abc123").unwrap();
        assert_eq!(sid.code(), MemberCode::Sequencer);
        assert!(sid.to_proto_primitive().starts_with("SEQ::"));
    }

    #[test]
    fn test_any_member() {
        let par = AnyMember::from_proto_primitive("PAR::node1::abc123").unwrap();
        assert_eq!(par.code(), MemberCode::Participant);

        let med = AnyMember::from_proto_primitive("MED::node2::def456").unwrap();
        assert_eq!(med.code(), MemberCode::Mediator);

        let seq = AnyMember::from_proto_primitive("SEQ::node3::789abc").unwrap();
        assert_eq!(seq.code(), MemberCode::Sequencer);
    }

    #[test]
    fn test_member_code() {
        assert_eq!(MemberCode::Participant.as_str(), "PAR");
        assert_eq!(MemberCode::Mediator.as_str(), "MED");
        assert_eq!(MemberCode::Sequencer.as_str(), "SEQ");

        assert_eq!(MemberCode::parse("PAR").unwrap(), MemberCode::Participant);
        assert!(MemberCode::parse("XXX").is_err());
        
        // Test FromStr trait
        use std::str::FromStr;
        assert_eq!("PAR".parse::<MemberCode>().unwrap(), MemberCode::Participant);
    }
}
