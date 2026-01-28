// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canton Sequencer gRPC Client
//!
//! This crate provides a Rust client for interacting with the Canton Sequencer
//! authentication service using gRPC (via tonic).
//!
//! # Features
//!
//! - **Member ID Generation**: Create participant, mediator, or sequencer IDs from signing keys
//! - **Ed25519 Signing**: Sign challenge nonces for authentication
//! - **gRPC Client**: Connect and authenticate with Canton sequencers
//!
//! # Example
//!
//! ```ignore
//! use canton_sequencer_client::{SequencerAuthClient, signing::Ed25519Signer, member::ParticipantId};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate a signing key and create a participant ID
//!     let signer = Ed25519Signer::generate();
//!     let participant_id = ParticipantId::create("myparticipant", signer.fingerprint())?;
//!
//!     // Connect to the sequencer
//!     let mut client = SequencerAuthClient::connect("http://localhost:5001").await?;
//!
//!     // Authenticate using challenge-response
//!     let challenge = client.challenge(participant_id.to_proto_primitive(), vec![30]).await?;
//!     let signature = signer.sign_nonce(&challenge.nonce);
//!     let token = client.authenticate(participant_id.to_proto_primitive(), signature, challenge.nonce).await?;
//!
//!     println!("Authenticated! Token expires at: {:?}", token.expires_at);
//!     Ok(())
//! }
//! ```

pub mod member;
pub mod signing;

/// Generated protobuf types for the Canton Sequencer API.
pub mod proto {
    /// Crypto types (signatures, keys, etc.)
    pub mod crypto {
        tonic::include_proto!("com.digitalasset.canton.crypto.v30");
    }
    /// Sequencer authentication service types and client.
    pub mod sequencer {
        tonic::include_proto!("com.digitalasset.canton.sequencer.api.v30");
    }
}

use proto::sequencer::sequencer_authentication_service_client::SequencerAuthenticationServiceClient;
use tonic::transport::{Channel, Endpoint};

// Re-export commonly used types
pub use proto::crypto::{
    Signature, SignatureDelegation, SignatureFormat, SigningAlgorithmSpec, SigningKeySpec,
};
pub use proto::sequencer::sequencer_authentication::{
    AuthenticateRequest, AuthenticateResponse, ChallengeRequest, ChallengeResponse, LogoutRequest,
    LogoutResponse,
};

// Re-export member types
pub use member::{MemberCode, ParticipantId, MediatorId, SequencerId, UniqueIdentifier, Member};

/// Authentication token returned by the sequencer after successful authentication.
#[derive(Debug, Clone)]
pub struct AuthToken {
    /// The authentication token bytes
    pub token: Vec<u8>,
    /// When the token expires (Unix timestamp)
    pub expires_at: Option<prost_types::Timestamp>,
}

/// A client for the Canton Sequencer Authentication Service.
///
/// This client wraps the gRPC `SequencerAuthenticationService` and provides
/// a convenient Rust interface for the challenge-response authentication flow.
pub struct SequencerAuthClient {
    inner: SequencerAuthenticationServiceClient<Channel>,
}

impl SequencerAuthClient {
    /// Connect to a sequencer at the given endpoint.
    ///
    /// # Arguments
    /// * `endpoint` - The URL of the sequencer (e.g., "http://localhost:5001")
    ///
    /// # Example
    /// ```ignore
    /// let client = SequencerAuthClient::connect("http://localhost:5001").await?;
    /// ```
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self, tonic::transport::Error> {
        let endpoint = Endpoint::from_shared(endpoint.into())?;
        let channel = endpoint.connect().await?;
        Ok(Self {
            inner: SequencerAuthenticationServiceClient::new(channel),
        })
    }

    /// Create a new client from an existing channel.
    ///
    /// This is useful when you want to share a channel across multiple clients
    /// or need more control over the channel configuration.
    pub fn from_channel(channel: Channel) -> Self {
        Self {
            inner: SequencerAuthenticationServiceClient::new(channel),
        }
    }

    /// Request a challenge from the sequencer.
    ///
    /// This is the first step in the authentication flow. The sequencer returns
    /// a nonce and a list of key fingerprints that it considers valid for signing.
    ///
    /// # Arguments
    /// * `member` - The member identifier requesting authentication
    /// * `protocol_versions` - List of protocol versions the member supports
    ///
    /// # Returns
    /// A `ChallengeResponse` containing the nonce to sign and valid key fingerprints.
    pub async fn challenge(
        &mut self,
        member: impl Into<String>,
        protocol_versions: Vec<i32>,
    ) -> Result<ChallengeResponse, tonic::Status> {
        let request = ChallengeRequest {
            member: member.into(),
            member_protocol_versions: protocol_versions,
        };

        let response = self.inner.challenge(request).await?;
        Ok(response.into_inner())
    }

    /// Authenticate with the sequencer using a signed nonce.
    ///
    /// This is the second step in the authentication flow. After signing the
    /// nonce received from `challenge()`, submit the signature to receive an
    /// authentication token.
    ///
    /// # Arguments
    /// * `member` - The member identifier
    /// * `signature` - The signature of the nonce
    /// * `nonce` - The nonce that was signed (from the challenge response)
    ///
    /// # Returns
    /// An `AuthToken` containing the authentication token and expiry time.
    pub async fn authenticate(
        &mut self,
        member: impl Into<String>,
        signature: Signature,
        nonce: Vec<u8>,
    ) -> Result<AuthToken, tonic::Status> {
        let request = AuthenticateRequest {
            member: member.into(),
            signature: Some(signature),
            nonce,
        };

        let response = self.inner.authenticate(request).await?;
        let auth_response = response.into_inner();

        Ok(AuthToken {
            token: auth_response.token,
            expires_at: auth_response.expires_at,
        })
    }

    /// Logout and invalidate the authentication token.
    ///
    /// This revokes the given token and disconnects the member from the sequencer.
    ///
    /// # Arguments
    /// * `token` - The authentication token to revoke
    pub async fn logout(&mut self, token: Vec<u8>) -> Result<LogoutResponse, tonic::Status> {
        let request = LogoutRequest { token };
        let response = self.inner.logout(request).await?;
        Ok(response.into_inner())
    }

    /// Get the inner gRPC client for direct access.
    ///
    /// This is useful when you need to access features not exposed by this wrapper.
    pub fn inner(&mut self) -> &mut SequencerAuthenticationServiceClient<Channel> {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_creation() {
        // Test that we can create a Signature struct
        let sig = Signature {
            format: SignatureFormat::Concat as i32,
            signature: vec![1, 2, 3, 4],
            signed_by: "test-key-fingerprint".to_string(),
            signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
            signature_delegation: None,
        };
        assert_eq!(sig.signature, vec![1, 2, 3, 4]);
        assert_eq!(sig.signed_by, "test-key-fingerprint");
    }

    #[test]
    fn test_challenge_request_creation() {
        let request = ChallengeRequest {
            member: "test-member".to_string(),
            member_protocol_versions: vec![30],
        };
        assert_eq!(request.member, "test-member");
        assert_eq!(request.member_protocol_versions, vec![30]);
    }

    #[test]
    fn test_member_id_generation() {
        use signing::Ed25519Signer;
        
        let signer = Ed25519Signer::generate();
        let fingerprint = signer.fingerprint();
        
        // Create a participant ID using the signing key's fingerprint
        let participant = ParticipantId::create("myparticipant", &fingerprint).unwrap();
        
        // Verify the format
        let proto = participant.to_proto_primitive();
        assert!(proto.starts_with("PAR::myparticipant::"));
        assert!(proto.contains(&fingerprint));
    }
}
