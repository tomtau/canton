// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canton Sequencer gRPC Client
//!
//! This crate provides Rust clients for interacting with Canton Sequencer services
//! using gRPC (via tonic).
//!
//! # Features
//!
//! - **Member ID Generation**: Create participant, mediator, or sequencer IDs from signing keys
//! - **Ed25519 Signing**: Sign challenge nonces for authentication
//! - **Topology Transactions**: Create and sign topology transactions for onboarding
//! - **Sequencer Connect**: Perform handshakes, get synchronizer info, register topology transactions
//! - **Sequencer Authentication**: Challenge-response authentication flow
//! - **Sequencer Service**: Get traffic state, subscribe to events
//! - **Protocol Versions**: Constants for supported Canton protocol versions
//!
//! # Example
//!
//! ```ignore
//! use canton_sequencer_client::{
//!     SequencerConnectClient, SequencerAuthClient, SequencerServiceClient,
//!     signing::Ed25519Signer, topology::TopologyTransactionBuilder, Member
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate a signing key and create a participant ID
//!     let signer = Ed25519Signer::generate();
//!     let participant_id = signer.participant_id("myparticipant")?;
//!
//!     // Step 1: Connect and perform handshake
//!     let mut connect_client = SequencerConnectClient::connect("http://localhost:5001").await?;
//!     let handshake = connect_client.handshake().await?;
//!     println!("Server protocol version: {}", handshake.server_protocol_version);
//!     
//!     // Get synchronizer info
//!     let sync_id = connect_client.get_synchronizer_id().await?;
//!     println!("Synchronizer ID: {}", sync_id.physical_synchronizer_id);
//!
//!     // Step 2: Register onboarding topology transactions
//!     let builder = TopologyTransactionBuilder::new(&signer);
//!     let transactions = builder.onboarding_transactions(
//!         &participant_id,
//!         &sync_id.physical_synchronizer_id
//!     );
//!     connect_client.register_onboarding_topology_transactions(transactions).await?;
//!
//!     // Step 3: Authenticate
//!     let mut auth_client = SequencerAuthClient::connect("http://localhost:5001").await?;
//!     let challenge = auth_client.challenge(&participant_id).await?;
//!     let signature = signer.sign_nonce(&challenge.nonce);
//!     let token = auth_client.authenticate(&participant_id, signature, challenge.nonce).await?;
//!
//!     // Step 4: Use sequencer service (requires authentication)
//!     let mut service_client = SequencerServiceClient::connect("http://localhost:5001").await?;
//!     let traffic = service_client.get_traffic_state(&participant_id, 0).await?;
//!     println!("Traffic state: {:?}", traffic);
//!
//!     Ok(())
//! }
//! ```

pub mod member;
pub mod protocol;
pub mod signing;
pub mod topology;

/// Generated protobuf types for the Canton Sequencer API.
pub mod proto {
    /// Crypto types (signatures, keys, etc.)
    pub mod crypto {
        tonic::include_proto!("com.digitalasset.canton.crypto.v30");
    }
    /// Sequencer services types and clients.
    pub mod sequencer {
        tonic::include_proto!("com.digitalasset.canton.sequencer.api.v30");
    }
    /// Protocol types (traffic, topology, sequencing)
    pub mod protocol {
        tonic::include_proto!("com.digitalasset.canton.protocol.v30");
    }
    /// Topology admin types
    pub mod topology {
        tonic::include_proto!("com.digitalasset.canton.topology.admin.v30");
    }
    /// Trace context
    pub mod trace {
        tonic::include_proto!("com.digitalasset.canton.v30");
    }
}

use proto::sequencer::sequencer_authentication_service_client::SequencerAuthenticationServiceClient;
use proto::sequencer::sequencer_connect_service_client::SequencerConnectServiceClient;
use proto::sequencer::sequencer_service_client::SequencerServiceClient as SequencerServiceGrpcClient;
use tonic::transport::{Channel, Endpoint};

// Re-export commonly used types
pub use proto::crypto::{
    Signature, SignatureDelegation, SignatureFormat, SigningAlgorithmSpec, SigningKeySpec,
};
pub use proto::sequencer::sequencer_authentication::{
    AuthenticateRequest, AuthenticateResponse, ChallengeRequest, ChallengeResponse, LogoutRequest,
    LogoutResponse,
};
pub use proto::sequencer::sequencer_connect::{
    HandshakeRequest, HandshakeResponse, GetSynchronizerIdRequest, GetSynchronizerIdResponse,
    GetSynchronizerParametersRequest, GetSynchronizerParametersResponse,
    VerifyActiveRequest, VerifyActiveResponse,
    RegisterOnboardingTopologyTransactionsRequest, RegisterOnboardingTopologyTransactionsResponse,
};
pub use proto::sequencer::{
    GetTrafficStateForMemberRequest, GetTrafficStateForMemberResponse,
    GetTimeRequest, GetTimeResponse,
};
pub use proto::protocol::{TrafficState, SignedTopologyTransaction};

// Re-export member types
pub use member::{MemberCode, ParticipantId, MediatorId, SequencerId, UniqueIdentifier, Member};

// Re-export protocol version types
pub use protocol::{ProtocolVersion, LATEST_STABLE_VERSION, MINIMUM_STABLE_VERSION};

// Re-export topology types
pub use topology::TopologyTransactionBuilder;

/// Authentication token returned by the sequencer after successful authentication.
#[derive(Debug, Clone)]
pub struct AuthToken {
    /// The authentication token bytes
    pub token: Vec<u8>,
    /// When the token expires (Unix timestamp)
    pub expires_at: Option<prost_types::Timestamp>,
}

/// Synchronizer information returned by GetSynchronizerId
#[derive(Debug, Clone)]
pub struct SynchronizerInfo {
    /// The physical synchronizer ID
    pub physical_synchronizer_id: String,
    /// The sequencer's unique identifier
    pub sequencer_uid: String,
}

// ============================================================================
// SequencerConnectClient - For handshake and registration before authentication
// ============================================================================

/// A client for the Canton Sequencer Connect Service.
///
/// This client is used for initial connection setup with the sequencer,
/// including protocol version handshake and retrieving synchronizer information.
/// This should be used *before* authentication.
///
/// # Example
/// ```ignore
/// let mut client = SequencerConnectClient::connect("http://localhost:5001").await?;
/// let handshake = client.handshake().await?;
/// let sync_id = client.get_synchronizer_id().await?;
/// ```
pub struct SequencerConnectClient {
    inner: SequencerConnectServiceClient<Channel>,
}

impl SequencerConnectClient {
    /// Connect to a sequencer at the given endpoint.
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self, tonic::transport::Error> {
        let endpoint = Endpoint::from_shared(endpoint.into())?;
        let channel = endpoint.connect().await?;
        Ok(Self {
            inner: SequencerConnectServiceClient::new(channel),
        })
    }

    /// Create a new client from an existing channel.
    pub fn from_channel(channel: Channel) -> Self {
        Self {
            inner: SequencerConnectServiceClient::new(channel),
        }
    }

    /// Perform a protocol version handshake with the sequencer.
    ///
    /// This verifies that the client and server can communicate using a compatible
    /// protocol version. Uses the latest stable protocol version by default.
    ///
    /// # Returns
    /// The handshake response containing the server's protocol version and success/failure.
    pub async fn handshake(&mut self) -> Result<HandshakeResponse, tonic::Status> {
        self.handshake_with_versions(vec![LATEST_STABLE_VERSION.as_i32()], None)
            .await
    }

    /// Perform a protocol version handshake with specific versions.
    ///
    /// # Arguments
    /// * `client_versions` - List of protocol versions the client supports
    /// * `minimum_version` - Optional minimum protocol version required
    pub async fn handshake_with_versions(
        &mut self,
        client_versions: Vec<i32>,
        minimum_version: Option<i32>,
    ) -> Result<HandshakeResponse, tonic::Status> {
        let request = HandshakeRequest {
            client_protocol_versions: client_versions,
            minimum_protocol_version: minimum_version,
        };
        let response = self.inner.handshake(request).await?;
        Ok(response.into_inner())
    }

    /// Get the synchronizer ID and sequencer UID.
    ///
    /// This returns information about the synchronizer that this sequencer belongs to.
    pub async fn get_synchronizer_id(&mut self) -> Result<SynchronizerInfo, tonic::Status> {
        let request = GetSynchronizerIdRequest {};
        let response = self.inner.get_synchronizer_id(request).await?;
        let inner = response.into_inner();
        Ok(SynchronizerInfo {
            physical_synchronizer_id: inner.physical_synchronizer_id,
            sequencer_uid: inner.sequencer_uid,
        })
    }

    /// Get the static synchronizer parameters.
    ///
    /// Returns the synchronizer's configuration including required crypto specs
    /// and protocol version.
    pub async fn get_synchronizer_parameters(
        &mut self,
    ) -> Result<GetSynchronizerParametersResponse, tonic::Status> {
        let request = GetSynchronizerParametersRequest {};
        let response = self.inner.get_synchronizer_parameters(request).await?;
        Ok(response.into_inner())
    }

    /// Verify if this sequencer is active.
    ///
    /// # Returns
    /// The response containing success (with is_active flag) or failure reason.
    pub async fn verify_active(&mut self) -> Result<VerifyActiveResponse, tonic::Status> {
        let request = VerifyActiveRequest {};
        let response = self.inner.verify_active(request).await?;
        Ok(response.into_inner())
    }

    /// Register onboarding topology transactions with the sequencer.
    ///
    /// This is used to submit the topology transactions required for participant
    /// onboarding before authentication. Typically includes:
    /// - Namespace delegation (root certificate)
    /// - Owner-to-key mapping
    /// - Synchronizer trust certificate
    ///
    /// # Arguments
    /// * `transactions` - The signed topology transactions to register
    ///
    /// # Example
    /// ```ignore
    /// use canton_sequencer_client::{
    ///     SequencerConnectClient, TopologyTransactionBuilder,
    ///     signing::Ed25519Signer
    /// };
    ///
    /// let signer = Ed25519Signer::generate();
    /// let participant_id = signer.participant_id("myparticipant")?;
    ///
    /// let mut client = SequencerConnectClient::connect("http://localhost:5001").await?;
    /// let sync_info = client.get_synchronizer_id().await?;
    ///
    /// // Build and sign onboarding transactions
    /// let builder = TopologyTransactionBuilder::new(&signer);
    /// let transactions = builder.onboarding_transactions(
    ///     &participant_id,
    ///     &sync_info.physical_synchronizer_id
    /// );
    ///
    /// // Submit to sequencer
    /// client.register_onboarding_topology_transactions(transactions).await?;
    /// ```
    pub async fn register_onboarding_topology_transactions(
        &mut self,
        transactions: Vec<SignedTopologyTransaction>,
    ) -> Result<RegisterOnboardingTopologyTransactionsResponse, tonic::Status> {
        let request = RegisterOnboardingTopologyTransactionsRequest {
            topology_transactions: transactions,
        };
        let response = self
            .inner
            .register_onboarding_topology_transactions(request)
            .await?;
        Ok(response.into_inner())
    }

    /// Get the inner gRPC client for direct access.
    pub fn inner(&mut self) -> &mut SequencerConnectServiceClient<Channel> {
        &mut self.inner
    }
}

// ============================================================================
// SequencerAuthClient - For challenge-response authentication
// ============================================================================

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

    /// Request a challenge from the sequencer using the latest stable protocol version.
    ///
    /// This is the first step in the authentication flow. The sequencer returns
    /// a nonce and a list of key fingerprints that it considers valid for signing.
    ///
    /// Uses [`LATEST_STABLE_VERSION`] as the protocol version.
    ///
    /// # Arguments
    /// * `member` - The member identifier requesting authentication (implements `Member` trait)
    ///
    /// # Returns
    /// A `ChallengeResponse` containing the nonce to sign and valid key fingerprints.
    ///
    /// # Example
    /// ```ignore
    /// let challenge = client.challenge(&participant_id).await?;
    /// ```
    pub async fn challenge<M: member::Member>(
        &mut self,
        member: &M,
    ) -> Result<ChallengeResponse, tonic::Status> {
        self.challenge_with_versions(member.to_proto_primitive(), vec![LATEST_STABLE_VERSION.as_i32()])
            .await
    }

    /// Request a challenge from the sequencer with specific protocol versions.
    ///
    /// This is the first step in the authentication flow. The sequencer returns
    /// a nonce and a list of key fingerprints that it considers valid for signing.
    ///
    /// # Arguments
    /// * `member` - The member identifier string (e.g., "PAR::name::fingerprint")
    /// * `protocol_versions` - List of protocol versions the member supports
    ///
    /// # Returns
    /// A `ChallengeResponse` containing the nonce to sign and valid key fingerprints.
    ///
    /// # Example
    /// ```ignore
    /// use canton_sequencer_client::ProtocolVersion;
    /// let challenge = client.challenge_with_versions(
    ///     "PAR::myparticipant::abc123",
    ///     vec![ProtocolVersion::V34.as_i32()]
    /// ).await?;
    /// ```
    pub async fn challenge_with_versions(
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
    /// * `member` - The member identifier (implements `Member` trait)
    /// * `signature` - The signature of the nonce
    /// * `nonce` - The nonce that was signed (from the challenge response)
    ///
    /// # Returns
    /// An `AuthToken` containing the authentication token and expiry time.
    pub async fn authenticate<M: member::Member>(
        &mut self,
        member: &M,
        signature: Signature,
        nonce: Vec<u8>,
    ) -> Result<AuthToken, tonic::Status> {
        let request = AuthenticateRequest {
            member: member.to_proto_primitive(),
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

// ============================================================================
// SequencerServiceClient - For traffic state and other operations (after auth)
// ============================================================================

/// A client for the Canton Sequencer Service.
///
/// This client provides access to sequencer operations like getting traffic state,
/// subscribing to events, and getting the current sequencing time.
/// Most operations require prior authentication.
///
/// # Example
/// ```ignore
/// let mut client = SequencerServiceClient::connect("http://localhost:5001").await?;
/// let traffic = client.get_traffic_state(&participant_id, timestamp).await?;
/// let time = client.get_time().await?;
/// ```
pub struct SequencerServiceClient {
    inner: SequencerServiceGrpcClient<Channel>,
}

impl SequencerServiceClient {
    /// Connect to a sequencer at the given endpoint.
    pub async fn connect(endpoint: impl Into<String>) -> Result<Self, tonic::transport::Error> {
        let endpoint = Endpoint::from_shared(endpoint.into())?;
        let channel = endpoint.connect().await?;
        Ok(Self {
            inner: SequencerServiceGrpcClient::new(channel),
        })
    }

    /// Create a new client from an existing channel.
    pub fn from_channel(channel: Channel) -> Self {
        Self {
            inner: SequencerServiceGrpcClient::new(channel),
        }
    }

    /// Get the traffic state for a member at a given timestamp.
    ///
    /// Returns the traffic control state including extra traffic purchased/consumed
    /// and base traffic remainder.
    ///
    /// # Arguments
    /// * `member` - The member to get traffic state for
    /// * `timestamp` - Timestamp in microseconds of UTC time since Unix epoch
    ///
    /// # Returns
    /// The traffic state for the member at the given timestamp.
    pub async fn get_traffic_state<M: member::Member>(
        &mut self,
        member: &M,
        timestamp: i64,
    ) -> Result<Option<TrafficState>, tonic::Status> {
        let request = GetTrafficStateForMemberRequest {
            member: member.to_proto_primitive(),
            timestamp,
        };
        let response = self.inner.get_traffic_state_for_member(request).await?;
        Ok(response.into_inner().traffic_state)
    }

    /// Get the current sequencing time.
    ///
    /// Returns a timestamp such that any subsequent `SendAsync` operation,
    /// if sequenced, will have a sequencing time later than this timestamp.
    ///
    /// # Returns
    /// The current sequencing timestamp in microseconds, or None if the sequencer
    /// is still initializing.
    pub async fn get_time(&mut self) -> Result<Option<i64>, tonic::Status> {
        let request = GetTimeRequest {};
        let response = self.inner.get_time(request).await?;
        Ok(response.into_inner().sequencing_timestamp)
    }

    /// Get the inner gRPC client for direct access.
    ///
    /// This is useful for advanced operations like subscribing to events
    /// or sending async messages.
    pub fn inner(&mut self) -> &mut SequencerServiceGrpcClient<Channel> {
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
            member_protocol_versions: vec![LATEST_STABLE_VERSION.as_i32()],
        };
        assert_eq!(request.member, "test-member");
        assert_eq!(request.member_protocol_versions, vec![34]); // v34 is latest stable
    }

    #[test]
    fn test_handshake_request_creation() {
        let request = HandshakeRequest {
            client_protocol_versions: vec![LATEST_STABLE_VERSION.as_i32()],
            minimum_protocol_version: Some(MINIMUM_STABLE_VERSION.as_i32()),
        };
        assert_eq!(request.client_protocol_versions, vec![34]);
        assert_eq!(request.minimum_protocol_version, Some(34));
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

    #[test]
    fn test_protocol_version_constants() {
        assert_eq!(LATEST_STABLE_VERSION.as_i32(), 34);
        assert!(LATEST_STABLE_VERSION.is_stable());
    }
}
