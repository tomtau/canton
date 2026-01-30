// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Topology transaction builders for Canton Sequencer onboarding.
//!
//! This module provides utilities for creating and signing topology transactions
//! required for participant onboarding:
//!
//! 1. **NamespaceDelegation**: Establishes trust in a signing key for a namespace
//! 2. **OwnerToKeyMapping**: Maps a member (participant) to their signing/encryption keys
//! 3. **SynchronizerTrustCertificate**: Declares that a participant trusts a synchronizer
//!
//! # Example: Complete Onboarding Flow
//!
//! ```
//! use canton_sequencer_client::signing::Ed25519Signer;
//! use canton_sequencer_client::topology::{
//!     TopologyTransactionBuilder, NamespaceDelegationBuilder,
//!     OwnerToKeyMappingBuilder, SynchronizerTrustCertificateBuilder,
//! };
//!
//! // Generate signing key
//! let signer = Ed25519Signer::generate();
//! let participant_id = signer.participant_id("myparticipant").unwrap();
//!
//! // Build the onboarding transactions
//! let builder = TopologyTransactionBuilder::new(&signer);
//!
//! // 1. Namespace delegation (root cert for the namespace)
//! let nsd = builder.namespace_delegation_root();
//! let signed_nsd = builder.sign(nsd);
//!
//! // 2. Owner-to-key mapping
//! let otk = builder.owner_to_key_mapping(&participant_id);
//! let signed_otk = builder.sign(otk);
//!
//! // 3. Synchronizer trust certificate
//! let stc = builder.synchronizer_trust_certificate(
//!     &participant_id,
//!     "synchronizer::abc123"
//! );
//! let signed_stc = builder.sign(stc);
//!
//! // These can now be submitted via SequencerConnectClient::register_onboarding_topology_transactions()
//! ```

use crate::member::Member;
use crate::proto::crypto::{
    CryptoKeyFormat, PublicKey, Signature, SignatureFormat, SigningAlgorithmSpec, SigningKeySpec,
    SigningKeyUsage, SigningPublicKey,
};
use crate::proto::protocol::{
    enums::TopologyChangeOp, namespace_delegation, NamespaceDelegation, OwnerToKeyMapping,
    SignedTopologyTransaction, SynchronizerTrustCertificate, TopologyMapping, TopologyTransaction,
};
use crate::signing::Ed25519Signer;
use prost::Message;

/// Builder for creating topology transactions.
///
/// This builder simplifies the creation of topology transactions required
/// for participant onboarding.
pub struct TopologyTransactionBuilder<'a> {
    signer: &'a Ed25519Signer,
}

impl<'a> TopologyTransactionBuilder<'a> {
    /// Create a new topology transaction builder with the given signer.
    ///
    /// # Arguments
    /// * `signer` - The Ed25519 signer that will be used to sign transactions
    pub fn new(signer: &'a Ed25519Signer) -> Self {
        Self { signer }
    }

    /// Get the namespace (fingerprint) of the signer's key.
    pub fn namespace(&self) -> String {
        self.signer.fingerprint()
    }

    /// Create a root namespace delegation transaction.
    ///
    /// This establishes the signer's key as the root authority for the namespace.
    /// This is typically the first transaction needed for onboarding.
    ///
    /// # Returns
    /// A `TopologyTransaction` containing a root namespace delegation.
    #[allow(deprecated)]
    pub fn namespace_delegation_root(&self) -> TopologyTransaction {
        let target_key = SigningPublicKey {
            format: CryptoKeyFormat::Raw as i32,
            public_key: self.signer.public_key_bytes().to_vec(),
            scheme: 0, // deprecated field
            usage: vec![SigningKeyUsage::Namespace as i32],
            key_spec: SigningKeySpec::EcCurve25519 as i32,
        };

        let nsd = NamespaceDelegation {
            namespace: self.namespace(),
            target_key: Some(target_key),
            is_root_delegation: true, // Deprecated but set for compatibility
            restriction: Some(namespace_delegation::Restriction::CanSignAllMappings(
                namespace_delegation::CanSignAllMappings {},
            )),
        };

        TopologyTransaction {
            operation: TopologyChangeOp::AddReplace as i32,
            serial: 1,
            mapping: Some(TopologyMapping {
                mapping: Some(crate::proto::protocol::topology_mapping::Mapping::NamespaceDelegation(nsd)),
            }),
        }
    }

    /// Create an owner-to-key mapping transaction.
    ///
    /// This maps a member (e.g., participant) to their public key,
    /// enabling the member to sign messages.
    ///
    /// # Arguments
    /// * `member` - The member to map to the signer's key
    ///
    /// # Returns
    /// A `TopologyTransaction` containing an owner-to-key mapping.
    pub fn owner_to_key_mapping<M: Member>(&self, member: &M) -> TopologyTransaction {
        let signing_key = SigningPublicKey {
            format: CryptoKeyFormat::Raw as i32,
            public_key: self.signer.public_key_bytes().to_vec(),
            scheme: 0, // deprecated field
            usage: vec![
                SigningKeyUsage::SequencerAuthentication as i32,
                SigningKeyUsage::Protocol as i32,
            ],
            key_spec: SigningKeySpec::EcCurve25519 as i32,
        };

        let public_key = PublicKey {
            key: Some(crate::proto::crypto::public_key::Key::SigningPublicKey(signing_key)),
        };

        let otk = OwnerToKeyMapping {
            member: member.to_proto_primitive(),
            public_keys: vec![public_key],
        };

        TopologyTransaction {
            operation: TopologyChangeOp::AddReplace as i32,
            serial: 1,
            mapping: Some(TopologyMapping {
                mapping: Some(crate::proto::protocol::topology_mapping::Mapping::OwnerToKeyMapping(otk)),
            }),
        }
    }

    /// Create a synchronizer trust certificate transaction.
    ///
    /// This declares that a participant trusts a specific synchronizer
    /// and wishes to connect to it.
    ///
    /// # Arguments
    /// * `participant` - The participant that trusts the synchronizer
    /// * `synchronizer_id` - The ID of the synchronizer to trust
    ///
    /// # Returns
    /// A `TopologyTransaction` containing a synchronizer trust certificate.
    pub fn synchronizer_trust_certificate<M: Member>(
        &self,
        participant: &M,
        synchronizer_id: impl Into<String>,
    ) -> TopologyTransaction {
        let stc = SynchronizerTrustCertificate {
            participant_uid: participant.uid().to_string(),
            synchronizer_id: synchronizer_id.into(),
        };

        TopologyTransaction {
            operation: TopologyChangeOp::AddReplace as i32,
            serial: 1,
            mapping: Some(TopologyMapping {
                mapping: Some(crate::proto::protocol::topology_mapping::Mapping::SynchronizerTrustCertificate(stc)),
            }),
        }
    }

    /// Create a topology transaction with custom parameters.
    ///
    /// # Arguments
    /// * `operation` - The operation type (AddReplace or Remove)
    /// * `serial` - The serial number for the transaction
    /// * `mapping` - The topology mapping content
    pub fn custom(
        &self,
        operation: TopologyChangeOp,
        serial: u32,
        mapping: TopologyMapping,
    ) -> TopologyTransaction {
        TopologyTransaction {
            operation: operation as i32,
            serial,
            mapping: Some(mapping),
        }
    }

    /// Sign a topology transaction.
    ///
    /// Serializes the transaction and signs it with the signer's key.
    ///
    /// # Arguments
    /// * `transaction` - The topology transaction to sign
    ///
    /// # Returns
    /// A `SignedTopologyTransaction` with the signature attached.
    pub fn sign(&self, transaction: TopologyTransaction) -> SignedTopologyTransaction {
        // Serialize the transaction
        let transaction_bytes = transaction.encode_to_vec();

        // Sign the serialized transaction
        let signature = self.signer.sign(&transaction_bytes);

        let sig = Signature {
            format: SignatureFormat::Concat as i32,
            signature: signature.to_vec(),
            signed_by: self.signer.fingerprint(),
            signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
            signature_delegation: None,
        };

        SignedTopologyTransaction {
            transaction: transaction_bytes,
            signatures: vec![sig],
            proposal: false,
        }
    }

    /// Sign a topology transaction and return it as a proposal.
    ///
    /// A proposal indicates that the transaction is not yet fully authorized
    /// and may need additional signatures.
    ///
    /// # Arguments
    /// * `transaction` - The topology transaction to sign
    ///
    /// # Returns
    /// A `SignedTopologyTransaction` marked as a proposal.
    pub fn sign_as_proposal(&self, transaction: TopologyTransaction) -> SignedTopologyTransaction {
        let mut signed = self.sign(transaction);
        signed.proposal = true;
        signed
    }

    /// Create all the standard onboarding transactions for a participant.
    ///
    /// This is a convenience method that creates and signs:
    /// 1. A root namespace delegation
    /// 2. An owner-to-key mapping for the participant
    /// 3. A synchronizer trust certificate
    ///
    /// # Arguments
    /// * `participant` - The participant being onboarded
    /// * `synchronizer_id` - The synchronizer to connect to
    ///
    /// # Returns
    /// A vector of signed topology transactions ready to be submitted.
    pub fn onboarding_transactions<M: Member>(
        &self,
        participant: &M,
        synchronizer_id: impl Into<String>,
    ) -> Vec<SignedTopologyTransaction> {
        let sync_id = synchronizer_id.into();

        vec![
            self.sign(self.namespace_delegation_root()),
            self.sign(self.owner_to_key_mapping(participant)),
            self.sign(self.synchronizer_trust_certificate(participant, sync_id)),
        ]
    }
}

/// Builder for namespace delegation transactions.
pub struct NamespaceDelegationBuilder {
    namespace: String,
    target_key: SigningPublicKey,
    is_root: bool,
}

impl NamespaceDelegationBuilder {
    /// Create a new namespace delegation builder.
    ///
    /// # Arguments
    /// * `namespace` - The namespace (key fingerprint) being delegated
    /// * `target_key_bytes` - The public key bytes of the target key
    pub fn new(namespace: impl Into<String>, target_key_bytes: &[u8]) -> Self {
        Self {
            namespace: namespace.into(),
            target_key: SigningPublicKey {
                format: CryptoKeyFormat::Raw as i32,
                public_key: target_key_bytes.to_vec(),
                scheme: 0, // deprecated
                usage: vec![SigningKeyUsage::Namespace as i32],
                key_spec: SigningKeySpec::EcCurve25519 as i32,
            },
            is_root: false,
        }
    }

    /// Mark this as a root delegation.
    pub fn root(mut self) -> Self {
        self.is_root = true;
        self
    }

    /// Build the namespace delegation.
    #[allow(deprecated)]
    pub fn build(self) -> NamespaceDelegation {
        NamespaceDelegation {
            namespace: self.namespace,
            target_key: Some(self.target_key),
            is_root_delegation: self.is_root,
            restriction: if self.is_root {
                Some(namespace_delegation::Restriction::CanSignAllMappings(
                    namespace_delegation::CanSignAllMappings {},
                ))
            } else {
                Some(namespace_delegation::Restriction::CanSignAllButNamespaceDelegations(
                    namespace_delegation::CanSignAllButNamespaceDelegations {},
                ))
            },
        }
    }
}

/// Builder for owner-to-key mapping transactions.
pub struct OwnerToKeyMappingBuilder {
    member: String,
    public_keys: Vec<PublicKey>,
}

impl OwnerToKeyMappingBuilder {
    /// Create a new owner-to-key mapping builder.
    ///
    /// # Arguments
    /// * `member` - The member identifier (e.g., "PAR::name::fingerprint")
    pub fn new(member: impl Into<String>) -> Self {
        Self {
            member: member.into(),
            public_keys: Vec::new(),
        }
    }

    /// Add a signing key to the mapping.
    pub fn with_signing_key(mut self, key_bytes: &[u8]) -> Self {
        let signing_key = SigningPublicKey {
            format: CryptoKeyFormat::Raw as i32,
            public_key: key_bytes.to_vec(),
            scheme: 0, // deprecated
            usage: vec![
                SigningKeyUsage::SequencerAuthentication as i32,
                SigningKeyUsage::Protocol as i32,
            ],
            key_spec: SigningKeySpec::EcCurve25519 as i32,
        };
        self.public_keys.push(PublicKey {
            key: Some(crate::proto::crypto::public_key::Key::SigningPublicKey(signing_key)),
        });
        self
    }

    /// Build the owner-to-key mapping.
    pub fn build(self) -> OwnerToKeyMapping {
        OwnerToKeyMapping {
            member: self.member,
            public_keys: self.public_keys,
        }
    }
}

/// Builder for synchronizer trust certificate transactions.
pub struct SynchronizerTrustCertificateBuilder {
    participant_uid: String,
    synchronizer_id: String,
}

impl SynchronizerTrustCertificateBuilder {
    /// Create a new synchronizer trust certificate builder.
    ///
    /// # Arguments
    /// * `participant_uid` - The participant's unique identifier
    /// * `synchronizer_id` - The synchronizer's identifier
    pub fn new(participant_uid: impl Into<String>, synchronizer_id: impl Into<String>) -> Self {
        Self {
            participant_uid: participant_uid.into(),
            synchronizer_id: synchronizer_id.into(),
        }
    }

    /// Build the synchronizer trust certificate.
    pub fn build(self) -> SynchronizerTrustCertificate {
        SynchronizerTrustCertificate {
            participant_uid: self.participant_uid,
            synchronizer_id: self.synchronizer_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::Ed25519Signer;

    #[test]
    fn test_namespace_delegation_root() {
        let signer = Ed25519Signer::generate();
        let builder = TopologyTransactionBuilder::new(&signer);

        let tx = builder.namespace_delegation_root();
        assert_eq!(tx.operation, TopologyChangeOp::AddReplace as i32);
        assert_eq!(tx.serial, 1);
        assert!(tx.mapping.is_some());

        let mapping = tx.mapping.unwrap();
        match mapping.mapping {
            Some(crate::proto::protocol::topology_mapping::Mapping::NamespaceDelegation(nsd)) => {
                assert_eq!(nsd.namespace, signer.fingerprint());
                assert!(nsd.target_key.is_some());
            }
            _ => panic!("Expected NamespaceDelegation"),
        }
    }

    #[test]
    fn test_owner_to_key_mapping() {
        let signer = Ed25519Signer::generate();
        let participant = signer.participant_id("test").unwrap();
        let builder = TopologyTransactionBuilder::new(&signer);

        let tx = builder.owner_to_key_mapping(&participant);
        assert_eq!(tx.operation, TopologyChangeOp::AddReplace as i32);

        let mapping = tx.mapping.unwrap();
        match mapping.mapping {
            Some(crate::proto::protocol::topology_mapping::Mapping::OwnerToKeyMapping(otk)) => {
                assert_eq!(otk.member, participant.to_proto_primitive());
                assert_eq!(otk.public_keys.len(), 1);
            }
            _ => panic!("Expected OwnerToKeyMapping"),
        }
    }

    #[test]
    fn test_synchronizer_trust_certificate() {
        let signer = Ed25519Signer::generate();
        let participant = signer.participant_id("test").unwrap();
        let builder = TopologyTransactionBuilder::new(&signer);

        let tx = builder.synchronizer_trust_certificate(&participant, "sync::abc123");

        let mapping = tx.mapping.unwrap();
        match mapping.mapping {
            Some(crate::proto::protocol::topology_mapping::Mapping::SynchronizerTrustCertificate(stc)) => {
                assert_eq!(stc.participant_uid, participant.uid().to_string());
                assert_eq!(stc.synchronizer_id, "sync::abc123");
            }
            _ => panic!("Expected SynchronizerTrustCertificate"),
        }
    }

    #[test]
    fn test_sign_transaction() {
        let signer = Ed25519Signer::generate();
        let builder = TopologyTransactionBuilder::new(&signer);

        let tx = builder.namespace_delegation_root();
        let signed = builder.sign(tx);

        assert!(!signed.transaction.is_empty());
        assert_eq!(signed.signatures.len(), 1);
        assert!(!signed.proposal);

        let sig = &signed.signatures[0];
        assert_eq!(sig.signed_by, signer.fingerprint());
        assert_eq!(sig.signature.len(), 64); // Ed25519 signature length
    }

    #[test]
    fn test_sign_as_proposal() {
        let signer = Ed25519Signer::generate();
        let builder = TopologyTransactionBuilder::new(&signer);

        let tx = builder.namespace_delegation_root();
        let signed = builder.sign_as_proposal(tx);

        assert!(signed.proposal);
    }

    #[test]
    fn test_onboarding_transactions() {
        let signer = Ed25519Signer::generate();
        let participant = signer.participant_id("test").unwrap();
        let builder = TopologyTransactionBuilder::new(&signer);

        let transactions = builder.onboarding_transactions(&participant, "sync::abc123");

        // Should have 3 transactions: NSD, OTK, STC
        assert_eq!(transactions.len(), 3);

        // All should be signed and not proposals
        for tx in &transactions {
            assert!(!tx.transaction.is_empty());
            assert!(!tx.signatures.is_empty());
            assert!(!tx.proposal);
        }
    }

    #[test]
    fn test_namespace_delegation_builder() {
        let signer = Ed25519Signer::generate();
        let nsd = NamespaceDelegationBuilder::new(signer.fingerprint(), &signer.public_key_bytes())
            .root()
            .build();

        assert_eq!(nsd.namespace, signer.fingerprint());
        assert!(nsd.is_root_delegation);
    }

    #[test]
    fn test_owner_to_key_mapping_builder() {
        let signer = Ed25519Signer::generate();
        let otk = OwnerToKeyMappingBuilder::new("PAR::test::abc123")
            .with_signing_key(&signer.public_key_bytes())
            .build();

        assert_eq!(otk.member, "PAR::test::abc123");
        assert_eq!(otk.public_keys.len(), 1);
    }

    #[test]
    fn test_synchronizer_trust_certificate_builder() {
        let stc = SynchronizerTrustCertificateBuilder::new("test::abc123", "sync::def456").build();

        assert_eq!(stc.participant_uid, "test::abc123");
        assert_eq!(stc.synchronizer_id, "sync::def456");
    }
}
