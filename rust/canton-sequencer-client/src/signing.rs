// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 signing utilities for Canton Sequencer authentication.
//!
//! This module provides Ed25519-based signing capabilities using the `ed25519-dalek` crate.
//!
//! # Example
//!
//! ```
//! use canton_sequencer_client::signing::Ed25519Signer;
//!
//! // Generate a new random key pair
//! let signer = Ed25519Signer::generate();
//!
//! // Get the key fingerprint (SHA-256 hash of public key)
//! println!("Key fingerprint: {}", signer.fingerprint());
//!
//! // Sign a nonce
//! let nonce = b"challenge-nonce";
//! let signature = signer.sign_nonce(nonce);
//! ```

use crate::{Signature, SignatureFormat, SigningAlgorithmSpec};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;

/// Ed25519 signer for Canton Sequencer authentication.
///
/// This struct wraps an Ed25519 signing key and provides methods to sign nonces
/// and create Canton-compatible signature objects.
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Generate a new random Ed25519 key pair.
    ///
    /// Uses the operating system's cryptographically secure random number generator.
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::signing::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate();
    /// ```
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a signer from raw secret key bytes.
    ///
    /// # Arguments
    /// * `secret_key` - 32-byte Ed25519 secret key
    ///
    /// # Errors
    /// Returns an error if the secret key bytes are invalid.
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::signing::Ed25519Signer;
    ///
    /// let secret_bytes = [0u8; 32]; // Replace with actual secret key
    /// let signer = Ed25519Signer::from_secret_key(&secret_bytes).unwrap();
    /// ```
    pub fn from_secret_key(secret_key: &[u8; SECRET_KEY_LENGTH]) -> Result<Self, SigningError> {
        let signing_key = SigningKey::from_bytes(secret_key);
        Ok(Self { signing_key })
    }

    /// Get the public verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the raw public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the raw secret key bytes (32 bytes).
    ///
    /// # Security Warning
    /// Handle secret key bytes with care. Never log or transmit them insecurely.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Compute the key fingerprint (hex-encoded SHA-256 hash of the public key).
    ///
    /// This fingerprint can be used to identify the key when authenticating
    /// with the sequencer.
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::signing::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate();
    /// let fingerprint = signer.fingerprint();
    /// println!("Key fingerprint: {}", fingerprint);
    /// ```
    pub fn fingerprint(&self) -> String {
        use std::fmt::Write;

        // SHA-256 hash of the public key bytes
        let public_key = self.public_key_bytes();
        let hash = sha256(&public_key);

        // Hex encode the hash
        let mut hex = String::with_capacity(64);
        for byte in hash {
            write!(hex, "{:02x}", byte).unwrap();
        }
        hex
    }

    /// Sign raw bytes and return the signature bytes.
    ///
    /// Returns a 64-byte Ed25519 signature in concatenated R || S format.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.signing_key.sign(message);
        signature.to_bytes()
    }

    /// Sign a nonce and return a Canton-compatible Signature object.
    ///
    /// This is the primary method to use for sequencer authentication.
    /// The signature is formatted according to Canton's Ed25519 signature format
    /// (concatenated R || S in little-endian form).
    ///
    /// # Arguments
    /// * `nonce` - The challenge nonce received from the sequencer
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::signing::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate();
    /// let nonce = b"challenge-nonce-from-sequencer";
    /// let signature = signer.sign_nonce(nonce);
    ///
    /// // Use this signature with SequencerAuthClient::authenticate()
    /// ```
    pub fn sign_nonce(&self, nonce: &[u8]) -> Signature {
        let sig_bytes = self.sign(nonce);

        Signature {
            format: SignatureFormat::Concat as i32,
            signature: sig_bytes.to_vec(),
            signed_by: self.fingerprint(),
            signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
            signature_delegation: None,
        }
    }

    /// Verify a signature against a message.
    ///
    /// # Arguments
    /// * `message` - The original message that was signed
    /// * `signature` - The 64-byte signature to verify
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.signing_key.verifying_key().verify(message, &sig).is_ok()
    }

    /// Create a ParticipantId using this signer's key fingerprint as the namespace.
    ///
    /// # Arguments
    /// * `identifier` - Human-readable identifier for the participant
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::signing::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate();
    /// let participant_id = signer.participant_id("myparticipant").unwrap();
    /// println!("Participant: {}", participant_id);
    /// ```
    pub fn participant_id(&self, identifier: impl Into<String>) -> Result<crate::member::ParticipantId, crate::member::MemberError> {
        crate::member::ParticipantId::create(identifier, self.fingerprint())
    }

    /// Create a MediatorId using this signer's key fingerprint as the namespace.
    ///
    /// # Arguments
    /// * `identifier` - Human-readable identifier for the mediator
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::signing::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate();
    /// let mediator_id = signer.mediator_id("mymediator").unwrap();
    /// println!("Mediator: {}", mediator_id);
    /// ```
    pub fn mediator_id(&self, identifier: impl Into<String>) -> Result<crate::member::MediatorId, crate::member::MemberError> {
        crate::member::MediatorId::create(identifier, self.fingerprint())
    }

    /// Create a SequencerId using this signer's key fingerprint as the namespace.
    ///
    /// # Arguments
    /// * `identifier` - Human-readable identifier for the sequencer
    ///
    /// # Example
    /// ```
    /// use canton_sequencer_client::signing::Ed25519Signer;
    ///
    /// let signer = Ed25519Signer::generate();
    /// let sequencer_id = signer.sequencer_id("mysequencer").unwrap();
    /// println!("Sequencer: {}", sequencer_id);
    /// ```
    pub fn sequencer_id(&self, identifier: impl Into<String>) -> Result<crate::member::SequencerId, crate::member::MemberError> {
        crate::member::SequencerId::create(identifier, self.fingerprint())
    }
}

/// Simple SHA-256 implementation for fingerprint computation.
/// Uses a minimal implementation to avoid additional dependencies.
fn sha256(data: &[u8]) -> [u8; 32] {
    use std::num::Wrapping;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [Wrapping<u32>; 8] = [
        Wrapping(0x6a09e667), Wrapping(0xbb67ae85), Wrapping(0x3c6ef372), Wrapping(0xa54ff53a),
        Wrapping(0x510e527f), Wrapping(0x9b05688c), Wrapping(0x1f83d9ab), Wrapping(0x5be0cd19),
    ];

    // Pre-processing: adding padding bits
    let ml = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&ml.to_be_bytes());

    // Process each 512-bit chunk
    for chunk in padded.chunks(64) {
        let mut w = [Wrapping(0u32); 64];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = Wrapping(u32::from_be_bytes([word[0], word[1], word[2], word[3]]));
        }
        for i in 16..64 {
            let s0 = (w[i - 15].0.rotate_right(7)) ^ (w[i - 15].0.rotate_right(18)) ^ (w[i - 15].0 >> 3);
            let s1 = (w[i - 2].0.rotate_right(17)) ^ (w[i - 2].0.rotate_right(19)) ^ (w[i - 2].0 >> 10);
            w[i] = w[i - 16] + Wrapping(s0) + w[i - 7] + Wrapping(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = Wrapping(e.0.rotate_right(6) ^ e.0.rotate_right(11) ^ e.0.rotate_right(25));
            let ch = Wrapping((e.0 & f.0) ^ ((!e.0) & g.0));
            let temp1 = hh + s1 + ch + Wrapping(K[i]) + w[i];
            let s0 = Wrapping(a.0.rotate_right(2) ^ a.0.rotate_right(13) ^ a.0.rotate_right(22));
            let maj = Wrapping((a.0 & b.0) ^ (a.0 & c.0) ^ (b.0 & c.0));
            let temp2 = s0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&val.0.to_be_bytes());
    }
    result
}

/// Error type for signing operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningError {
    /// The provided key bytes are invalid.
    InvalidKey,
    /// The provided signature bytes are invalid.
    InvalidSignature,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::InvalidKey => write!(f, "invalid key bytes"),
            SigningError::InvalidSignature => write!(f, "invalid signature bytes"),
        }
    }
}

impl std::error::Error for SigningError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let signer = Ed25519Signer::generate();
        let message = b"test message";
        let signature = signer.sign(message);

        // Ed25519 signatures are 64 bytes
        assert_eq!(signature.len(), 64);

        // Verify the signature
        assert!(signer.verify(message, &signature));
    }

    #[test]
    fn test_sign_nonce() {
        let signer = Ed25519Signer::generate();
        let nonce = b"challenge-nonce";
        let signature = signer.sign_nonce(nonce);

        // Check signature format
        assert_eq!(signature.format, SignatureFormat::Concat as i32);
        assert_eq!(signature.signing_algorithm_spec, SigningAlgorithmSpec::Ed25519 as i32);
        assert_eq!(signature.signature.len(), 64);
        assert!(!signature.signed_by.is_empty());
    }

    #[test]
    fn test_fingerprint() {
        let signer = Ed25519Signer::generate();
        let fingerprint = signer.fingerprint();

        // SHA-256 hex is 64 characters
        assert_eq!(fingerprint.len(), 64);

        // Should be consistent
        assert_eq!(fingerprint, signer.fingerprint());
    }

    #[test]
    fn test_from_secret_key() {
        let signer1 = Ed25519Signer::generate();
        let secret_bytes = signer1.secret_key_bytes();

        let signer2 = Ed25519Signer::from_secret_key(&secret_bytes).unwrap();

        // Same key should produce same fingerprint
        assert_eq!(signer1.fingerprint(), signer2.fingerprint());

        // Same key should produce same signature
        let message = b"test";
        assert_eq!(signer1.sign(message), signer2.sign(message));
    }

    #[test]
    fn test_public_key_bytes() {
        let signer = Ed25519Signer::generate();
        let public_key = signer.public_key_bytes();

        // Ed25519 public keys are 32 bytes
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn test_verify_wrong_message() {
        let signer = Ed25519Signer::generate();
        let message1 = b"message 1";
        let message2 = b"message 2";
        let signature = signer.sign(message1);

        // Signature should not verify for different message
        assert!(!signer.verify(message2, &signature));
    }

    #[test]
    fn test_sha256_known_value() {
        // Test with a known SHA-256 hash
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }
}
