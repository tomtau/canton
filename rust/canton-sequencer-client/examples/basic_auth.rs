// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating full usage of the Canton Sequencer Clients.
//!
//! This example shows how to:
//! 1. Generate an Ed25519 signing key
//! 2. Create a Participant ID from the key
//! 3. Connect and perform handshake with SequencerConnectService
//! 4. Get synchronizer info and parameters
//! 5. Authenticate using SequencerAuthenticationService
//! 6. Use SequencerService to get traffic state
//!
//! Usage:
//! ```bash
//! cargo run --example basic_auth -- http://localhost:5001 myparticipant
//! ```

use canton_sequencer_client::{
    member::Member, signing::Ed25519Signer,
    SequencerConnectClient, SequencerAuthClient, SequencerServiceClient,
    LATEST_STABLE_VERSION,
};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <endpoint> <participant-name>", args[0]);
        eprintln!("Example: {} http://localhost:5001 myparticipant", args[0]);
        std::process::exit(1);
    }

    let endpoint = &args[1];
    let participant_name = &args[2];

    // Step 1: Generate a new Ed25519 signing key
    // In production, you would load this from secure storage
    println!("=== Key Generation ===");
    let signer = Ed25519Signer::generate();
    println!("Generated Ed25519 key pair");
    println!("Key fingerprint: {}", signer.fingerprint());

    // Step 2: Create a Participant ID from the signing key
    // The key fingerprint becomes the namespace part of the ID
    let participant_id = signer.participant_id(participant_name)?;
    println!("\n=== Participant ID ===");
    println!("Full ID: {}", participant_id.to_proto_primitive());
    println!("  - Code: {} (Participant)", participant_id.code());
    println!("  - Identifier: {}", participant_id.uid().identifier());
    println!("  - Namespace: {}", participant_id.uid().namespace());

    // Step 3: Connect and perform handshake
    println!("\n=== SequencerConnectService ===");
    println!("Endpoint: {}", endpoint);
    let mut connect_client = SequencerConnectClient::connect(endpoint.clone()).await?;
    println!("Connected successfully!");

    // Perform protocol version handshake
    println!("\n--- Handshake ---");
    println!("Client protocol version: {}", LATEST_STABLE_VERSION);
    match connect_client.handshake().await {
        Ok(response) => {
            println!("Server protocol version: {}", response.server_protocol_version);
            match response.value {
                Some(canton_sequencer_client::proto::sequencer::sequencer_connect::handshake_response::Value::Success(_)) => {
                    println!("Handshake: SUCCESS");
                }
                Some(canton_sequencer_client::proto::sequencer::sequencer_connect::handshake_response::Value::Failure(f)) => {
                    println!("Handshake: FAILED - {}", f.reason);
                }
                None => {
                    println!("Handshake: No response value");
                }
            }
        }
        Err(e) => {
            println!("Handshake failed: {}", e);
        }
    }

    // Get synchronizer ID
    println!("\n--- Synchronizer Info ---");
    match connect_client.get_synchronizer_id().await {
        Ok(info) => {
            println!("Physical Synchronizer ID: {}", info.physical_synchronizer_id);
            println!("Sequencer UID: {}", info.sequencer_uid);
        }
        Err(e) => {
            println!("Failed to get synchronizer ID: {}", e);
        }
    }

    // Verify active
    println!("\n--- Verify Active ---");
    match connect_client.verify_active().await {
        Ok(response) => {
            match response.value {
                Some(canton_sequencer_client::proto::sequencer::sequencer_connect::verify_active_response::Value::Success(s)) => {
                    println!("Sequencer active: {}", s.is_active);
                }
                Some(canton_sequencer_client::proto::sequencer::sequencer_connect::verify_active_response::Value::Failure(f)) => {
                    println!("Verify active failed: {}", f.reason);
                }
                None => {
                    println!("Verify active: No response");
                }
            }
        }
        Err(e) => {
            println!("Failed to verify active: {}", e);
        }
    }

    // Step 4: Authentication
    println!("\n=== SequencerAuthenticationService ===");
    let mut auth_client = SequencerAuthClient::connect(endpoint.clone()).await?;

    // Request a challenge
    println!("\n--- Challenge ---");
    println!("Requesting challenge for: {}", participant_id);
    let challenge = auth_client.challenge(&participant_id).await?;

    println!("Nonce (hex): {}", hex_encode(&challenge.nonce));
    println!("Valid key fingerprints from sequencer:");
    for fp in &challenge.fingerprints {
        println!("  - {}", fp);
    }

    // Sign the nonce
    println!("\n--- Sign Nonce ---");
    let signature = signer.sign_nonce(&challenge.nonce);
    println!("Signature created (64 bytes, Ed25519)");
    println!("Signed by fingerprint: {}", signature.signed_by);

    // Authenticate
    println!("\n--- Authenticate ---");
    match auth_client
        .authenticate(&participant_id, signature, challenge.nonce)
        .await
    {
        Ok(token) => {
            println!("Authentication SUCCESSFUL!");
            println!("Token (hex): {}", hex_encode(&token.token));
            if let Some(expires_at) = token.expires_at {
                println!("Expires at: {} seconds", expires_at.seconds);
            }

            // Step 5: Use SequencerService
            println!("\n=== SequencerService ===");
            let mut service_client = SequencerServiceClient::connect(endpoint.clone()).await?;

            // Get current time
            println!("\n--- Get Time ---");
            match service_client.get_time().await {
                Ok(Some(time)) => {
                    println!("Current sequencing time: {} microseconds", time);
                }
                Ok(None) => {
                    println!("Sequencer is still initializing");
                }
                Err(e) => {
                    println!("Failed to get time: {}", e);
                }
            }

            // Get traffic state
            println!("\n--- Get Traffic State ---");
            match service_client.get_traffic_state(&participant_id, 0).await {
                Ok(Some(state)) => {
                    println!("Traffic state:");
                    println!("  Extra traffic purchased: {}", state.extra_traffic_purchased);
                    println!("  Extra traffic consumed: {}", state.extra_traffic_consumed);
                    println!("  Base traffic remainder: {}", state.base_traffic_remainder);
                }
                Ok(None) => {
                    println!("No traffic state available");
                }
                Err(e) => {
                    println!("Failed to get traffic state: {}", e);
                }
            }

            // Logout
            println!("\n=== Logout ===");
            auth_client.logout(token.token).await?;
            println!("Logged out successfully!");
        }
        Err(e) => {
            println!("Authentication FAILED: {}", e);
            println!("\nNote: This is expected if your key is not registered with the sequencer.");
            println!("In a real scenario, you need to first register your key with the synchronizer.");
        }
    }

    Ok(())
}

/// Simple hex encoding for display
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
