// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating basic usage of the Canton Sequencer Authentication Client.
//!
//! This example shows how to:
//! 1. Generate an Ed25519 signing key
//! 2. Create a Participant ID from the key
//! 3. Connect to a sequencer and authenticate
//!
//! Usage:
//! ```bash
//! cargo run --example basic_auth -- http://localhost:5001 myparticipant
//! ```

use canton_sequencer_client::{
    member::Member, signing::Ed25519Signer, SequencerAuthClient,
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

    // Step 3: Connect to the sequencer
    println!("\n=== Connecting to Sequencer ===");
    println!("Endpoint: {}", endpoint);
    let mut client = SequencerAuthClient::connect(endpoint.clone()).await?;
    println!("Connected successfully!");

    // Step 4: Request a challenge for our participant
    println!("\n=== Authentication Challenge ===");
    let member_str = participant_id.to_proto_primitive();
    println!("Requesting challenge for: {}", member_str);
    let challenge = client.challenge(&member_str, vec![30]).await?;

    println!("Nonce (hex): {}", hex_encode(&challenge.nonce));
    println!("Valid key fingerprints from sequencer:");
    for fp in &challenge.fingerprints {
        println!("  - {}", fp);
    }

    // Step 5: Sign the nonce
    println!("\n=== Signing Challenge ===");
    let signature = signer.sign_nonce(&challenge.nonce);
    println!("Signature created (64 bytes, Ed25519)");
    println!("Signed by fingerprint: {}", signature.signed_by);

    // Step 6: Authenticate with the sequencer
    println!("\n=== Authentication ===");
    match client
        .authenticate(&member_str, signature, challenge.nonce)
        .await
    {
        Ok(token) => {
            println!("Authentication SUCCESSFUL!");
            println!("Token (hex): {}", hex_encode(&token.token));
            if let Some(expires_at) = token.expires_at {
                println!("Expires at: {} seconds", expires_at.seconds);
            }

            // Step 7: Logout
            println!("\n=== Logout ===");
            client.logout(token.token).await?;
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
