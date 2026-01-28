// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating basic usage of the Canton Sequencer Authentication Client.
//!
//! This example shows how to connect to a sequencer, request a challenge, and
//! sign it using Ed25519.
//!
//! Usage:
//! ```bash
//! cargo run --example basic_auth -- http://localhost:5001 my-member-id
//! ```

use canton_sequencer_client::{signing::Ed25519Signer, SequencerAuthClient};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <endpoint> <member-id>", args[0]);
        eprintln!("Example: {} http://localhost:5001 my-member-id", args[0]);
        std::process::exit(1);
    }

    let endpoint = &args[1];
    let member_id = &args[2];

    // Generate a new Ed25519 signing key
    // In production, you would load this from secure storage
    let signer = Ed25519Signer::generate();
    println!("Generated Ed25519 key pair");
    println!("Key fingerprint: {}", signer.fingerprint());

    println!("\nConnecting to sequencer at: {}", endpoint);

    // Step 1: Connect to the sequencer
    let mut client = SequencerAuthClient::connect(endpoint.clone()).await?;
    println!("Connected successfully!");

    // Step 2: Request a challenge
    // Protocol version 30 corresponds to the v30 API
    println!("\nRequesting challenge for member: {}", member_id);
    let challenge = client.challenge(member_id.clone(), vec![30]).await?;

    println!("\n=== Challenge Response ===");
    println!("Nonce (hex): {}", hex_encode(&challenge.nonce));
    println!("Valid key fingerprints:");
    for fp in &challenge.fingerprints {
        println!("  - {}", fp);
    }

    // Step 3: Sign the nonce
    println!("\nSigning nonce with Ed25519 key...");
    let signature = signer.sign_nonce(&challenge.nonce);
    println!("Signature created (64 bytes)");
    println!("Signature format: CONCAT (r || s little-endian)");
    println!("Signed by: {}", signature.signed_by);

    // Step 4: Authenticate with the sequencer
    println!("\nAuthenticating with sequencer...");
    match client
        .authenticate(member_id.clone(), signature, challenge.nonce)
        .await
    {
        Ok(token) => {
            println!("\n=== Authentication Successful ===");
            println!("Token (hex): {}", hex_encode(&token.token));
            if let Some(expires_at) = token.expires_at {
                println!("Expires at: {} seconds", expires_at.seconds);
            }

            // Step 5: Logout
            println!("\nLogging out...");
            client.logout(token.token).await?;
            println!("Logged out successfully!");
        }
        Err(e) => {
            println!("\nAuthentication failed: {}", e);
            println!("This is expected if your key is not registered with the sequencer.");
            println!("In a real scenario, you would use a key that the sequencer knows about.");
        }
    }

    Ok(())
}

/// Simple hex encoding for display
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
