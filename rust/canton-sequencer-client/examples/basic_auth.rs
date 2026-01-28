// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Example demonstrating basic usage of the Canton Sequencer Authentication Client.
//!
//! This example shows how to connect to a sequencer and request a challenge.
//! In a real application, you would sign the nonce and complete authentication.
//!
//! Usage:
//! ```bash
//! cargo run --example basic_auth -- http://localhost:5001 my-member-id
//! ```

use canton_sequencer_client::SequencerAuthClient;
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

    println!("Connecting to sequencer at: {}", endpoint);

    // Step 1: Connect to the sequencer
    let mut client = SequencerAuthClient::connect(endpoint.clone()).await?;
    println!("Connected successfully!");

    // Step 2: Request a challenge
    // Protocol version 30 corresponds to the v30 API
    println!("Requesting challenge for member: {}", member_id);
    let challenge = client.challenge(member_id.clone(), vec![30]).await?;

    println!("\n=== Challenge Response ===");
    println!("Nonce (hex): {}", hex_encode(&challenge.nonce));
    println!("Valid key fingerprints:");
    for fp in &challenge.fingerprints {
        println!("  - {}", fp);
    }

    // In a real application, you would now:
    // 1. Sign the nonce with your private key
    // 2. Call client.authenticate() with the signature
    // 3. Use the resulting token for authenticated operations

    println!("\nTo complete authentication:");
    println!("1. Sign the nonce with one of the valid keys");
    println!("2. Call authenticate() with the signature");
    println!("3. Use the token for sequencer operations");

    Ok(())
}

/// Simple hex encoding for display
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
