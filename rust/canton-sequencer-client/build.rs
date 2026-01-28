// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

fn main() -> Result<()> {
    let proto_root = "proto";

    // First, compile the crypto types
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &["proto/com/digitalasset/canton/crypto/v30/crypto.proto"],
            &[proto_root],
        )?;

    // Then compile the sequencer authentication service, using extern_path 
    // to reference the crypto types from the crate module
    tonic_build::configure()
        .build_server(false)
        .extern_path(
            ".com.digitalasset.canton.crypto.v30",
            "crate::proto::crypto",
        )
        .compile_protos(
            &[
                "proto/com/digitalasset/canton/sequencer/api/v30/sequencer_authentication_service.proto",
            ],
            &[proto_root],
        )?;

    // Rerun build script if proto files change
    println!("cargo:rerun-if-changed=proto/");
    Ok(())
}
