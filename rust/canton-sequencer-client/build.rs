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

    // Compile protocol types (sequencing, traffic, topology)
    tonic_build::configure()
        .build_server(false)
        .extern_path(
            ".com.digitalasset.canton.crypto.v30",
            "crate::proto::crypto",
        )
        .compile_protos(
            &[
                "proto/com/digitalasset/canton/protocol/v30/sequencing.proto",
                "proto/com/digitalasset/canton/protocol/v30/topology.proto",
                "proto/com/digitalasset/canton/protocol/v30/traffic_control_parameters.proto",
            ],
            &[proto_root],
        )?;

    // Compile topology admin types
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &["proto/com/digitalasset/canton/topology/admin/v30/common.proto"],
            &[proto_root],
        )?;

    // Compile trace context
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &["proto/com/digitalasset/canton/v30/trace_context.proto"],
            &[proto_root],
        )?;

    // Finally, compile all sequencer services, using extern_path 
    // to reference the other types from the crate modules
    tonic_build::configure()
        .build_server(false)
        .extern_path(
            ".com.digitalasset.canton.crypto.v30",
            "crate::proto::crypto",
        )
        .extern_path(
            ".com.digitalasset.canton.protocol.v30",
            "crate::proto::protocol",
        )
        .extern_path(
            ".com.digitalasset.canton.topology.admin.v30",
            "crate::proto::topology",
        )
        .extern_path(
            ".com.digitalasset.canton.v30",
            "crate::proto::trace",
        )
        .compile_protos(
            &[
                "proto/com/digitalasset/canton/sequencer/api/v30/sequencer_authentication_service.proto",
                "proto/com/digitalasset/canton/sequencer/api/v30/sequencer_connect_service.proto",
                "proto/com/digitalasset/canton/sequencer/api/v30/sequencer_service.proto",
            ],
            &[proto_root],
        )?;

    // Rerun build script if proto files change
    println!("cargo:rerun-if-changed=proto/");
    Ok(())
}
