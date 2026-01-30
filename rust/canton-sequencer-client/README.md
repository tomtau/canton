# Canton Sequencer Client (Rust)

A Rust gRPC client for Canton Sequencer services, built with [tonic](https://github.com/hyperium/tonic).

## Features

- **SequencerConnectService**: Handshake, get synchronizer info, register onboarding topology transactions
- **SequencerAuthenticationService**: Challenge-response authentication flow  
- **SequencerService**: Get traffic state, sequencing time, and subscribe to events
- **Topology Transactions**: Create and sign topology transactions for participant onboarding
- **Member ID Generation**: Create participant, mediator, or sequencer IDs from signing keys
- **Ed25519 signing support** via `ed25519-dalek`
- **Protocol Version Constants**: Use the correct Canton protocol version automatically
- Type-safe protobuf message definitions
- TLS support via tonic

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
canton-sequencer-client = { path = "path/to/canton-sequencer-client" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Complete Example: Onboarding, Connect, Authenticate, and Get Traffic State

```rust
use canton_sequencer_client::{
    SequencerConnectClient, SequencerAuthClient, SequencerServiceClient,
    signing::Ed25519Signer, topology::TopologyTransactionBuilder, Member
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Generate a signing key and create a participant ID
    let signer = Ed25519Signer::generate();
    let participant_id = signer.participant_id("myparticipant")?;
    println!("Participant ID: {}", participant_id);

    // Step 2: Connect and perform handshake
    let mut connect_client = SequencerConnectClient::connect("http://localhost:5001").await?;
    let handshake = connect_client.handshake().await?;
    println!("Server protocol version: {}", handshake.server_protocol_version);

    // Get synchronizer info
    let sync_info = connect_client.get_synchronizer_id().await?;
    println!("Synchronizer ID: {}", sync_info.physical_synchronizer_id);
    println!("Sequencer UID: {}", sync_info.sequencer_uid);

    // Step 3: Register onboarding topology transactions
    let builder = TopologyTransactionBuilder::new(&signer);
    let transactions = builder.onboarding_transactions(
        &participant_id,
        &sync_info.physical_synchronizer_id
    );
    connect_client.register_onboarding_topology_transactions(transactions).await?;
    println!("Topology transactions registered");

    // Step 4: Authenticate with challenge-response
    let mut auth_client = SequencerAuthClient::connect("http://localhost:5001").await?;
    let challenge = auth_client.challenge(&participant_id).await?;
    let signature = signer.sign_nonce(&challenge.nonce);
    let token = auth_client.authenticate(&participant_id, signature, challenge.nonce).await?;
    println!("Authenticated! Token expires at: {:?}", token.expires_at);

    // Step 5: Use the SequencerService (requires authentication)
    let mut service_client = SequencerServiceClient::connect("http://localhost:5001").await?;
    
    // Get current sequencing time
    if let Some(time) = service_client.get_time().await? {
        println!("Current sequencing time: {}", time);
    }
    
    // Get traffic state for the member
    if let Some(traffic) = service_client.get_traffic_state(&participant_id, 0).await? {
        println!("Traffic state: {:?}", traffic);
    }

    // Step 6: Logout when done
    auth_client.logout(token.token).await?;
    
    Ok(())
}
```

### Topology Transactions (Participant Onboarding)

Before a participant can authenticate, it must register its topology transactions.
Use `TopologyTransactionBuilder` to create the required transactions:

```rust
use canton_sequencer_client::{
    SequencerConnectClient, signing::Ed25519Signer,
    topology::TopologyTransactionBuilder
};

let signer = Ed25519Signer::generate();
let participant_id = signer.participant_id("myparticipant")?;

// Create topology transaction builder
let builder = TopologyTransactionBuilder::new(&signer);

// Option 1: Create all onboarding transactions at once
let transactions = builder.onboarding_transactions(&participant_id, "synchronizer::abc123");

// Option 2: Create individual transactions
let nsd = builder.namespace_delegation_root();           // Root cert for namespace
let otk = builder.owner_to_key_mapping(&participant_id); // Map participant to key
let stc = builder.synchronizer_trust_certificate(        // Trust the synchronizer
    &participant_id, "synchronizer::abc123"
);

// Sign and submit
let signed_nsd = builder.sign(nsd);
let signed_otk = builder.sign(otk);
let signed_stc = builder.sign(stc);

// Register with sequencer
let mut client = SequencerConnectClient::connect("http://localhost:5001").await?;
client.register_onboarding_topology_transactions(
    vec![signed_nsd, signed_otk, signed_stc]
).await?;
```

The three required topology transactions for onboarding are:
1. **NamespaceDelegation**: Establishes the signing key as the root authority for the participant's namespace
2. **OwnerToKeyMapping**: Maps the participant to its signing/protocol keys
3. **SynchronizerTrustCertificate**: Declares that the participant trusts the synchronizer

### SequencerConnectService (Before Authentication)

Use `SequencerConnectClient` for initial connection and registration:

```rust
use canton_sequencer_client::SequencerConnectClient;

let mut client = SequencerConnectClient::connect("http://localhost:5001").await?;

// Perform protocol version handshake
let handshake = client.handshake().await?;

// Get synchronizer ID and sequencer UID
let sync_info = client.get_synchronizer_id().await?;

// Get static synchronizer parameters (crypto specs, etc.)
let params = client.get_synchronizer_parameters().await?;

// Verify the sequencer is active
let active_response = client.verify_active().await?;
```

### SequencerService (After Authentication)

Use `SequencerServiceClient` to access sequencer operations:

```rust
use canton_sequencer_client::SequencerServiceClient;

let mut client = SequencerServiceClient::connect("http://localhost:5001").await?;

// Get traffic state for a member at a specific timestamp
let traffic_state = client.get_traffic_state(&participant_id, timestamp_micros).await?;

// Get current sequencing time
let sequencing_time = client.get_time().await?;

// For advanced operations (subscribe, send), access the inner client
let inner = client.inner();
```

### Protocol Versions

The client automatically uses the latest stable protocol version (v34) when calling `challenge()` or `handshake()`.
If you need to specify a different version:

```rust
use canton_sequencer_client::{SequencerConnectClient, ProtocolVersion};

// Use the default (latest stable version v34)
let handshake = client.handshake().await?;

// Or specify custom versions
let handshake = client.handshake_with_versions(
    vec![ProtocolVersion::V34.as_i32()],
    Some(ProtocolVersion::V34.as_i32())  // minimum version
).await?;
```

### Member ID Generation

Member IDs follow the Canton format: `<CODE>::<identifier>::<fingerprint>`

```rust
use canton_sequencer_client::signing::Ed25519Signer;
use canton_sequencer_client::member::{ParticipantId, MediatorId, SequencerId, Member};

// Generate a signing key
let signer = Ed25519Signer::generate();

// Create different member types using the key
let participant = signer.participant_id("myparticipant").unwrap();
// -> PAR::myparticipant::abc123def...

let mediator = signer.mediator_id("mymediator").unwrap();
// -> MED::mymediator::abc123def...

let sequencer = signer.sequencer_id("mysequencer").unwrap();
// -> SEQ::mysequencer::abc123def...

// Or create manually
let pid = ParticipantId::create("manual", "abc123def456").unwrap();

// Parse from string
let parsed = ParticipantId::from_proto_primitive("PAR::node::abc123").unwrap();
```

### Key Management

```rust
use canton_sequencer_client::signing::Ed25519Signer;

// Generate a new random key pair
let signer = Ed25519Signer::generate();

// Get key fingerprint (SHA-256 hash of public key, hex-encoded)
let fingerprint = signer.fingerprint();

// Export secret key bytes (handle with care!)
let secret_bytes = signer.secret_key_bytes();

// Import from existing secret key bytes
let signer2 = Ed25519Signer::from_secret_key(&secret_bytes).unwrap();

// Get public key bytes
let public_key = signer.public_key_bytes();
```

## Connection Flow

The typical flow for connecting to a Canton sequencer:

1. **Connect & Handshake** (`SequencerConnectClient`): Verify protocol compatibility
2. **Get Synchronizer Info**: Retrieve synchronizer ID and parameters
3. **Register Topology Transactions** (`TopologyTransactionBuilder`): Submit onboarding topology
4. **Authenticate** (`SequencerAuthClient`): Challenge-response to get token
5. **Use Sequencer** (`SequencerServiceClient`): Get traffic state, subscribe, etc.
6. **Logout**: Revoke authentication token when done

## API Reference

### `SequencerConnectClient`

Client for initial connection and registration (before authentication).

#### Methods

- `connect(endpoint)` - Connect to a sequencer endpoint
- `handshake()` - Perform protocol version handshake with default version
- `handshake_with_versions(versions, min_version)` - Handshake with custom versions
- `get_synchronizer_id()` - Get synchronizer ID and sequencer UID
- `get_synchronizer_parameters()` - Get static synchronizer parameters
- `verify_active()` - Verify the sequencer is active
- `register_onboarding_topology_transactions(transactions)` - Register topology transactions for onboarding

### `SequencerAuthClient`

Client for challenge-response authentication.

#### Methods

- `connect(endpoint)` - Connect to a sequencer endpoint
- `challenge(member)` - Request challenge with latest stable protocol version
- `challenge_with_versions(member, versions)` - Request challenge with custom versions
- `authenticate(member, signature, nonce)` - Authenticate with signed nonce
- `logout(token)` - Revoke authentication token

### `SequencerServiceClient`

Client for sequencer operations (requires authentication).

#### Methods

- `connect(endpoint)` - Connect to a sequencer endpoint
- `get_traffic_state(member, timestamp)` - Get traffic state for a member
- `get_time()` - Get current sequencing time
- `inner()` - Access inner gRPC client for advanced operations

### `TopologyTransactionBuilder`

Builder for creating and signing topology transactions for participant onboarding.

#### Methods

- `new(signer)` - Create a builder with the given Ed25519 signer
- `namespace()` - Get the namespace (key fingerprint)
- `namespace_delegation_root()` - Create root namespace delegation transaction
- `owner_to_key_mapping(member)` - Create owner-to-key mapping transaction
- `synchronizer_trust_certificate(member, sync_id)` - Create synchronizer trust certificate
- `sign(transaction)` - Sign a topology transaction
- `sign_as_proposal(transaction)` - Sign as a proposal (not fully authorized)
- `onboarding_transactions(member, sync_id)` - Create all onboarding transactions at once

### Protocol Version Constants

- `LATEST_STABLE_VERSION` - The latest stable protocol version (v34)
- `MINIMUM_STABLE_VERSION` - The minimum supported stable version (v34)
- `ProtocolVersion::V34` - Protocol version 34 (stable)
- `ProtocolVersion::V35` - Protocol version 35 (alpha)

### `Ed25519Signer`

Ed25519 signing key for authentication.

#### Methods

- `generate()` - Generate a new random key pair
- `from_secret_key(bytes)` - Create from secret key bytes
- `sign_nonce(nonce)` - Sign a nonce and return Canton-compatible Signature
- `fingerprint()` - Get hex-encoded SHA-256 fingerprint of public key
- `participant_id(name)` - Create a ParticipantId
- `mediator_id(name)` - Create a MediatorId
- `sequencer_id(name)` - Create a SequencerId
- `public_key_bytes()` - Get raw public key bytes
- `secret_key_bytes()` - Get raw secret key bytes
- `verify(message, signature)` - Verify a signature

### Member Types

- `ParticipantId` - A participant identifier (code: `PAR`)
- `MediatorId` - A mediator identifier (code: `MED`)
- `SequencerId` - A sequencer identifier (code: `SEQ`)
- `UniqueIdentifier` - Base identifier with `identifier::fingerprint` format
- `Member` trait - Common interface for all member types

### Topology Transaction Types

- `SignedTopologyTransaction` - A signed topology transaction
- `TopologyTransaction` - An unsigned topology transaction
- `NamespaceDelegation` - Delegates authority over a namespace
- `OwnerToKeyMapping` - Maps a member to their keys
- `SynchronizerTrustCertificate` - Trust declaration for a synchronizer

### Other Types

- `SynchronizerInfo` - Synchronizer ID and sequencer UID
- `TrafficState` - Traffic control state for a member
- `Signature` - Cryptographic signature with format, algorithm, and optional delegation
- `AuthToken` - Authentication token with expiration time
- `HandshakeRequest/Response` - Protocol handshake messages
- `ChallengeRequest/Response` - Challenge flow messages

## Building from Source

Requirements:
- Rust 1.75 or later
- Protocol Buffers compiler (`protoc`)

```bash
cd rust/canton-sequencer-client
cargo build
cargo test
```

## License

Apache-2.0
