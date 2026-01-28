# Canton Sequencer Client (Rust)

A Rust gRPC client for the Canton Sequencer Authentication Service, built with [tonic](https://github.com/hyperium/tonic).

## Features

- **Member ID Generation**: Create participant, mediator, or sequencer IDs from signing keys
- **Ed25519 signing support** via `ed25519-dalek`
- Full gRPC client for `SequencerAuthenticationService`
- Challenge-response authentication flow
- Type-safe protobuf message definitions
- TLS support via tonic

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
canton-sequencer-client = { path = "path/to/canton-sequencer-client" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Complete Example: Generate Participant ID and Authenticate

```rust
use canton_sequencer_client::{
    SequencerAuthClient, signing::Ed25519Signer, member::Member, ParticipantId
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Generate an Ed25519 signing key
    let signer = Ed25519Signer::generate();
    println!("Key fingerprint: {}", signer.fingerprint());

    // Step 2: Create a Participant ID using the key's fingerprint as namespace
    // Format: PAR::myparticipant::<fingerprint>
    let participant_id = signer.participant_id("myparticipant")?;
    println!("Participant ID: {}", participant_id.to_proto_primitive());

    // Step 3: Connect to the sequencer
    let mut client = SequencerAuthClient::connect("http://localhost:5001").await?;

    // Step 4: Request a challenge
    let member_str = participant_id.to_proto_primitive();
    let challenge = client.challenge(&member_str, vec![30]).await?;

    // Step 5: Sign the nonce with Ed25519
    let signature = signer.sign_nonce(&challenge.nonce);

    // Step 6: Authenticate with the signed nonce
    let token = client.authenticate(&member_str, signature, challenge.nonce).await?;
    println!("Authenticated! Token expires at: {:?}", token.expires_at);

    // Step 7: Logout when done
    client.logout(token.token).await?;
    
    Ok(())
}
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

## Authentication Flow

The authentication with Canton Sequencer follows a challenge-response pattern:

1. **Generate Key**: Create or load an Ed25519 signing key
2. **Create Member ID**: Generate a participant/mediator/sequencer ID using the key's fingerprint
3. **Challenge**: Request a nonce from the sequencer with your member ID
4. **Sign**: Sign the nonce with your Ed25519 key
5. **Authenticate**: Submit the signed nonce to receive an authentication token
6. **Use Token**: The token is used in subsequent sequencer operations
7. **Logout**: When done, revoke your authentication token

## API Reference

### `SequencerAuthClient`

The main client struct for interacting with the sequencer.

#### Methods

- `connect(endpoint: &str) -> Result<Self, Error>` - Connect to a sequencer endpoint
- `from_channel(channel: Channel) -> Self` - Create client from existing channel
- `challenge(member: &str, versions: Vec<i32>) -> Result<ChallengeResponse, Status>` - Request authentication challenge
- `authenticate(member: &str, signature: Signature, nonce: Vec<u8>) -> Result<AuthToken, Status>` - Authenticate with signed nonce
- `logout(token: Vec<u8>) -> Result<LogoutResponse, Status>` - Revoke authentication token

### `Ed25519Signer`

Ed25519 signing key for authentication.

#### Methods

- `generate() -> Self` - Generate a new random key pair
- `from_secret_key(bytes: &[u8; 32]) -> Result<Self, SigningError>` - Create from secret key bytes
- `sign_nonce(nonce: &[u8]) -> Signature` - Sign a nonce and return Canton-compatible Signature
- `fingerprint() -> String` - Get hex-encoded SHA-256 fingerprint of public key
- `participant_id(name: &str) -> Result<ParticipantId, MemberError>` - Create a ParticipantId
- `mediator_id(name: &str) -> Result<MediatorId, MemberError>` - Create a MediatorId
- `sequencer_id(name: &str) -> Result<SequencerId, MemberError>` - Create a SequencerId
- `public_key_bytes() -> [u8; 32]` - Get raw public key bytes
- `secret_key_bytes() -> [u8; 32]` - Get raw secret key bytes
- `verify(message: &[u8], signature: &[u8; 64]) -> bool` - Verify a signature

### Member Types

- `ParticipantId` - A participant identifier (code: `PAR`)
- `MediatorId` - A mediator identifier (code: `MED`)
- `SequencerId` - A sequencer identifier (code: `SEQ`)
- `UniqueIdentifier` - Base identifier with `identifier::fingerprint` format
- `Member` trait - Common interface for all member types

### Other Types

- `Signature` - Cryptographic signature with format, algorithm, and optional delegation
- `SignatureFormat` - Enum for signature formats (Raw, DER, Concat, Symbolic)
- `SigningAlgorithmSpec` - Enum for signing algorithms (Ed25519, ECDSA-SHA256, ECDSA-SHA384)
- `AuthToken` - Authentication token with expiration time
- `ChallengeRequest/Response` - Challenge flow messages
- `AuthenticateRequest/Response` - Authentication flow messages
- `LogoutRequest/Response` - Logout flow messages

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
