# Canton Sequencer Client (Rust)

A Rust gRPC client for the Canton Sequencer Authentication Service, built with [tonic](https://github.com/hyperium/tonic).

## Features

- Full gRPC client for `SequencerAuthenticationService`
- Challenge-response authentication flow
- **Ed25519 signing support** via `ed25519-dalek`
- Type-safe protobuf message definitions
- TLS support via tonic

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
canton-sequencer-client = { path = "path/to/canton-sequencer-client" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Example with Ed25519 Signing

```rust
use canton_sequencer_client::{SequencerAuthClient, signing::Ed25519Signer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Generate or load an Ed25519 signing key
    let signer = Ed25519Signer::generate();
    println!("Key fingerprint: {}", signer.fingerprint());

    // Step 2: Connect to the sequencer
    let mut client = SequencerAuthClient::connect("http://localhost:5001").await?;

    // Step 3: Request a challenge
    let challenge = client.challenge("my-member-id", vec![30]).await?;
    println!("Received nonce: {:?}", challenge.nonce);

    // Step 4: Sign the nonce with Ed25519
    let signature = signer.sign_nonce(&challenge.nonce);

    // Step 5: Authenticate with the signed nonce
    let token = client.authenticate("my-member-id", signature, challenge.nonce).await?;
    println!("Authentication token received, expires at: {:?}", token.expires_at);

    // Step 6: Use the token for subsequent requests...

    // Step 7: Logout when done
    client.logout(token.token).await?;
    
    Ok(())
}
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

1. **Challenge**: Client requests a nonce from the sequencer, providing its member ID and supported protocol versions.

2. **Sign**: Client signs the nonce using a valid signing key. The sequencer provides hints about which key fingerprints it considers valid.

3. **Authenticate**: Client submits the signed nonce to receive an authentication token with an expiration time.

4. **Use Token**: The authentication token is used in subsequent sequencer operations.

5. **Logout**: When done, the client can revoke its authentication token.

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
- `public_key_bytes() -> [u8; 32]` - Get raw public key bytes
- `secret_key_bytes() -> [u8; 32]` - Get raw secret key bytes
- `verify(message: &[u8], signature: &[u8; 64]) -> bool` - Verify a signature

### Types

- `Signature` - Cryptographic signature with format, algorithm, and optional delegation
- `SignatureFormat` - Enum for signature formats (Raw, DER, Concat, Symbolic)
- `SigningAlgorithmSpec` - Enum for signing algorithms (Ed25519, ECDSA-SHA256, ECDSA-SHA384)
- `SigningKeySpec` - Enum for signing key types (Curve25519, P-256, P-384, secp256k1)
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
