# Canton Sequencer Client (Rust)

A Rust gRPC client for the Canton Sequencer Authentication Service, built with [tonic](https://github.com/hyperium/tonic).

## Features

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

### Example

```rust
use canton_sequencer_client::{
    SequencerAuthClient, AuthToken, Signature, SignatureFormat, SigningAlgorithmSpec
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Connect to the sequencer
    let mut client = SequencerAuthClient::connect("http://localhost:5001").await?;

    // Step 2: Request a challenge
    let challenge = client.challenge("my-member-id", vec![30]).await?;
    println!("Received nonce: {:?}", challenge.nonce);
    println!("Valid key fingerprints: {:?}", challenge.fingerprints);

    // Step 3: Sign the nonce (you need to implement your signing logic)
    let signature = Signature {
        format: SignatureFormat::Der as i32,
        signature: sign_nonce(&challenge.nonce), // Your signing implementation
        signed_by: "your-key-fingerprint".to_string(),
        signing_algorithm_spec: SigningAlgorithmSpec::Ed25519 as i32,
        signature_delegation: None,
    };

    // Step 4: Authenticate with the signed nonce
    let token = client.authenticate("my-member-id", signature, challenge.nonce).await?;
    println!("Authentication token received, expires at: {:?}", token.expires_at);

    // Step 5: Use the token for subsequent requests...

    // Step 6: Logout when done
    client.logout(token.token).await?;
    
    Ok(())
}

fn sign_nonce(nonce: &[u8]) -> Vec<u8> {
    // Implement your signing logic here
    // This depends on your cryptographic library of choice (e.g., ring, ed25519-dalek)
    unimplemented!()
}
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
