# `msal-cert`

`msal-cert` is a Rust library for handling Microsoft Authentication Library (MSAL) certificates. It provides functionality for generating JWT tokens signed with a certificate, and acquiring access tokens from Azure Active Directory using client credentials.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [License](#license)

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
msal-cert = "0.1.0"
```

## Usage

### Generating a JWT Token

You can generate a JWT token using your public and private keys.

```rust
use msal_cert::token::{Header, Payload};
use msal_cert::lib::acquire_token;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Your tenant ID and client ID
    let tenant_id = "your_tenant_id".to_string();
    let client_id = "your_client_id".to_string();
    let scope = "your_scope".to_string();

    // Load your private and public key PEM files
    let private_key_pem = include_bytes!("../keys/private_key.pem").to_vec(); // Update with path to your private key
    let public_key_pem = include_bytes!("../keys/public_key.pem").to_vec(); // Update with path to your public key

    // Acquire token
    let token_response = acquire_token(tenant_id, client_id, scope, &private_key_pem, &public_key_pem).await?;

    println!("Access Token: {}", token_response.access_token);

    Ok(())
}
```

### Defining the Header and Payload

The `Header` and `Payload` structs are provided to facilitate JWT token creation:

```rust
use msal_cert::token::{Header, Payload};

// Initialize Header
let public_key_pem = include_bytes!("../keys/public_key.pem").to_vec();
let header = Header::new(&public_key_pem)?;

// Initialize Payload
let tenant_id = "your_tenant_id".to_string();
let client_id = "your_client_id".to_string();
let payload = Payload::new(tenant_id.clone(), client_id.clone());
```

## Testing

Run tests using the following command:

```sh
cargo test
```

Note: Ensure that you have your key files in the correct paths specified in the test functions.

```rust
#[tokio::test]
#[ignore]
async fn test_acquire_token() -> Result<(), Box<dyn std::error::Error>> {
    let tenant_id = "your_tenant_id".to_string();
    let client_id = "your_client_id".to_string();
    let scope = "your_scope".to_string();
    let private_key_pem = include_bytes!("../keys/private_key.pem").to_vec();
    let public_key_pem = include_bytes!("../keys/public_key.pem").to_vec();

    let token_response = acquire_token(tenant_id, client_id, scope, &private_key_pem, &public_key_pem).await?;

    assert_eq!(token_response.token_type, "Bearer");
    assert!(token_response.expires_in > 0);
    assert!(token_response.access_token.len() > 0);
    Ok(())
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](https://opensource.org/licenses/MIT) file for more details.
