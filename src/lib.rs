use std::collections::HashMap;
use std::error::Error;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use jwt::algorithm::openssl::PKeyWithDigest;
use jwt::SigningAlgorithm;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;

use token::Header;

use crate::token::{AccessTokenResponse, aud, Payload};

mod token;

pub async fn acquire_token(tenant_id: String, client_id: String, scope: String, private_key_pem: &Vec<u8>, public_key_pem: &Vec<u8>) -> Result<AccessTokenResponse, Box<dyn Error>> {
    let algorithm = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: PKey::private_key_from_pem(&private_key_pem)?,
    };

    let header = Header::new(&public_key_pem)?;
    let payload = Payload::new(tenant_id.to_owned(), client_id.to_string());
    let header_json = serde_json::json!(header);
    let payload_json = serde_json::json!(payload);

    let header_base64 = BASE64_STANDARD.encode(header_json.to_string());
    let payload_base64 = BASE64_STANDARD.encode(payload_json.to_string());
    let result = algorithm.sign(&header_base64, &payload_base64).unwrap();
    let client_assertion = format!("{}.{}.{}", header_base64, payload_base64, result);

    let client = reqwest::Client::new();
    let mut params = HashMap::new();
    params.insert("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    params.insert("grant_type", "client_credentials");
    let all_scope = format!("openid profile offline_access {}", scope);
    params.insert("scope", &all_scope);
    params.insert("client_assertion", &client_assertion);
    params.insert("client_id", &client_id);

    let res = client.post(aud(tenant_id.to_owned()))
        .form(&params)
        .send()
        .await?;

    let body_text = match res.text().await {
        Ok(text) => text,
        Err(e) => {
            return Err(e.into());
        }
    };

    let x: Result<AccessTokenResponse, _> = serde_json::from_str(&body_text);

    let ret = match x {
        Ok(token_response) => {
            Ok(token_response)
        }
        Err(e) => {
            println!("Error while parsing JSON: {}. Response text: {}", e, body_text);
            Err(e.into())
        }
    };
    ret
}

#[cfg(test)]
mod tests {
    use tokio;
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_acquire_token() -> Result<(), Box<dyn Error>> {
        // Setup test data
        let tenant_id = "72f988bf-86f1-41af-91ab-2d7cd011db47".to_string();
        let client_id = "064b969a-ed15-42fa-9044-f08081163a67".to_string();
        let scope = "https://graph.microsoft.com/.default".to_string();
        let private_key_pem = include_bytes!("../keys/private_key.pem").to_vec(); // Update with the correct path to your private key
        let public_key_pem = include_bytes!("../keys/public_key.pem").to_vec(); // Update with the correct path to your public key

        // Call the acquire_token function
        let token_response = acquire_token(tenant_id, client_id, scope, &private_key_pem, &public_key_pem).await?;

        // Validate the response
        assert_eq!(token_response.token_type, "Bearer");
        assert!(token_response.expires_in > 0);
        assert!(token_response.access_token.len() > 0);
        Ok(())
    }
}
