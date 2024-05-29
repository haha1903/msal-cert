use std::error::Error;
use std::time::SystemTime;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use openssl::hash::{hash, MessageDigest};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

pub fn aud(tenant_id: String) -> String {
    format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant_id)
}

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Header {
    x5t: String,
    alg: String,
    x5c: Vec<String>,
}

impl Header {
    pub fn new(public_key_pem: &[u8]) -> Result<Self, Box<dyn Error>> {
        let cert_pem = Self::calc_pem(public_key_pem)?;
        let x5t = Self::calc_x5t(cert_pem.clone())?;

        Ok(Self {
            alg: String::from("RS256"),
            x5t,
            x5c: vec![cert_pem],
        })
    }
    fn calc_x5t(public_key_pem: String) -> Result<String, Box<dyn Error>> {
        let data = BASE64_STANDARD.decode(public_key_pem)?;
        let hash = hash(MessageDigest::sha1(), &data)?;
        let x5t = BASE64_STANDARD.encode(&hash);
        // let x5t: String = hash.iter().map(|&x| format!("{:02X}", x)).collect();
        Ok(x5t)
    }

    fn calc_pem(public_key_pem: &[u8]) -> Result<String, Box<dyn Error>> {
        let pem = X509::from_pem(public_key_pem)?.to_pem()?;
        Ok(String::from_utf8(pem)?.replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\n", "")
            .trim().to_owned())
    }
}

#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Payload {
    iss: String,
    aud: String,
    sub: String,
    nbf: u64,
    exp: u64,
    jti: String,
}

impl Payload {
    pub fn new(tenant_id: String, client_id: String) -> Self {
        let issued_at = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let expiration_time = issued_at + 600;
        Self {
            iss: client_id.to_owned(),
            aud: aud(tenant_id),
            sub: client_id,
            nbf: issued_at,
            exp: expiration_time,
            jti: uuid::Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenResponse {
    pub token_type: String,
    pub expires_in: u64,
    pub ext_expires_in: u64,
    pub access_token: String,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_header_new() -> Result<(), Box<dyn Error>> {
        let public_key_pem = include_bytes!("../../keys/public_key.pem").to_vec(); // Update with the correct path to your public key
        let header = Header::new(&public_key_pem)?;

        assert_eq!(header.alg, "RS256");
        assert_eq!(header.x5c.len(), 1);
        assert!(header.x5t.len() > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_payload_new() {
        let tenant_id = "your_tenant_id".to_string();
        let client_id = "your_client_id".to_string();

        let payload = Payload::new(tenant_id.clone(), client_id.clone());

        assert_eq!(payload.iss, client_id);
        assert!(payload.aud.contains(&tenant_id));
        assert_eq!(payload.sub, client_id);
        assert!(payload.exp > payload.nbf);
        assert!(payload.jti.len() > 0);
    }
}
