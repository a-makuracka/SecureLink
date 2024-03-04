use std::io::{Read, Write};
use rustls::{ClientConnection, RootCertStore, ServerConnection, StreamOwned};
use std::convert::TryInto;
use std::sync::Arc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;


pub struct SecureClient<L: Read + Write> {
    secure_link: StreamOwned<ClientConnection, L>,
    hmac_key: Vec<u8>,
}


pub struct SecureServer<L: Read + Write> {
    secure_link: StreamOwned<ServerConnection, L>,
    hmac_key: Vec<u8>,
}


fn calculate_hmac_tag(data: &[u8], secret_key: &[u8]) -> [u8; 32] {
    // Initialize a new MAC instance from the secret key:
    let mut mac = HmacSha256::new_from_slice(secret_key).unwrap();

    // Calculate MAC for the data (one can provide it in multiple portions):
    mac.update(data);

    // Finalize the computations of MAC and obtain the resulting tag:
    let tag = mac.finalize().into_bytes();

    tag.into()
}


fn verify_hmac_tag(tag: &[u8], message: &[u8], secret_key: &[u8]) -> bool {
    // Initialize a new MAC instance from the secret key:
    let mut mac = HmacSha256::new_from_slice(secret_key).unwrap();

    // Calculate MAC for the data (one can provide it in multiple portions):
    mac.update(message);

    // Verify the tag:
    mac.verify_slice(tag).is_ok()
}


fn client_stream<L: Read + Write>(stream: L, root_cert: &str) -> StreamOwned<ClientConnection, L> {
    // Create an empty store for root certificates:
    let mut root_store = RootCertStore::empty();

    // Add to the store the root certificate of the server:
    root_store.add_parsable_certificates(
        &rustls_pemfile::certs(&mut root_cert.as_bytes()).unwrap(),
    );

    // Create a TLS configuration for the client:
    let client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .clone(); // Clone to avoid ownership issues

    // Create a TLS connection using the configuration prepared above:
    let connection = ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
        .unwrap();

    // Wrap the stream in TLS:
    StreamOwned::new(connection, stream)
}


// Wrap `TcpStream` of a server in TLS. Writing to/reading from the new stream
// will automatically apply TLS to the outgoing/incoming data:
fn server_stream<L: Read + Write>(stream: L, s_pv_key: &str, s_full_chain: &str) -> StreamOwned<ServerConnection, L> {
    // Load the certificate chain for the server:
    let certs = rustls_pemfile::certs(&mut s_full_chain.as_bytes())
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect();

    // Load the private key for the server:
    let private_key = rustls::PrivateKey(
        rustls_pemfile::rsa_private_keys(&mut s_pv_key.as_bytes())
            .unwrap()
            .first()
            .unwrap()
            .to_vec(),
    );

    // Create a TLS configuration for the server:
    let server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap();

    // Create a TLS connection using the configuration prepared above:
    let connection = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();

    // Wrap the TCP strem in TLS:
    rustls::StreamOwned::new(connection, stream)
}


impl<L: Read + Write> SecureClient<L> {
    /// Creates a new instance of SecureClient.
    ///
    /// SecureClient communicates with SecureServer via `link`.
    /// The messages include a HMAC tag calculated using `hmac_key`.
    /// A certificate of SecureServer is signed by `root_cert`.
    pub fn new(link: L, hmac_key: &[u8], root_cert: &str) -> Self {
        SecureClient {
            secure_link: client_stream(link, root_cert),
            hmac_key: hmac_key.to_vec(),
        }
    }

    /// Sends the data to the server. The sent message follows the
    /// format specified in the description of the assignment.
    pub fn send_msg(&mut self, data: Vec<u8>) {
        let content_length = data.len() as u32;
        let length_bytes = content_length.to_be_bytes();

        let hmac_key_cloned = self.hmac_key.clone();
        let hmac_tag = calculate_hmac_tag(&data, &hmac_key_cloned);
        
        // Create a formatted message.
        let mut message = Vec::new();
        message.extend_from_slice(&length_bytes);
        message.extend_from_slice(&data);
        message.extend_from_slice(&hmac_tag);

        // Encrypt the message using TLS.
        let _ = self.secure_link.write(&message);
    }
}


/// Transforms vector into array.
pub fn into_arr<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}


impl<L: Read + Write> SecureServer<L> {
    /// Creates a new instance of SecureServer.
    ///
    /// SecureServer receives messages from SecureClients via `link`.
    /// HMAC tags of the messages are verified against `hmac_key`.
    /// The private key of the SecureServer's certificate is `server_private_key`,
    /// and the full certificate chain is `server_full_chain`.
    pub fn new(
        link: L,
        hmac_key: &[u8],
        server_private_key: &str,
        server_full_chain: &str,
    ) -> Self {
        SecureServer {
            secure_link: server_stream(link, server_private_key, server_full_chain),
            hmac_key: hmac_key.to_vec(),
        }
    }

    /// Receives the next incoming message and returns the message's content
    /// (i.e., without the message size and without the HMAC tag) if the
    /// message's HMAC tag is correct. Otherwise returns `SecureServerError`.
    pub fn recv_message(&mut self) -> Result<Vec<u8>, SecureServerError> {
        // Read first 4 bytes (to check the length of a message).
        let mut length_as_bytes = vec![0; 4];
        self.secure_link.read_exact(length_as_bytes.as_mut()).unwrap();
        let length = u32::from_be_bytes(into_arr(length_as_bytes)) as usize;

        // Read the message.
        let mut message = vec![0; length];
        self.secure_link.read_exact(message.as_mut()).unwrap();

        // Read the HMAC tag.
        let mut hmac_tag = vec![0; 32];
        self.secure_link.read_exact(hmac_tag.as_mut()).unwrap();

        // Verify the HMAC tag.
        if !verify_hmac_tag(&hmac_tag, &message, &self.hmac_key) {
            return Err(SecureServerError::InvalidHmac);
        }

        Ok(message)
    }
}


#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum SecureServerError {
    /// The HMAC tag of a message is invalid.
    InvalidHmac,
}
