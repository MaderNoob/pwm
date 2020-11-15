use chacha20poly1305::{
    aead::{AeadInPlace, NewAead},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::ThreadRng, RngCore};
use sha2::{Digest, Sha256};
pub struct Encryptor {
    chacha: ChaCha20Poly1305,
    nonce: Nonce,
}
impl Encryptor {
    pub fn new(key: &str, thread_random: &mut ThreadRng) -> Encryptor {
        let mut key_hasher = Sha256::new();
        key_hasher.update(key);
        let key = key_hasher.finalize();
        let mut nonce = Nonce::default();
        thread_random.fill_bytes(&mut nonce);
        Encryptor {
            chacha: ChaCha20Poly1305::new(&key),
            nonce,
        }
    }
    pub fn nonce<'a>(&'a self) -> &'a Nonce {
        &self.nonce
    }
    pub fn mut_nonce<'a>(&'a mut self) -> &'a mut Nonce {
        &mut self.nonce
    }
    pub fn encrypt(&mut self, buf: &mut [u8]) -> Vec<u8> {
        let mut cipher_buf = vec![0u8; buf.len() + 12];
        self.chacha
            .encrypt_in_place(&self.nonce, buf, &mut cipher_buf)
            .unwrap();
        cipher_buf
    }
}
pub struct Decryptor {
    chacha: ChaCha20Poly1305,
    nonce: Nonce,
}
impl Decryptor {
    pub fn new(key: &str, nonce: Nonce) -> Decryptor {
        let mut key_hasher = Sha256::new();
        key_hasher.update(key);
        let key = key_hasher.finalize();
        Decryptor {
            chacha: ChaCha20Poly1305::new(&key),
            nonce,
        }
    }
    pub fn nonce<'a>(&'a self) -> &'a Nonce {
        &self.nonce
    }
    pub fn mut_nonce<'a>(&'a mut self) -> &'a mut Nonce {
        &mut self.nonce
    }
    pub fn decrypt(&mut self, buf: &mut [u8]) -> Option<Vec<u8>> {
        if buf.len() < 12 {
            return None;
        }
        let mut plaintext_buf = vec![0u8; buf.len() - 12];
        match self
            .chacha
            .decrypt_in_place(&self.nonce, buf, &mut plaintext_buf)
        {
            Ok(()) => Some(plaintext_buf),
            Err(_) => None,
        }
    }
}
impl From<Encryptor> for Decryptor {
    fn from(e: Encryptor) -> Self {
        Decryptor {
            chacha: e.chacha,
            nonce: e.nonce,
        }
    }
}
impl From<Decryptor> for Encryptor {
    fn from(d: Decryptor) -> Self {
        Encryptor {
            chacha: d.chacha,
            nonce: d.nonce,
        }
    }
}
