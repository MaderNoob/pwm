use crate::locker::errors::{Error, Result};
use chacha20poly1305::Nonce;
use generic_array::GenericArray;
use sha2::{Digest, Sha512};
use std::fs::File;
use std::io::{BufReader, Read};
pub type Sha512Digest = GenericArray<u8, <Sha512 as Digest>::OutputSize>;
pub const SALT_LENGTH:usize=16;
pub struct EncryptionHeaders {
    pub salted_key_hash: Sha512Digest,
    pub nonce: Nonce,
    pub salt: [u8;SALT_LENGTH],
}
impl EncryptionHeaders {
    fn new() -> EncryptionHeaders {
        EncryptionHeaders {
            salted_key_hash: Sha512Digest::default(),
            nonce: Nonce::default(),
            salt: [0u8;SALT_LENGTH],
        }
    }
    pub fn read(reader: &mut BufReader<File>) -> Result<EncryptionHeaders> {
            fn read_with_io_error(
                reader: &mut BufReader<File>,
                headers: &mut EncryptionHeaders,
            ) -> std::io::Result<()> {
            reader.read_exact(&mut headers.salted_key_hash)?;
            reader.read_exact(&mut headers.nonce)?;
            reader.read_exact(&mut headers.salt)
        }
        let mut headers=EncryptionHeaders::new();
        match read_with_io_error(reader,&mut headers){
            Ok(())=>Ok(headers),
            Err(_)=>Err(Error::FileNotEncryptedProperly)
        }
    }
}
