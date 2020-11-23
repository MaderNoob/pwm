use crate::locker::errors::{Error, Result,map_to_locker_error};
use crate::locker::vec_reader::VecReader;
use chacha20::{ChaCha20,Nonce,cipher::NewStreamCipher};
use generic_array::GenericArray;
use sha2::{Digest, Sha512};
use generic_array::typenum::Unsigned;
use std::fs::File;
use std::io::Read;
use rand::{thread_rng,Rng,RngCore};

pub type Sha512Digest = GenericArray<u8, <Sha512 as Digest>::OutputSize>;
pub const SALT_LENGTH:usize=16;
pub const ENCRYPTION_HEADERS_SIZE:usize=
    SALT_LENGTH + 
    <Sha512 as Digest>::OutputSize::USIZE*2 + // salted key hash and hmac
    <ChaCha20 as NewStreamCipher>::NonceSize::USIZE; // nonce
pub struct EncryptionHeaders {
    pub salt: [u8;SALT_LENGTH],
    pub salted_key_hash: Sha512Digest,
    pub hmac:Sha512Digest,
    pub nonce: Nonce,
}
impl EncryptionHeaders {
    fn new() -> EncryptionHeaders {
        EncryptionHeaders {
            hmac:Sha512Digest::default(),
            salt: [0u8;SALT_LENGTH],
            salted_key_hash: Sha512Digest::default(),
            nonce: Nonce::default(),
        }
    }
    pub fn size()->usize{
       ENCRYPTION_HEADERS_SIZE
    }
    pub fn read(reader:&mut VecReader) -> Result<EncryptionHeaders> {
        fn read_with_unit_error(
            reader: &mut VecReader,
            headers: &mut EncryptionHeaders,
        ) -> std::result::Result<(),()> {
            reader.read_exact(&mut headers.hmac)?;
            reader.read_exact(&mut headers.salt)?;
            reader.read_exact(&mut headers.salted_key_hash)?;
            reader.read_exact(&mut headers.nonce)
        }
        let mut headers=EncryptionHeaders::new();
        match read_with_unit_error(&mut reader,&mut headers){
            Ok(())=>Ok(headers),
            Err(())=>Err(Error::FileNotEncryptedProperly)
        }
    }
}
