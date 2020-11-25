use crate::locker::errors::{ErrorKind, Result,io_to_locker_error};
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
pub const SHA_512_DIGEST_SIZE:usize=<Sha512 as Digest>::OutputSize::USIZE;
pub const CHACHA20_NONCE_SIZE:usize=<ChaCha20 as NewStreamCipher>::NonceSize::USIZE;
pub const ENCRYPTION_HEADERS_SIZE:usize=
    SALT_LENGTH + 
    SHA_512_DIGEST_SIZE*2 + // salted key hash and hmac
    CHACHA20_NONCE_SIZE; // nonce
pub struct EncryptionHeaders {
    pub hmac:Sha512Digest,
    pub salt: [u8;SALT_LENGTH],
    pub salted_key_hash: Sha512Digest,
    pub nonce: Nonce,
}
impl EncryptionHeaders {
    pub fn new<B:AsRef<[u8]>>(hasher:&mut Sha512,content:&Vec<u8>,key:B)->EncryptionHeaders{
        let mut thread_random = thread_rng();
        let mut result=EncryptionHeaders::default();
        
        // generate salt
        thread_random.fill_bytes(&mut result.salt);

        // calculate hmac
        hasher.update(content);
        result.hmac.as_mut().copy_from_slice(&hasher.finalize_reset());

        hasher.update(key.as_ref());
        hasher.update(result.salt);
        result.salted_key_hash.as_mut().copy_from_slice(&hasher.finalize_reset());

        thread_random.fill_bytes(&mut result.nonce);

        result
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
        let mut headers=EncryptionHeaders::default();
        match read_with_unit_error(reader,&mut headers){
            Ok(())=>Ok(headers),
            Err(())=>Err(ErrorKind::FileNotEncryptedProperly.without_source_error())
        }
    }
    pub fn write_to(&self,buf:&mut [u8]){
        let mut current_index=0;
        buf[..SHA_512_DIGEST_SIZE].copy_from_slice(&self.hmac);
        current_index+=SHA_512_DIGEST_SIZE;

        buf[current_index..current_index+SALT_LENGTH].copy_from_slice(&self.salt);
        current_index+=SALT_LENGTH;

        buf[current_index..current_index+SHA_512_DIGEST_SIZE].copy_from_slice(&self.salted_key_hash);
        current_index+=SHA_512_DIGEST_SIZE;

        buf[current_index..current_index+CHACHA20_NONCE_SIZE].copy_from_slice(&self.nonce);
    }
}
impl Default for EncryptionHeaders{
    fn default() -> Self {
        EncryptionHeaders {
            hmac:Sha512Digest::default(),
            salt: [0u8;SALT_LENGTH],
            salted_key_hash: Sha512Digest::default(),
            nonce: Nonce::default(),
        }
    }
}