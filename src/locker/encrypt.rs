use crate::locker::errors::{map_to_locker_error, Error, Result};
use crate::locker::headers::{EncryptionHeaders, ENCRYPTION_HEADERS_SIZE};
use crate::locker::readers::VecReader;
use chacha20::{
    cipher::NewStreamCipher, cipher::SyncStreamCipher, cipher::SyncStreamCipherSeek, ChaCha20,
    Nonce,
};
use rand::{thread_rng, RngCore,Rng};
use sha2::{Digest, Sha256, Sha512};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom};
type Sha256Digest=generic_array::GenericArray<u8,<Sha256 as Digest>::OutputSize>;
pub struct Encryptor {
    chacha: ChaCha20,
    hashed_key:Sha256Digest,
}
impl Encryptor {
    pub fn new<B: AsRef<[u8]>>(key: B, nonce: &Nonce) -> Encryptor {
        let mut key_hasher = Sha256::new();
        key_hasher.update(key);
        let key = key_hasher.finalize();
        Encryptor {
            chacha: ChaCha20::new(&key, nonce),
            hashed_key:key,
        }
    }
    pub fn apply(&mut self, buf: &mut [u8]) -> Result<()> {
        match self.chacha.try_apply_keystream(buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::EncryptionError),
        }
    }
    pub fn reset_with_nonce(&mut self,nonce: &Nonce){
        self.chacha=ChaCha20::new(&self.hashed_key, nonce)
    }
}

pub struct LockedEncryptedFile {
    file: File,
    reader: VecReader,
    headers: EncryptionHeaders,
    hasher: Sha512,
}
impl LockedEncryptedFile {
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<LockedEncryptedFile> {
        let mut file =
            map_to_locker_error(OpenOptions::new().read(true).open(path), Error::OpenFile)?;

        // get the file length and create a buffer with the retrieved length
        let file_len = file
            .metadata()
            .map(|meta| meta.len() as usize + 1)
            .unwrap_or(0);
        let content = Vec::with_capacity(file_len);

        // read the whole file into the buffer
        map_to_locker_error(file.read_to_end(&mut content), Error::ReadFile)?;

        // create a reader over the content vector
        let mut reader = VecReader::new(content);
        let headers = EncryptionHeaders::read(&mut reader)?;
        Ok(LockedEncryptedFile {
            file,
            reader,
            headers,
            hasher: Sha512::new(),
        })
    }
    pub fn test_key<B: AsRef<[u8]>>(&mut self, key: B) -> bool {
        self.hasher.update(key);
        self.hasher.update(&self.headers.salt);

        self.hasher.finalize_reset() == self.headers.salted_key_hash
    }
    pub fn unlock<B: AsRef<[u8]>>(mut self, key: B) -> Result<EncryptedFile> {
        if !self.test_key(key.as_ref()) {
            Err(Error::WrongPassword)
        } else {
            let mut encryptor = Encryptor::new(key.as_ref(), &self.headers.nonce);
            // decrypt the content
            encryptor.apply(self.reader.mut_rest())?;

            // validate the hmac
            self.hasher.update(self.reader.rest());
            if self.hasher.finalize_reset() != self.headers.hmac {
                return Err(Error::MacError);
            }

            Ok(EncryptedFile {
                file: self.file,
                reader: self.reader,
                encryptor,
                headers: self.headers,
                hasher: self.hasher,
                key: Vec::from(key.as_ref()),
            })
        }
    }
}
pub struct EncryptedFile {
    file: File,
    reader: VecReader,
    headers: EncryptionHeaders,
    hasher: Sha512,
    key: Vec<u8>,
    encryptor: Encryptor,
}
impl EncryptedFile {
    pub fn reader(self) -> EncryptedFileReader {
        EncryptedFileReader { file: self }
    }
    pub fn writer(self) -> EncryptedFileWriter {
        EncryptedFileWriter::new(self)
    }
}
pub struct EncryptedFileReader {
    file: EncryptedFile,
}
impl EncryptedFileReader {
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        match self.file.reader.read_exact(buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::ReadFile),
        }
    }
}
pub struct EncryptedFileWriter {
    file: EncryptedFile,
    buffer: Vec<u8>,
    hasher:Sha512,
}
impl EncryptedFileWriter {
    pub fn new(mut file:EncryptedFile)->EncryptedFileWriter{
        // regenerate a new random nonce - never reuse the same keystream!!
        let mut nonce=Nonce::default();
        thread_rng().fill_bytes(&mut nonce);
        file.encryptor.reset_with_nonce(&nonce);
        EncryptedFileWriter{
            file:file,
            buffer:Vec::new(),
            hasher:Sha512::new(),
        }
    }
    pub fn write_all(&mut self, buf: &[u8]) -> Result<&mut Self> {
        // update the hmac hasher
        self.hasher.update(buf);

        // add the bytes to the buffer
        self.buffer.extend(buf);

        // decrypt the new bytes
        self.file.encryptor.apply(&mut self.buffer[self.buffer.len()-buf.len()..])?;
        Ok(self)
    }
    pub fn flush(self)->Result<()>{
        self.file.headers.resalt(&self.file.key);

        fn rewrite_salt_and_hash_with_io_error(writer:&mut EncryptedFileWriter)->std::io::Result<()>{
            self.file.file.seek(SeekFrom::Start(0))?;

        }
        
    }
}
