use crate::locker::errors::{map_to_locker_error, Error, Result};
use crate::locker::headers::{EncryptionHeaders, ENCRYPTION_HEADERS_SIZE, SALT_LENGTH};
use crate::locker::readers::VecReader;
use chacha20::{
    cipher::NewStreamCipher, cipher::SyncStreamCipher, cipher::SyncStreamCipherSeek, ChaCha20,
    Nonce,
};
use generic_array::typenum::Unsigned;
use rand::{thread_rng, Rng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

type Sha256Digest = generic_array::GenericArray<u8, <Sha256 as Digest>::OutputSize>;
pub struct Encryptor {
    chacha: ChaCha20,
    hashed_key: Sha256Digest,
}
impl Encryptor {
    pub fn new<B: AsRef<[u8]>>(key: B, nonce: &Nonce) -> Encryptor {
        let mut key_hasher = Sha256::new();
        key_hasher.update(key);
        let key = key_hasher.finalize();
        Encryptor {
            chacha: ChaCha20::new(&key, nonce),
            hashed_key: key,
        }
    }
    pub fn apply(&mut self, buf: &mut [u8]) -> Result<()> {
        match self.chacha.try_apply_keystream(buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::EncryptionError),
        }
    }
    pub fn reset_with_nonce(&mut self, nonce: &Nonce) {
        self.chacha = ChaCha20::new(&self.hashed_key, nonce)
    }
}

pub struct LockedEncryptedFile {
    file: File,
    reader: VecReader,
    headers: EncryptionHeaders,
    hasher: Sha512,
}
impl LockedEncryptedFile {
    pub fn open<P: AsRef<std::path::Path>>(path: P,open_options:OpenOptions) -> Result<LockedEncryptedFile> {
        let mut file =
            map_to_locker_error(open_options.open(path), Error::OpenFile)?;

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
    pub fn open_readonly<P: AsRef<std::path::Path>>(path: P) -> Result<LockedEncryptedFile> {
        LockedEncryptedFile::open(path, OpenOptions::new().read(true))    
    }
    pub fn open_write<P: AsRef<std::path::Path>>(path: P) -> Result<LockedEncryptedFile> {
        LockedEncryptedFile::open(path, OpenOptions::new().read(true).write(true))    
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
    pub fn appender(self)->EncryptedFileAppender{
        EncryptedFileAppender::new(self)
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
}
impl EncryptedFileWriter {
    pub fn new(mut file: EncryptedFile) -> EncryptedFileWriter {
        // regenerate a new random nonce - never reuse the same keystream!!
        let mut nonce = Nonce::default();
        thread_rng().fill_bytes(&mut nonce);
        file.encryptor.reset_with_nonce(&nonce);
        EncryptedFileWriter {
            file: file,
            buffer: Vec::new(),
        }
    }
    pub fn write_all(&mut self, buf: &[u8]) -> Result<&mut Self> {
        // update the hmac hasher
        self.file.hasher.update(buf);

        // add the bytes to the buffer
        self.buffer.extend(buf);

        // encrypt the new bytes
        self.file
            .encryptor
            .apply(&mut self.buffer[self.buffer.len() - buf.len()..])?;
        Ok(self)
    }
    fn seek_file(&mut self, pos: u64) -> Result<u64> {
        map_to_locker_error(self.file.file.seek(SeekFrom::Start(pos)), Error::SeekFile)
    }
    fn write_file(&mut self, buf: &[u8]) -> Result<()> {
        map_to_locker_error(self.file.file.write_all(buf), Error::WriteFile)
    }
    pub fn flush(self) -> Result<()> {
        self.file
            .headers
            .hmac
            .as_ref()
            .copy_from_slice(&self.file.hasher.finalize_reset());

        // rewrite the hmac
        self.seek_file(0)?;
        self.write_file(&self.file.headers.hmac)?;

        // write the new content
        self.seek_file(ENCRYPTION_HEADERS_SIZE)?;
        self.write_all(&self.buffer)?;

        // if the length of the original content of the file (without the headers - thus rest),
        // is bigger then the new content's length
        if self.file.reader.rest().len() > self.buffer.len() {
            map_to_locker_error(
                self.file.file.set_len(ENCRYPTION_HEADERS_SIZE),
                Error::TruncateFile,
            )?;
        }
        Ok(())
    }
}
pub struct EncryptedFileAppender{
    file:EncryptedFile,
    buffer:Vec<u8>,
}
impl EncryptedFileAppender{
    pub fn new(mut file: EncryptedFile) -> EncryptedFileAppender {
        // regenerate a new random nonce - never reuse the same keystream!!
        let mut nonce = Nonce::default();
        thread_rng().fill_bytes(&mut nonce);
        file.encryptor.reset_with_nonce(&nonce);

        // update the hmac hasher with the original content of the file, 
        // and then re-update it everytime we append to get the full hmac
        file.hasher.update(file.reader.rest());
        EncryptedFileAppender {
            file: file,
            buffer: Vec::new(),
        }
    }
    pub fn append_all(&mut self, buf: &[u8]) -> Result<&mut Self> {
        // update the hmac hasher
        self.file.hasher.update(buf);

        // add the bytes to the buffer
        self.buffer.extend(buf);

        // encrypt the new bytes
        self.file
            .encryptor
            .apply(&mut self.buffer[self.buffer.len() - buf.len()..])?;
        Ok(self)
    }
    pub fn flush(self) -> Result<()> {
        self.file
            .headers
            .hmac
            .as_ref()
            .copy_from_slice(&self.file.hasher.finalize_reset());

        // rewrite the hmac
        self.seek_file(0)?;
        self.write_file(&self.file.headers.hmac)?;


        //  === write the new content ===

        // seek to the end of the file
        self.seek_file(self.file.reader.buffer().len())?;
        // write the appended content
        self.write_all(&self.buffer)?;

        Ok(())
    }
}