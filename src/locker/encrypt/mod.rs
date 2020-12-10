mod io;
pub use self::io::*;

use crate::{
    locker::{
        io_to_locker_error, to_locker_error, EncryptionHeaders, ErrorKind, MutableFile, Result,
        ENCRYPTION_HEADERS_SIZE,
    },
    passwords::Password,
};
use crate::{
    passwords::{PasswordReader, PasswordWriter},
    vec_io::VecReader,
};
use chacha20::{
    cipher::NewStreamCipher, cipher::SyncStreamCipher, cipher::SyncStreamCipherSeek, ChaCha20,
    Nonce,
};
use rand::{thread_rng, RngCore};
use sha3::{Digest, Sha3_256, Sha3_512};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use super::EncryptedFlush;

type Sha256Digest = generic_array::GenericArray<u8, <Sha3_256 as Digest>::OutputSize>;
pub struct Encryptor {
    chacha: ChaCha20,
    hashed_key: Sha256Digest,
}
impl Encryptor {
    pub fn new<B: AsRef<[u8]>>(key: B, nonce: &Nonce) -> Encryptor {
        let mut key_hasher = Sha3_256::new();
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
            Err(_) => Err(ErrorKind::EncryptionError.without_source_error()),
        }
    }
    pub fn advance(&mut self, amount: u64) -> Result<()> {
        let cur: u64 = to_locker_error(self.chacha.try_current_pos(), ErrorKind::EncryptionError)?;
        to_locker_error(
            self.chacha.try_seek(cur + amount),
            ErrorKind::EncryptionError,
        )
    }
    pub fn reset_with_nonce(&mut self, nonce: &Nonce) {
        self.chacha = ChaCha20::new(&self.hashed_key, nonce)
    }
}

fn make_mutable_if_immutable(file: &mut File) -> Result<()> {
    if cfg!(unix) {
        file.make_mutable()
    } else {
        Ok(())
    }
}

pub struct LockedEncryptedFile {
    file: File,
    reader: VecReader,
    headers: EncryptionHeaders,
    hasher: Sha3_512,
}
impl LockedEncryptedFile {
    pub fn open<P: AsRef<std::path::Path>>(
        path: P,
        open_options: &OpenOptions,
    ) -> Result<LockedEncryptedFile> {
        let mut file = io_to_locker_error(open_options.open(path), ErrorKind::OpenFile)?;

        // get the file length and create a buffer with the retrieved length
        let file_len = file
            .metadata()
            .map(|meta| meta.len() as usize + 1)
            .unwrap_or(0);
        let mut content = Vec::with_capacity(file_len);

        // read the whole file into the buffer
        io_to_locker_error(file.read_to_end(&mut content), ErrorKind::ReadFile)?;

        // create a reader over the content vector
        let mut reader = VecReader::new(content);
        let headers = EncryptionHeaders::read(&mut reader)?;
        Ok(LockedEncryptedFile {
            file,
            reader,
            headers,
            hasher: Sha3_512::new(),
        })
    }
    pub fn open_readonly<P: AsRef<std::path::Path>>(path: P) -> Result<LockedEncryptedFile> {
        LockedEncryptedFile::open(path, OpenOptions::new().read(true))
    }
    pub fn open_write<P: AsRef<std::path::Path>>(path: P) -> Result<LockedEncryptedFile> {
        LockedEncryptedFile::open(path, OpenOptions::new().read(true).write(true))
    }

    pub fn test_key<B: AsRef<[u8]>>(&mut self, key: B) -> bool {
        self.hasher.update(&key);
        self.hasher.update(&self.headers.salt);

        self.hasher.finalize_reset() == self.headers.salted_key_hash
    }
    pub fn unlock<B: AsRef<[u8]>>(mut self, key: B) -> Result<EncryptedFile> {
        let mut encryptor = Encryptor::new(key.as_ref(), &self.headers.nonce);
        // decrypt the content
        encryptor.apply(self.reader.rest_mut())?;
        // validate the hmac
        self.hasher.update(self.reader.rest());
        if self.hasher.finalize_reset() != self.headers.hmac {
            return Err(ErrorKind::MacError.without_source_error());
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
pub struct EncryptedFile {
    file: File,
    reader: VecReader,
    headers: EncryptionHeaders,
    hasher: Sha3_512,
    key: Vec<u8>,
    encryptor: Encryptor,
}
impl EncryptedFile {
    pub fn create<P: AsRef<std::path::Path>, B: AsRef<[u8]>>(
        path: P,
        key: B,
    ) -> Result<EncryptedFile> {
        let mut file = io_to_locker_error(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path),
            ErrorKind::OpenFile,
        )?;

        let mut hasher = Sha3_512::new();
        let content = Vec::new();
        let headers = EncryptionHeaders::new(&mut hasher, &content, key.as_ref());
        let mut headers_buf = [0u8; ENCRYPTION_HEADERS_SIZE];
        headers.write_to(&mut headers_buf);
        io_to_locker_error(file.write_all(&headers_buf), ErrorKind::WriteFile)?;

        // encrypt the content buffer
        Ok(EncryptedFile {
            encryptor: Encryptor::new(key.as_ref(), &headers.nonce),
            key: Vec::from(key.as_ref()),
            reader: VecReader::new(content),
            file,
            headers,
            hasher,
        })
    }
    pub fn encrypt_file<P: AsRef<std::path::Path>, B: AsRef<[u8]>>(
        path: P,
        key: B,
    ) -> Result<EncryptedFile> {
        let mut file = io_to_locker_error(
            OpenOptions::new().read(true).write(true).open(path),
            ErrorKind::OpenFile,
        )?;
        make_mutable_if_immutable(&mut file)?;

        // get the file length and create a buffer with the retrieved length
        let file_len = file
            .metadata()
            .map(|meta| meta.len() as usize + 1)
            .unwrap_or(0);
        let mut content = Vec::with_capacity(file_len);

        io_to_locker_error(file.read_to_end(&mut content), ErrorKind::ReadFile)?;

        // seek back to the start of the file for later write calls
        io_to_locker_error(file.seek(SeekFrom::Start(0)), ErrorKind::SeekFile)?;

        let mut hasher = Sha3_512::new();
        let headers = EncryptionHeaders::new(&mut hasher, &content, key.as_ref());
        let mut headers_buf = [0u8; ENCRYPTION_HEADERS_SIZE];
        headers.write_to(&mut headers_buf);
        io_to_locker_error(file.write_all(&headers_buf), ErrorKind::WriteFile)?;

        // encrypt the content buffer
        let mut encryptor = Encryptor::new(key.as_ref(), &headers.nonce);
        encryptor.apply(&mut content)?;

        // write the encrypted content
        match file.write_all(&content) {
            Ok(()) => Ok(EncryptedFile {
                key: Vec::from(key.as_ref()),
                reader: VecReader::new(content),
                file,
                headers,
                hasher,
                encryptor,
            }),
            Err(err) => {
                // if failed to write the content, rewrite the original content
                // that was overwritten when writing the headers to the file
                match file.write_all(&content[..ENCRYPTION_HEADERS_SIZE]) {
                    Ok(()) => Err(ErrorKind::WriteFile.with_source_error(err)),
                    Err(backup_err) => Err(ErrorKind::RevertToBackup.with_source_error(backup_err)),
                }
            }
        }
    }
    pub fn decrypt(mut self) -> Result<()> {
        // right now the file cursor is at the end of the file because we called read_to_end,
        // so seek to the start of the file to write the decrypted content
        io_to_locker_error(self.file.seek(SeekFrom::Start(0)), ErrorKind::SeekFile)?;
        // write all the decrypted content to the file
        io_to_locker_error(
            self.file.write_all(self.reader.rest()),
            ErrorKind::WriteFile,
        )?;

        // truncate the rest of the file
        io_to_locker_error(
            self.file.set_len(self.reader.rest().len() as u64),
            ErrorKind::TruncateFile,
        )
    }
    fn seek_file(&mut self, pos: u64) -> Result<u64> {
        io_to_locker_error(self.file.seek(SeekFrom::Start(pos)), ErrorKind::SeekFile)
    }
    fn write_hmac_and_nonce(&mut self) -> Result<()> {
        io_to_locker_error(
            self.file.write_all(&self.headers.hmac),
            ErrorKind::WriteFile,
        )?;
        io_to_locker_error(
            self.file.write_all(&self.headers.nonce),
            ErrorKind::WriteFile,
        )
    }
    // using self instead of &mut self because modifying the content vector causes a problem with
    // the position of the VecReader, so using self prevents the use of the struct after this
    // corruption
    // pub fn append_password(mut self, password: &Password) -> Result<()> {
    //     // create a new random nonce
    //     thread_rng().fill_bytes(&mut self.headers.nonce);
    //     self.encryptor.reset_with_nonce(&self.headers.nonce);
    //     // used extra scope so that content, which is a mut ref to self.reader, will be dropped,
    //     // so that self could be used later
    //     {
    //         // calculate the new amount
    //         let amount_buf = &mut self.reader.rest_mut()[..std::mem::size_of::<usize>()];
    //         let mut amount_usize_buf = [0u8; std::mem::size_of::<usize>()];
    //         amount_usize_buf.copy_from_slice(amount_buf);
    //         let new_amount = usize::from_ne_bytes(amount_usize_buf) + 1;
    //         // write the new amount to the buffer
    //         amount_buf.copy_from_slice(&new_amount.to_ne_bytes());
    //     }
    //     // update the mac hasher with the whole content
    //     self.hasher.update(self.reader.rest());
    //     // encrypt the updated bytes and rewrite them
    //     self.encryptor
    //         .apply(&mut self.reader.rest_mut()[..std::mem::size_of::<usize>()])?;
    //     self.seek_file(ENCRYPTION_HEADERS_SIZE as u64)?;
    //     io_to_locker_error(
    //         self.file
    //             .write_all(&self.reader.rest()[..std::mem::size_of::<usize>()]),
    //         ErrorKind::WriteFile,
    //     )?;
    //     // seek forward on the encryptor because it currently has only encrypted the first sizeof::<usize>()
    //     // bytes, and we later want to use it to encrypt the appened content, so we want to skip
    //     // the rest of the content
    //     self.encryptor
    //         .advance(self.reader.rest().len() as u64 - std::mem::size_of::<usize>() as u64)?;
    //     // write the new password and update the hmac hasher with it
    //     let mut password_bytes = Vec::new();
    //     password_bytes.write_password(password);
    //     self.hasher.update(&password_bytes);
    //     self.encryptor.apply(&mut password_bytes)?;
    //     io_to_locker_error(self.file.write_all(&password_bytes), ErrorKind::WriteFile)?;
    //     self.headers
    //         .hmac
    //         .as_mut()
    //         .copy_from_slice(&self.hasher.finalize_reset());
    //     // rewrite the hmac
    //     self.seek_file(0)?;
    //     self.write_hmac_and_nonce()?;
    //     Ok(())
    // }
    pub fn reader(&mut self) -> EncryptedFileReader {
        EncryptedFileReader::new(self)
    }
    pub fn writer(&'_ mut self) -> EncryptedFileWriter<'_> {
        EncryptedFileWriter::new(self)
    }
    pub fn appender(&'_ mut self) -> EncryptedFileAppender<'_> {
        EncryptedFileAppender::new(self)
    }
}
