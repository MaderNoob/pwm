pub mod inner_files;

use crate::locker::errors::{io_to_locker_error, to_locker_error, ErrorKind, Result};
use crate::locker::flags::{MutableFile, UnixFile, UnixFileFlags};
use crate::locker::headers::{EncryptionHeaders, ENCRYPTION_HEADERS_SIZE};
use crate::vec_reader::VecReader;
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
            Err(_) => Err(ErrorKind::EncryptionError.without_source_error()),
        }
    }
    pub fn seek(&mut self, pos: u64) -> Result<()> {
        to_locker_error(self.chacha.try_seek(pos), ErrorKind::EncryptionError)
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
    hasher: Sha512,
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
    hasher: Sha512,
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

        let mut hasher = Sha512::new();
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

        let mut hasher = Sha512::new();
        let headers = EncryptionHeaders::new(&mut hasher, &content, key.as_ref());
        let mut headers_buf = [0u8; ENCRYPTION_HEADERS_SIZE];
        headers.write_to(&mut headers_buf);
        io_to_locker_error(file.write_all(&headers_buf), ErrorKind::WriteFile)?;

        // encrypt the content buffer
        let mut encryptor = Encryptor::new(key.as_ref(), &headers.nonce);
        encryptor.apply(&mut content)?;

        // write the encrypted content
        match file.write_all(&content) {
            Ok(()) => Ok(EncryptedFile{
                key:Vec::from(key.as_ref()),
                reader:VecReader::new(content),
                file,headers,hasher,encryptor,
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
    pub fn reader(&mut self) -> EncryptedFileReader {
        EncryptedFileReader { file: self }
    }
    pub fn writer(&'_ mut self) -> EncryptedFileWriter<'_> {
        EncryptedFileWriter::new(self)
    }
    pub fn appender(&'_ mut self) -> EncryptedFileAppender<'_> {
        EncryptedFileAppender::new(self)
    }
}

pub struct EncryptedFileReader<'a> {
    file: &'a mut EncryptedFile,
}
impl<'a> crate::locker::io::Read for EncryptedFileReader<'a> {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        match self.file.reader.read_exact(buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(ErrorKind::CorruptedFile.without_source_error()),
        }
    }
    fn read_until(&mut self, terminator: u8) -> Vec<u8> {
        let mut length = 0usize;
        let mut res = Vec::new();
        // used the extra scop so that rest, which is a reference to self.file.reader will
        // be dropped, otherwise self.file.reader couldn't be used later on
        {
            let rest = self.file.reader.rest();
            while rest[length] != terminator && length < rest.len() {
                length += 1;
            }
            res.extend_from_slice(&rest[..length]);
        }
        self.file.reader.consume(length + 1);
        res
    }
}

pub struct EncryptedFileWriter<'a> {
    file: &'a mut EncryptedFile,
    buffer: Vec<u8>,
}
impl<'a> EncryptedFileWriter<'a> {
    pub fn new(file: &'a mut EncryptedFile) -> EncryptedFileWriter<'a> {
        // regenerate a new random nonce - never reuse the same keystream!!
        thread_rng().fill_bytes(&mut file.headers.nonce);
        file.encryptor.reset_with_nonce(&file.headers.nonce);
        EncryptedFileWriter {
            file,
            buffer: Vec::new(),
        }
    }
    fn seek_file(&mut self, pos: u64) -> Result<u64> {
        io_to_locker_error(
            self.file.file.seek(SeekFrom::Start(pos)),
            ErrorKind::SeekFile,
        )
    }
    fn write_hmac_and_nonce(&mut self) -> Result<()> {
        io_to_locker_error(
            self.file.file.write_all(&self.file.headers.hmac),
            ErrorKind::WriteFile,
        )?;
        io_to_locker_error(
            self.file.file.write_all(&self.file.headers.nonce),
            ErrorKind::WriteFile,
        )
    }
    fn write_buffer(&mut self) -> Result<()> {
        io_to_locker_error(self.file.file.write_all(&self.buffer), ErrorKind::WriteFile)
    }
}
impl<'a> crate::locker::io::Write for EncryptedFileWriter<'a> {
    fn write(&mut self, byte: u8) -> Result<&mut Self> {
        // update the hmac hasher
        self.file.hasher.update(&[byte]);

        // add the bytes to the buffer
        self.buffer.push(byte);

        // encrypt the new bytes
        let buffer_len = self.buffer.len();
        self.file
            .encryptor
            .apply(&mut self.buffer[buffer_len - 1..])?;
        Ok(self)
    }
    fn write_all(&mut self, buf: &[u8]) -> Result<&mut Self> {
        // update the hmac hasher
        self.file.hasher.update(buf);

        // add the bytes to the buffer
        self.buffer.extend(buf);

        // encrypt the new bytes
        let buffer_len = self.buffer.len();
        self.file
            .encryptor
            .apply(&mut self.buffer[buffer_len - buf.len()..])?;
        Ok(self)
    }
    fn flush(mut self) -> Result<()> {
        self.file
            .headers
            .hmac
            .as_mut()
            .copy_from_slice(&self.file.hasher.finalize_reset());
        // rewrite the hmac
        self.seek_file(0)?;
        self.write_hmac_and_nonce()?;

        // write the new content
        self.seek_file(ENCRYPTION_HEADERS_SIZE as u64)?;
        self.write_buffer()?;

        // if the length of the original content of the file (without the headers - thus rest),
        // is bigger then the new content's length
        if self.file.reader.rest().len() > self.buffer.len() {
            io_to_locker_error(
                self.file.file.set_len(ENCRYPTION_HEADERS_SIZE as u64),
                ErrorKind::TruncateFile,
            )?;
        }
        Ok(())
    }
}

pub struct EncryptedFileAppender<'a> {
    file: &'a mut EncryptedFile,
    buffer: Vec<u8>,
}
impl<'a> EncryptedFileAppender<'a> {
    pub fn new(file: &'a mut EncryptedFile) -> EncryptedFileAppender<'a> {
        // regenerate a new random nonce - never reuse the same keystream!!
        thread_rng().fill_bytes(&mut file.headers.nonce);
        file.encryptor.reset_with_nonce(&file.headers.nonce);

        // update the hmac hasher with the original content of the file,
        // and then re-update it everytime we append to get the full hmac
        file.hasher.update(file.reader.rest());
        EncryptedFileAppender {
            file: file,
            buffer: Vec::new(),
        }
    }
    fn seek_file(&mut self, pos: u64) -> Result<u64> {
        io_to_locker_error(
            self.file.file.seek(SeekFrom::Start(pos)),
            ErrorKind::SeekFile,
        )
    }
    fn write_hmac_and_nonce(&mut self) -> Result<()> {
        io_to_locker_error(
            self.file.file.write_all(&self.file.headers.hmac),
            ErrorKind::WriteFile,
        )?;
        io_to_locker_error(
            self.file.file.write_all(&self.file.headers.nonce),
            ErrorKind::WriteFile,
        )
    }
    fn write_buffer(&mut self) -> Result<()> {
        io_to_locker_error(self.file.file.write_all(&self.buffer), ErrorKind::WriteFile)
    }
}
impl<'a> crate::locker::io::Write for EncryptedFileAppender<'a> {
    fn write(&mut self, byte: u8) -> Result<&mut Self> {
        // update the hmac hasher
        self.file.hasher.update(&[byte]);

        // add the bytes to the buffer
        self.buffer.push(byte);

        // encrypt the new bytes
        let buffer_len = self.buffer.len();
        self.file
            .encryptor
            .apply(&mut self.buffer[buffer_len - 1..])?;
        Ok(self)
    }
    fn write_all(&mut self, buf: &[u8]) -> Result<&mut Self> {
        // update the hmac hasher
        self.file.hasher.update(buf);

        // add the bytes to the buffer
        self.buffer.extend(buf);

        // encrypt the new bytes
        let buffer_len = self.buffer.len();
        self.file
            .encryptor
            .apply(&mut self.buffer[buffer_len - buf.len()..])?;
        Ok(self)
    }
    fn flush(mut self) -> Result<()> {
        self.file
            .headers
            .hmac
            .as_mut()
            .copy_from_slice(&self.file.hasher.finalize_reset());

        // rewrite the hmac
        self.seek_file(0)?;
        self.write_hmac_and_nonce()?;

        //  === append the new content ===

        // seek to the end of the file
        self.seek_file(self.file.reader.buffer().len() as u64)?;

        // write the appended content
        self.write_buffer()?;

        Ok(())
    }
}
