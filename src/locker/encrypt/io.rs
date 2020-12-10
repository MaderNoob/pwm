use crate::{locker::{ENCRYPTION_HEADERS_SIZE, EncryptedFile, ErrorKind, Result, io_to_locker_error}};
use rand::{thread_rng, RngCore};
use sha3::Digest;
use std::fs::File;
use std::io::Write;

pub struct EncryptedFileReader<'a> {
    file: &'a mut EncryptedFile,
}
impl EncryptedFileReader<'_> {
    pub fn new(file:&'_ mut EncryptedFile)->EncryptedFileReader<'_>{
        EncryptedFileReader{
            file
        }
    }
    pub fn eof(&self) -> bool {
        self.file.reader.eof()
    }
}
impl<'a> crate::locker::EncryptedRead for EncryptedFileReader<'a> {
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
    fn encrypt_and_write_buffer(&mut self) -> Result<()> {
        self.file.encryptor.apply(&mut self.buffer)?;
        io_to_locker_error(self.file.file.write_all(&self.buffer), ErrorKind::WriteFile)
    }
}
impl<'a> crate::locker::EncryptedWrite for EncryptedFileWriter<'a> {
    fn write(&mut self, byte: u8) -> &mut Self {
        // add the bytes to the buffer
        self.buffer.push(byte);
        self
    }
    fn write_all(&mut self, buf: &[u8]) -> &mut Self {
        // add the bytes to the buffer
        self.buffer.extend(buf);
        self
    }
}
impl<'a> crate::locker::EncryptedFlush for EncryptedFileWriter<'a> {
    fn flush(mut self) -> Result<()> {
        // update the hmac hasher
        self.file.hasher.update(&self.buffer);
        self.file
            .headers
            .hmac
            .as_mut()
            .copy_from_slice(&self.file.hasher.finalize_reset());
        // rewrite the hmac
        self.file.seek_file(0)?;
        self.file.write_hmac_and_nonce()?;

        // write the new content
        self.file.seek_file(ENCRYPTION_HEADERS_SIZE as u64)?;
        self.encrypt_and_write_buffer()?;

        // if the length of the original content of the file (without the headers - thus rest),
        // is bigger then the new content's length
        if self.file.reader.rest().len() > self.buffer.len() {
            io_to_locker_error(
                self.file.file.set_len(ENCRYPTION_HEADERS_SIZE as u64 + self.buffer.len() as u64),
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
            file,
            buffer: Vec::new(),
        }
    }
    fn encrypt_and_write_buffer(&mut self) -> Result<()> {
        self.file.encryptor.apply(&mut self.buffer)?;
        io_to_locker_error(self.file.file.write_all(&self.buffer), ErrorKind::WriteFile)
    }
    fn write_reader_rest(&mut self)->Result<()>{
        io_to_locker_error(self.file.file.write_all(self.file.reader.rest()),ErrorKind::WriteFile)
    }
}
impl<'a> crate::locker::EncryptedWrite for EncryptedFileAppender<'a> {
    fn write(&mut self, byte: u8) -> &mut Self {
        // add the bytes to the buffer
        self.buffer.push(byte);
        self
    }
    fn write_all(&mut self, buf: &[u8]) -> &mut Self {
        // add the bytes to the buffer
        self.buffer.extend(buf);
        self
    }
}
impl<'a> crate::locker::EncryptedFlush for EncryptedFileAppender<'a> {
    fn flush(mut self) -> Result<()> {
        // reencrypt the original content with the new nonce
        self.file.encryptor.apply(self.file.reader.rest_mut())?;

        // update the hmac hasher
        self.file.hasher.update(&self.buffer);
        self.file
            .headers
            .hmac
            .as_mut()
            .copy_from_slice(&self.file.hasher.finalize_reset());

        // rewrite the hmac
        self.file.seek_file(0)?;
        self.file.write_hmac_and_nonce()?;

        //  === append the new content ===

        // seek to the start of the content
        self.file
            .seek_file(ENCRYPTION_HEADERS_SIZE as u64)?;

        // rewrite the original content after it has been encrypted with the new nonce
        self.write_reader_rest()?;

        // write the appended content
        self.encrypt_and_write_buffer()?;

        Ok(())
    }
}

pub trait InnerFile {
    fn inner_file(&self) -> &File;
    fn inner_file_mut(&mut self) -> &mut File;
}
impl InnerFile for EncryptedFile {
    fn inner_file(&self) -> &File {
        &self.file
    }
    fn inner_file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}
impl<'a> InnerFile for EncryptedFileReader<'a> {
    fn inner_file(&self) -> &File {
        &self.file.file
    }
    fn inner_file_mut(&mut self) -> &mut File {
        &mut self.file.file
    }
}
impl<'a> InnerFile for EncryptedFileWriter<'a> {
    fn inner_file(&self) -> &File {
        &self.file.file
    }
    fn inner_file_mut(&mut self) -> &mut File {
        &mut self.file.file
    }
}
impl<'a> InnerFile for EncryptedFileAppender<'a> {
    fn inner_file(&self) -> &File {
        &self.file.file
    }
    fn inner_file_mut(&mut self) -> &mut File {
        &mut self.file.file
    }
}
pub trait InnerEncryptedFile {
    fn inner_encrypted_file(&self) -> &EncryptedFile;
    fn inner_encrypted_file_mut(&mut self) -> &mut EncryptedFile;
}
impl<'a> InnerEncryptedFile for EncryptedFileReader<'a> {
    fn inner_encrypted_file(&self) -> &EncryptedFile {
        &self.file
    }
    fn inner_encrypted_file_mut(&mut self) -> &mut EncryptedFile {
        &mut self.file
    }
}
impl<'a> InnerEncryptedFile for EncryptedFileWriter<'a> {
    fn inner_encrypted_file(&self) -> &EncryptedFile {
        &self.file
    }
    fn inner_encrypted_file_mut(&mut self) -> &mut EncryptedFile {
        &mut self.file
    }
}
impl<'a> InnerEncryptedFile for EncryptedFileAppender<'a> {
    fn inner_encrypted_file(&self) -> &EncryptedFile {
        &self.file
    }
    fn inner_encrypted_file_mut(&mut self) -> &mut EncryptedFile {
        &mut self.file
    }
}
