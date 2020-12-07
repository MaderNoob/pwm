use crate::locker::{errors::ErrorKind, encrypt::{EncryptedFile, EncryptedFileReader}};
use crate::locker::errors::{Error, Result,to_locker_error};
use crate::passwords::Password;
use crate::passwords::io::PasswordReader;
use fallible_iterator::FallibleIterator;
pub struct PasswordIterator<'a> {
    reader: EncryptedFileReader<'a>,
    total_passwords: usize,
    current_password_index: usize,
}
impl<'a> PasswordIterator<'a> {
    pub fn new(file: &'a mut EncryptedFile) -> Result<PasswordIterator> {
        let mut reader = file.reader();
        Ok(PasswordIterator {
            total_passwords: to_locker_error(reader.read_usize(),ErrorKind::CorruptedFile)?,
            reader,
            current_password_index: 0,
        })
    }
}

impl<'a> FallibleIterator for PasswordIterator<'a> {
    type Error = Error;
    type Item = Password;
    fn next(&mut self) -> Result<Option<Self::Item>> {
        Ok(if self.current_password_index < self.total_passwords {
            Some(match self.reader.read_password(){
                Ok(v)=>v,
                Err(e)=>return Err(match e.kind(){
                    ErrorKind::ReadFile=>e.with_kind(ErrorKind::CorruptedFile),
                    _ => e
                })
            })
        } else {
            None
        })
    }
}
