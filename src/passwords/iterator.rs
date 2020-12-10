use crate::locker::{Error, Result,EncryptedFile, EncryptedFileReader, ErrorKind};
use crate::passwords::io::PasswordReader;
use crate::passwords::Password;
use fallible_iterator::FallibleIterator;
pub struct PasswordIterator<'a> {
    reader: EncryptedFileReader<'a>,
}
impl<'a> PasswordIterator<'a> {
    pub fn new(file: &'a mut EncryptedFile) -> PasswordIterator {
        PasswordIterator {
            reader: file.reader(),
        }
    }
}

impl<'a> FallibleIterator for PasswordIterator<'a> {
    type Error = Error;
    type Item = Password;
    fn next(&mut self) -> Result<Option<Self::Item>> {
        Ok(if self.reader.eof() {
            None
        } else {
            Some(match self.reader.read_password() {
                Ok(v) => v,
                Err(e) => {
                    return Err(match e.kind() {
                        ErrorKind::ReadFile => e.with_kind(ErrorKind::CorruptedFile),
                        _ => e,
                    })
                }
            })
        })
    }
}
