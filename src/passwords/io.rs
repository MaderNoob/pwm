use std::collections::HashMap;

use crate::locker::{
    to_locker_error, EncryptedFile, ErrorKind, Result, EncryptedWrite, ENCRYPTION_HEADERS_SIZE,
};

use crate::passwords::Password;
pub trait PasswordReader {
    fn read_usize(&mut self) -> Result<usize>;
    fn read_string(&mut self) -> Result<String>;
    fn read_optional_string(&mut self) -> Result<Option<String>>;
    fn read_additional_fields(&mut self) -> Result<HashMap<String, String>>;
    fn read_password(&mut self) -> Result<Password>;
}
impl<T: crate::locker::EncryptedRead> PasswordReader for T {
    fn read_usize(&mut self) -> Result<usize> {
        let mut usize_buf = [0u8; std::mem::size_of::<usize>()];
        self.read_exact(&mut usize_buf)?;
        Ok(usize::from_ne_bytes(usize_buf))
    }
    fn read_string(&mut self) -> Result<String> {
        to_locker_error(
            String::from_utf8(self.read_until(0)),
            ErrorKind::EncodingError,
        )
    }
    fn read_optional_string(&mut self) -> Result<Option<String>> {
        let string = to_locker_error(
            String::from_utf8(self.read_until(0)),
            ErrorKind::EncodingError,
        )?;
        Ok(match string.len() {
            0 => None,
            _ => Some(string),
        })
    }
    fn read_additional_fields(&mut self) -> Result<HashMap<String, String>> {
        let amount = self.read_usize()?;
        let mut fields = HashMap::new();
        for _ in 0..amount {
            let key = self.read_string()?;
            let value = self.read_string()?;
            fields.insert(key, value);
        }
        Ok(fields)
    }
    fn read_password(&mut self) -> Result<Password> {
        Ok(Password {
            password: self.read_string()?,
            domain: self.read_string()?,
            username: self.read_string()?,
            additional_fields: self.read_additional_fields()?,
        })
    }
}

pub trait PasswordWriter {
    fn write_usize(&mut self, usize_value: usize) -> &mut Self;
    fn write_string(&mut self, string: &str) -> &mut Self;
    fn write_additional_fields(&mut self, additional_fields: &HashMap<String, String>)
        -> &mut Self;
    fn write_password(&mut self, password: &Password) -> &mut Self;
    fn write_passwords(&mut self, passwords: &[Password]) -> &mut Self;
}
impl<T: EncryptedWrite> PasswordWriter for T {
    fn write_usize(&mut self, usize_value: usize) -> &mut Self {
        self.write_all(&usize_value.to_ne_bytes())
    }
    fn write_string(&mut self, string: &str) -> &mut Self {
        self.write_all(string.as_bytes()).write(0)
    }
    fn write_additional_fields(
        &mut self,
        additional_fields: &HashMap<String, String>,
    ) -> &mut Self {
        self.write_usize(additional_fields.len());
        for (key, value) in additional_fields {
            self.write_string(key).write_string(value);
        }
        self
    }
    fn write_password(&mut self, password: &Password) -> &mut Self {
        self.write_string(&password.password)
            .write_string(&password.domain)
            .write_string(&password.username)
            .write_additional_fields(&password.additional_fields)
    }
    fn write_passwords(&mut self, passwords: &[Password]) -> &mut Self {
        for password in passwords {
            self.write_password(password);
        }
        self
    }
}
