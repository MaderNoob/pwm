pub mod errors;
pub mod flags;
pub mod headers;
pub mod io;
pub mod encrypt;

use errors::Result;
use flags::{MutableFile};
use encrypt::{LockedEncryptedFile,EncryptedFile};
use std::fs::{File,OpenOptions};

pub fn lock<P: AsRef<std::path::Path>>(path: P,key:&str, make_immutable: bool) -> Result<()> {
    let mut encrypted_file=EncryptedFile::encrypt_file(path, key)?;
    if make_immutable && cfg!(unix){
        encrypted_file.make_immutable()?
    }
    Ok(())
}