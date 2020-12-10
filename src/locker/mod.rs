mod errors;
mod flags;
mod headers;
mod io;
mod encrypt;
pub use {errors::*,flags::*,headers::*,io::*,encrypt::*};

pub fn lock<P: AsRef<std::path::Path>>(path: P,key:&str, make_immutable: bool) -> Result<()> {
    let mut encrypted_file=EncryptedFile::encrypt_file(path, key)?;
    if make_immutable && cfg!(unix){
        encrypted_file.inner_file_mut().make_immutable()?
    }
    Ok(())
}