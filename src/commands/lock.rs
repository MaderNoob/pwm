use crate::locker::encrypt::EncryptedFile;
use crate::locker::errors::{Result,print_error};
use crate::locker::flags::{MutableFile};
use crate::styles::{error_style,success_style};

fn lock(path:&str,key:&str,make_immutable:bool)->Result<()>{
    let mut file=EncryptedFile::encrypt_file(path, key)?;
    if make_immutable{
        file.make_immutable()?;
    }
    Ok(())
}
pub fn lock_command(path:&str,key:&str,make_immutable:bool){
    match lock(path,key,make_immutable){
        Ok(())=>println!("{}",success_style().paint("The target file was successfully locked")),
        Err(e)=>print_error(e, "target", &error_style()),
    }
}