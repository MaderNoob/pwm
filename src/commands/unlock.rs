use crate::styles::{error_style, success_style};
use crate::input::prompt_user_to_unlock_file_with_password;
use crate::locker::encrypt::{LockedEncryptedFile};
use crate::locker::errors::{print_error, Result};

fn unlock(path: &str) -> Result<()> {
    let file = LockedEncryptedFile::open_write(path)?;
    let unlocked_file = prompt_user_to_unlock_file_with_password(file, "Enter password: ")?;
    unlocked_file.decrypt()?;
    Ok(())
}
pub fn unlock_command(path: &str) {
    match unlock(path) {
        Ok(()) => println!(
            "{}",
            success_style().paint("The target file was successfully unlocked")
        ),
        Err(e) => print_error(e, "target", &error_style()),
    }
}
