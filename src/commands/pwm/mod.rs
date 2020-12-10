mod get;
mod new;
pub mod master_password;
pub mod printing;

pub use {get::get_command,new::new_command};

use crate::{
    input::prompt_user_to_create_master_password,
    locker::{EncryptedFile, ErrorKind, Result, EncryptedFlush},
    passwords::PasswordWriter,
    styles::{success_style, warning_style},
};
use std::path::{Path, PathBuf};

fn get_passwords_file_path() -> Result<PathBuf> {
    match dirs::home_dir() {
        Some(mut dir) => {
            dir.push(".pswm");
            Ok(dir)
        }
        None => Err(ErrorKind::HomeDir.without_source_error()),
    }
}

pub fn create_passwords_file_dialog(path: &Path) -> Result<EncryptedFile> {
    println!("{}", warning_style().paint("Passwords file not found"));
    let master_password = prompt_user_to_create_master_password(
        "Enter a master password for the new passwords file: ",
    )?;
    let mut file = EncryptedFile::create(path, &master_password)?;
    {
        let mut writer = file.writer();
        writer.write_passwords(&[]);
        writer.flush()?;
        println!(
            "{}",
            success_style().paint("The passwords file was successfully created")
        );
    }
    Ok(file)
}
