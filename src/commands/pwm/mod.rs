pub mod get;
pub mod master_password;
pub mod printing;
use printing::*;

use crate::{input::prompt_user_to_create_master_password, input::prompt_user_to_unlock_file_with_password, locker::{encrypt::{EncryptedFile, EncryptedFileWriter}, io::Write}, passwords::iterator::PasswordIterator, styles::{success_style, warning_style}};
use crate::{
    locker::{
        encrypt::{inner_files::InnerEncryptedFile, LockedEncryptedFile},
        errors::{ErrorKind, Result},
        flags::MutableFile,
    },
    passwords::{
        filter::{Filter, PasswordFilter},
        io::PasswordWriter,
        sort::{Sort, SortBy, SortedPasswords},
        Password,
    },
};
use fallible_iterator::FallibleIterator;
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
        writer.write_passwords(&[])?;
        writer.flush()?;
        println!(
            "{}",
            success_style().paint("The passwords file was successfully created")
        );
    }
    Ok(file)
}
