use std::collections::HashMap;

use crate::{input::prompt_user_to_unlock_file_with_password, locker::{
        print_error, EncryptedFile, EncryptedFlush, LockedEncryptedFile, MutableFile, Result,
    }, passwords::{Filter, Password, PasswordFilter, PasswordIterator, PasswordWriter, Sort, SortBy, generate_password}, styles::error_style};

use super::{create_passwords_file_dialog, get_passwords_file_path};
pub fn add_password_to_unlocked_file(file: &mut EncryptedFile, password: &Password) -> Result<()> {
    let appender = file.appender();
    appender.write_password(&password);
    appender.flush()
}
fn new(
    password: Option<String>,
    username: String,
    domain: String,
    additional_fields: HashMap<String, String>,
    password_length:Option<usize>,
    use_lowercase:
) -> Result<()> {
    let path = get_passwords_file_path()?;
    let mut unlocked_file = if path.exists() {
        prompt_user_to_unlock_file_with_password(
            LockedEncryptedFile::open_readonly(path)?,
            "Enter master password: ",
        )?
    } else {
        create_passwords_file_dialog(&path)?
    };
    match add_password_to_unlocked_file(&mut unlocked_file, &Password{
        password:password.unwrap_or_else(|| generate_password(length, use_lowercase, use_uppercase, use_digits, use_symbols))
    }) {
        Ok(()) => Ok(()),
        Err(err) => {
            unlocked_file.make_immutable()?;
            Err(err)
        }
    }
}

pub fn get_command(filter: PasswordFilter, sort_by: Option<SortBy>, printing_mode: PrintingMode) {
    if let Err(error) = get(filter, sort_by, printing_mode) {
        print_error(error, "passwords", &error_style());
    }
}
