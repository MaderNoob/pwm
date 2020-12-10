use std::collections::HashMap;

use crate::{wrapped_clipboard,input::prompt_user_to_unlock_file_with_password, locker::{
        print_error, EncryptedFile, EncryptedFlush, LockedEncryptedFile, MutableFile, Result,
    }, passwords::{
        generate_password, Filter, Password, PasswordFilter, PasswordGeneratorOptions,
        PasswordWriter, Sort, SortBy,
    }, styles::{error_style, success_style}};

use super::{create_passwords_file_dialog, get_passwords_file_path};
pub fn add_password_to_unlocked_file(file: &mut EncryptedFile, password: &Password) -> Result<()> {
    let mut appender = file.appender();
    appender.write_password(&password);
    appender.flush()
}
// returns true if the new password was newly generated,
// otherwise if it was supplied the function returns false
fn new(
    password: Option<String>,
    username: String,
    domain: String,
    additional_fields: HashMap<String, String>,
    password_generator_options: PasswordGeneratorOptions,
) -> Result<bool> {
    let mut is_password_generated=false;
    let path = get_passwords_file_path()?;
    let mut unlocked_file = if path.exists() {
        prompt_user_to_unlock_file_with_password(
            LockedEncryptedFile::open_write(path)?,
            "Enter master password: ",
        )?
    } else {
        create_passwords_file_dialog(&path)?
    };
    let password = Password {
        password: match password {
            Some(p) => p,
            None => {
                let pwd=generate_password(&password_generator_options)?;
                is_password_generated=true;
                wrapped_clipboard::clipboard_set(&pwd)?;
                pwd
            },
        },
        username,
        domain,
        additional_fields,
    };
    match add_password_to_unlocked_file(&mut unlocked_file, &password) {
        Ok(()) => Ok(is_password_generated),
        Err(err) => {
            unlocked_file.make_immutable()?;
            Err(err)
        }
    }
}

pub fn new_command(
    password: Option<String>,
    username: String,
    domain: String,
    additional_fields: HashMap<String, String>,
    password_generator_options: PasswordGeneratorOptions,
) {
    match new(
        password,
        username,
        domain,
        additional_fields,
        password_generator_options,
    ) {
        Ok(was_password_generated) => {
            if was_password_generated {
                println!(
                    "{}",
                    success_style()
                        .paint("The password was successfully generated and copied to the clipboard")
                )
            } else {
                println!(
                    "{}",
                    success_style()
                        .paint("The password was successfully added to the passwords file")
                )
            }
        }
        Err(e) => print_error(e, "passwords", &error_style()),
    }
}
