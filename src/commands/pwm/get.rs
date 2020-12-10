use crate::{
    wrapped_clipboard,
    input::prompt_user_to_unlock_file_with_password,
    locker::{print_error, EncryptedFile, LockedEncryptedFile, MutableFile, Result},
    passwords::{Filter, PasswordFilter, PasswordIterator, Sort, SortBy},
    styles::error_style,
};

use super::{
    create_passwords_file_dialog, get_passwords_file_path,
    printing::{print_passwords, print_sorted_passwords, PrintingMode},
};
pub fn get_passwords_from_unlocked_file(
    file: &mut EncryptedFile,
    filter: PasswordFilter,
    sort_by: Option<SortBy>,
    printing_mode: PrintingMode,
) -> Result<()> {
    let passwords = PasswordIterator::new(file);
    match (filter.is_redundant(), sort_by) {
        (true, None) => print_passwords(passwords, printing_mode)?,
        (true, Some(s)) => print_sorted_passwords(passwords.sort(s)?, printing_mode)?,
        (false, None) => print_passwords(passwords.filter_passwords(filter), printing_mode)?,
        (false, Some(s)) => {
            print_sorted_passwords(passwords.filter_passwords(filter).sort(s)?, printing_mode)?
        }
    };
    Ok(())
}
fn get(filter: PasswordFilter, sort_by: Option<SortBy>, printing_mode: PrintingMode) -> Result<()> {
    let path = get_passwords_file_path()?;
    let mut unlocked_file = if path.exists() {
        prompt_user_to_unlock_file_with_password(
            LockedEncryptedFile::open_readonly(path)?,
            "Enter master password: ",
        )?
    } else {
        create_passwords_file_dialog(&path)?;
        return Ok(());
    };
    match get_passwords_from_unlocked_file(&mut unlocked_file, filter, sort_by, printing_mode) {
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
