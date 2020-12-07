pub mod printing;
use printing::*;

use crate::{
    input::prompt_user_to_unlock_file_with_password, passwords::iterator::PasswordIterator,
};
use crate::{
    locker::{
        encrypt::LockedEncryptedFile,
        errors::{ErrorKind, Result},
    },
    passwords::{
        filter::{Filter, PasswordFilter},
        sort::{Sort, SortBy, SortedPasswords},
        Password,
    },
};
use fallible_iterator::FallibleIterator;
use std::path::PathBuf;

fn get_passwords_file_path() -> Result<PathBuf> {
    match dirs::home_dir() {
        Some(dir) => {
            dir.push(".pswm");
            Ok(dir)
        }
        None => Err(ErrorKind::HomeDir.without_source_error()),
    }
}
fn get(filter: PasswordFilter, sort_by: Option<SortBy>, printing_mode: PrintingMode) -> Result<()> {
    let file = LockedEncryptedFile::open_readonly(get_passwords_file_path()?)?;
    let unlocked_file = prompt_user_to_unlock_file_with_password(file, "Enter master password: ")?;
    let passwords = PasswordIterator::new(unlocked_file)?;
    let total_matches = 0usize;
    match (filter.is_redundant(), sort_by) {
        (true, None) => print_passwords(passwords, printing_mode),
        (true, Some(s)) => print_sorted_passwords(passwords.sort(s), printing_mode),
        (false, None) => print_passwords(passwords.filter(filter), printing_mode),
        (false, Some(s)) => print_sorted_passwords(passwords.filter(filter).sort(s), printing_mode),
    }
    Ok(())
}
