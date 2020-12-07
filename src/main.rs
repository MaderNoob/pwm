mod commands;
mod input;
mod locker;
mod passwords;
mod styles;
mod vec_reader;
use commands::pwm::printing::PrintingMode;
use fallible_iterator::FallibleIterator;
use locker::encrypt::{EncryptedFile, Encryptor, LockedEncryptedFile};
use locker::io::Write;
use passwords::{
    filter::PasswordFilter, io::*, iterator::PasswordIterator, sort::SortBy, Password,
};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    path::Path,
    ptr::read,
};
fn main() {
    let filter = PasswordFilter::new(None, None, None, None, HashMap::new());
    commands::pwm::get::get(filter, None, PrintingMode::Normal).unwrap();
    // commands::lock::lock_command("test.txt", "suka noob", false);
    // commands::unlock::unlock_command("test.txt");
}
