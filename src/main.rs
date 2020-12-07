mod commands;
mod input;
mod locker;
mod passwords;
mod styles;
mod vec_reader;
use passwords::{Password, io::*, iterator::PasswordIterator};
use std::{collections::HashMap, fs::{File, OpenOptions}, path::Path, ptr::read};
use fallible_iterator::FallibleIterator;
use locker::encrypt::{EncryptedFile, Encryptor, LockedEncryptedFile};
use locker::io::Write;
fn main() {
    // commands::lock::lock_command("test.txt", "suka noob", false);
    // commands::unlock::unlock_command("test.txt");
}
