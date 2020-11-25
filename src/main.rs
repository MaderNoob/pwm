mod locker;
mod commands;
mod input;
use std::fs::{File, OpenOptions};
use std::io::Write;

use locker::encrypt::{EncryptedFile, Encryptor, LockedEncryptedFile};
fn main() {
    // commands::lock::lock_command("test.txt", "suka noob", false);
    // commands::unlock::unlock_command("test.txt");
}
