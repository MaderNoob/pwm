mod locker;
use std::fs::{File, OpenOptions};
use std::io::Write;

use locker::encrypt::{EncryptedFile, Encryptor, LockedEncryptedFile};
fn main() {
   //  locker::lock("test.txt","suka noob", false).unwrap();
    let mut file = LockedEncryptedFile::open_write("test.txt")
        .unwrap()
        .unlock("suka noob")
        .unwrap();
}
