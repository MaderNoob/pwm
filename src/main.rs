mod locker;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read,BufRead};

use locker::encrypt::Encryptor;
fn main() {
   locker::lock("sfasfsaf","suka noob", true);
   let x=5;
}
