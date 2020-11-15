mod locker;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read,BufRead};

use chacha20poly1305::aead::{Aead, AeadInPlace, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key};
fn main() {
    let mut reader = BufReader::new(
        OpenOptions::new()
            .read(true)
            .open("/home/clear/Documents/cpp/interpreter/first_interpreter/main.cpp")
            .unwrap(),
    );
    let buf=reader.fill_buf().unwrap();
    // for i in buf{
    //     println!("{}",*i as char);
    // }
    let used=buf.len();
    reader.consume(used);
    let second=reader.fill_buf().unwrap();
    println!("second's length: {}",second.len());
}
