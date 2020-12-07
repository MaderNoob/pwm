use crate::commands::pwm::master_password::check_master_password;
use crate::locker::encrypt::{EncryptedFile, LockedEncryptedFile};
use crate::locker::errors::{print_error, ErrorKind, Result};
use ansi_term::Style;
use std::io::{Stdout, Write};
fn flush_stdout_and_read_password(stdout: &mut Stdout) -> std::io::Result<String> {
    stdout.flush()?;
    rpassword::read_password()
}
pub fn prompt_user_to_unlock_file_with_password(
    mut file: LockedEncryptedFile,
    prompt: &str,
) -> Result<EncryptedFile> {
    let mut stdout = std::io::stdout();
    loop {
        print!("{}", prompt);
        match flush_stdout_and_read_password(&mut stdout) {
            Err(e) => break Err(ErrorKind::PromptPasswordIOError.with_source_error(e)),
            Ok(password) => {
                if file.test_key(&password) {
                    break file.unlock(&password);
                } else {
                    println!("Wrong password");
                    println!();
                }
            }
        }
    }
}

pub fn prompt_user_to_create_master_password(prompt: &str) -> Result<String> {
    let mut stdout = std::io::stdout();
    loop {
        print!("{}", prompt);
        match flush_stdout_and_read_password(&mut stdout) {
            Err(e) => break Err(ErrorKind::PromptPasswordIOError.with_source_error(e)),
            Ok(password) => match check_master_password(&password) {
                Ok(()) => return Ok(password),
                Err(err) => {
                    println!("{}", err);
                    println!();
                }
            },
        }
    }
}
