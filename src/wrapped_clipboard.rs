use crate::locker::{io_to_locker_error, to_locker_error, ErrorKind, Result};
use clipboard::{x11_clipboard::X11ClipboardContext, ClipboardProvider};
use std::io::Write;
use std::process::{Command, Stdio};
pub fn clipboard_set(content: &str) -> Result<()> {
    let mut child = io_to_locker_error(
        Command::new("xclip")
            .args(&["-in", "-selection", "clipboard"])
            .stdin(Stdio::piped())
            .spawn(),
        ErrorKind::CopyToClipboard,
    )?;

    let stdin = match child.stdin {
        Some(ref mut stdin) => stdin,
        None => return Err(ErrorKind::CopyToClipboard.without_source_error()),
    };

    match stdin.write(content.as_bytes()) {
        Ok(_)=>Ok(()),
        Err(e)=>Err(ErrorKind::CopyToClipboard.with_source_error(e)),
    }
}
