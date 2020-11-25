use ansi_term::{Color,Style};

pub fn error_style()->Style{
    Color::Red.bold()
}
pub fn success_style()->Style{
    Color::Green.bold()
}
