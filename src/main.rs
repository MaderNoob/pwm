mod wrapped_clipboard;
mod commands;
mod input;
mod locker;
mod passwords;
mod styles;
mod vec_io;
use commands::pwm::printing::PrintingMode;
use passwords::{PasswordFilter, PasswordGeneratorOptions, SortBy};
use std::collections::HashMap;
fn main() {
    let filter = PasswordFilter::new(None, Some("git".to_string()), None, HashMap::new());
    commands::pwm::get_command(
        filter,
        Some(SortBy::Other("Phone Number".to_string())),
        PrintingMode::Verbose,
    );
    // commands::pwm::new_command(
    //     None,
    //     "roee_.s".to_string(),
    //     "instagram.com".to_string(),
    //     HashMap::new(),
    //     PasswordGeneratorOptions::new(),
    // );
}
