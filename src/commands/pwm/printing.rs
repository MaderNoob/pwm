use crate::{
    locker::{Error, Result},
    passwords::{SortBy, SortedPasswords},
    styles::warning_style,
};
use crate::{passwords::Password, styles::PasswordPrintingStyles};
use fallible_iterator::FallibleIterator;
pub enum PrintingMode {
    Normal,
    Verbose,
}
pub fn print_passwords<T: FallibleIterator<Item = Password, Error = Error>>(
    mut passwords_iter: T,
    printing_mode: PrintingMode,
) -> Result<()> {
    let styles = crate::styles::passwords_printing_styles();
    let mut total = 0usize;
    while let Some(password) = passwords_iter.next()? {
        print_single_password(password, &printing_mode, &styles);
        total += 1;
    }
    if total == 0 {
        println!("{}", warning_style().paint("No Results"));
    }
    Ok(())
}

pub fn print_sorted_passwords(sorted_passwords: SortedPasswords, printing_mode: PrintingMode) {
    let styles = crate::styles::passwords_printing_styles();
    let mut total = 0usize;
    for (sort_field_value, passwords) in sorted_passwords.entries {
        let sort_field_value_string = match sort_field_value {
            Some(s) => s,
            None => "none".to_string(),
        };
        println!(
            "{}",
            styles.sort_field_value_style.paint(sort_field_value_string),
        );
        for password in passwords {
            print_single_password_indented(password, &printing_mode, &styles);
            total += 1;
        }
    }
    if total == 0 {
        println!("{}", warning_style().paint("no results"));
    }
}

fn print_single_password(
    password: Password,
    printing_mode: &PrintingMode,
    styles: &PasswordPrintingStyles,
) {
    match printing_mode {
        PrintingMode::Normal => {
            println!(
                "{}{}{}: '{}'",
                styles.username_style.paint(password.username),
                styles.at_symbol_style.paint("@"),
                styles.domain_style.paint(password.domain),
                styles.password_style.paint(password.password)
            );
        }
        PrintingMode::Verbose => {
            println!(
                "{}{}{}",
                styles.username_style.paint(password.username),
                styles.at_symbol_style.paint("@"),
                styles.domain_style.paint(password.domain),
            );
            for (field_name, field_value) in password.additional_fields {
                println!(
                    " - {}: '{}'",
                    styles.field_name_style.paint(field_name),
                    styles.field_value_style.paint(field_value),
                );
            }
            println!(
                " - {}: '{}'",
                styles.password_style.paint("password"),
                styles.password_style.paint(password.password)
            );
            println!();
        }
    }
}
fn print_single_password_indented(
    password: Password,
    printing_mode: &PrintingMode,
    styles: &PasswordPrintingStyles,
) {
    match printing_mode {
        PrintingMode::Normal => {
            println!(
                "\t{}{}{}: '{}'",
                styles.username_style.paint(password.username),
                styles.at_symbol_style.paint("@"),
                styles.domain_style.paint(password.domain),
                styles.password_style.paint(password.password)
            );
        }
        PrintingMode::Verbose => {
            println!(
                "\t{}{}{}",
                styles.username_style.paint(password.username),
                styles.at_symbol_style.paint("@"),
                styles.domain_style.paint(password.domain),
            );
            for (field_name, field_value) in password.additional_fields {
                println!(
                    "\t - {}: '{}'",
                    styles.field_name_style.paint(field_name),
                    styles.field_value_style.paint(field_value),
                );
            }
            println!(
                "\t - {}: '{}'",
                styles.password_style.paint("password"),
                styles.password_style.paint(password.password)
            );
            println!();
        }
    }
}
