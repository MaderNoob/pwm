use ansi_term::{Color,Style};

use crate::passwords::SortBy;

pub fn error_style()->Style{
    Color::Red.bold()
}
pub fn success_style()->Style{
    Color::Green.bold()
}
pub fn warning_style()->Style{
    Color::Yellow.normal()
}
pub struct PasswordPrintingStyles{
    pub password_style:Style,
    pub username_style:Style,
    pub domain_style:Style,
    pub at_symbol_style:Style,
    pub field_name_style:Style,
    pub field_value_style:Style,
    pub sort_field_value_style:Style,
}
pub fn passwords_printing_styles()->PasswordPrintingStyles{
    PasswordPrintingStyles{
        password_style:Color::Green.bold(),
        username_style:Color::Purple.bold(),
        domain_style:Color::Purple.bold(),
        at_symbol_style:Color::White.bold(),
        field_name_style:Color::Cyan.normal(),
        field_value_style:Color::Cyan.normal(),
        sort_field_value_style:Color::White.bold(),
    }
}