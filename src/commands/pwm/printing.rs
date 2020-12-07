use crate::{locker::errors::{Error, Result}, passwords, styles};
use crate::passwords::Password;
use ansi_term::Style;
use fallible_iterator::FallibleIterator;
use passwords::sort::SortedPasswords;
pub enum PrintingMode {
    Normal,
    Verbose,
}
pub fn print_passwords<T: FallibleIterator<Item = Password, Error = Error>>(
    passwords_iter: T,
    printing_mode: PrintingMode,
) -> Result<()> {
    let style=crate::styles::password_style();
    while let Some(password) = passwords_iter.next()?{
        print_single_password(password, printing_mode, &style)
    }
    Ok(())
}

pub fn print_sorted_passwords(sorted_passwords:SortedPasswords,printing_mode: PrintingMode){
    let style=crate::styles::password_style();
    for (sort_field_value,passwords) in sorted_passwords{
        let sort_field_value_string=match sort_field_value{
            Some(s)=>&s,
            None=>"None"
        };
        match term_size::dimensions(){
            Some((width,height))=>println!("{:=^width$}",sort_field_value_string,width=width),
            None=>println!("{}",sort_field_value_string),
        }
        for password in passwords{
            print_single_password_indented(password, printing_mode, &style);
        }
    }
}

struct CapitalizedString{
    source:String,
}
trait Capitalized{
    fn capitalized(self)->CapitalizedString;
}
impl Capitalized for String{
    fn capitalized(self) ->CapitalizedString {
        CapitalizedString{
            source:self
        }
    }
}
impl std::fmt::Display for CapitalizedString{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"{}",match self.source.chars().next(){
            Some(c)=>c.to_uppercase(),
            None=>return Ok(())
        })?;
        write!(f,"{}",&self.source[1..])
    }
}

fn print_single_password(password:Password,printing_mode: PrintingMode,password_style:&Style){
    match printing_mode{
        PrintingMode::Normal=>{
            println!("{}@{}: '{}'",password.username,password.domain,password_style.paint(password.password));
        },
        PrintingMode::Verbose=>{
            println!("{}@{}",password.username,password.domain);
            println!(" - Password: '{}'",password_style.paint(password.password));
            if let Some(email)=password.email{
                println!(" - Email: '{}'",email);
            }
            for (field_name,field_value) in password.additional_fields{
                println!(" - {}: '{}'",field_name.capitalized(), field_value);
            }
            println!();
        }
    }
}
fn print_single_password_indented(password:Password,printing_mode: PrintingMode,password_style:&Style){
    match printing_mode{
        PrintingMode::Normal=>{
            println!("\t{}@{}: '{}'",password.username,password.domain,password_style.paint(password.password));
        },
        PrintingMode::Verbose=>{
            println!("\t{}@{}",password.username,password.domain);
            println!("\t - Password: '{}'",password_style.paint(password.password));
            if let Some(email)=password.email{
                println!("\t - Email: '{}'",email);
            }
            for (field_name,field_value) in password.additional_fields{
                println!("\t - {}: '{}'",field_name.capitalized(), field_value);
            }
            println!();
        }
    }
}

