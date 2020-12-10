use rand::{thread_rng, Rng, RngCore};

use crate::locker::{ErrorKind, Result};

pub const DEFAULT_PASSWORD_LENGTH: usize = 20;

pub struct PasswordGeneratorOptions {
    pub password_length: usize,
    pub use_lowercase: bool,
    pub use_uppercase: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
}

impl PasswordGeneratorOptions {
    pub fn new() -> PasswordGeneratorOptions {
        PasswordGeneratorOptions {
            password_length: DEFAULT_PASSWORD_LENGTH,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_symbols: true,
        }
    }
    pub fn get_dictionary(&self) -> Result<Vec<char>> {
        if !self.use_lowercase && !self.use_uppercase && !self.use_digits && !self.use_symbols {
            return Err(ErrorKind::EmptyPasswordDict.without_source_error());
        }
        let mut dict = Vec::new();
        if self.use_lowercase {
            dict.extend("abcdefghijklmnopqrstuvwxyz".chars());
        }
        if self.use_uppercase {
            dict.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars());
        }
        if self.use_digits {
            dict.extend("0123456789".chars());
        }
        if self.use_symbols {
            dict.extend(" !\"#$%&'()*+,-./:;<=>?@[\\]^_.chars())`{|}~".chars());
        }
        Ok(dict)
    }
}

pub fn generate_password(options: &PasswordGeneratorOptions) -> Result<String> {
    if options.password_length == 0 {
        return Err(ErrorKind::PasswordLengthZero.without_source_error());
    }
    let dict = options.get_dictionary()?;
    let dict_length = dict.len();
    let mut random = thread_rng();
    let mut result=String::with_capacity(options.password_length);
    for _ in 0..options.password_length{
        result.push(dict[random.gen_range::<usize, _, _>(0, dict_length)])
    }
    Ok(result)
}
