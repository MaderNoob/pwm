use std::collections::HashMap;

use crate::locker::errors::{Error, Result};
use crate::passwords::Password;
#[derive(Debug)]
pub enum SortBy {
    Domain,
    Username,
    Email,
    Other(String),
}

impl std::fmt::Display for SortBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Domain => write!(f, "domain"),
            Username => write!(f, "username"),
            Email => write!(f, "email"),
            SortBy::Other(name) => write!(f, "{}", name),
        }
    }
}

pub type SortedPasswords = HashMap<Option<String>, Vec<Password>>;

trait GetSortFieldValue {
    fn get_sort_field_value(&self, sort_by: &SortBy) -> Option<String>;
}
impl GetSortFieldValue for Password {
    fn get_sort_field_value(&self, sort_by: &SortBy) -> Option<String> {
        match sort_by {
            SortBy::Domain => Some(self.domain),
            SortBy::Username => Some(self.username),
            SortBy::Email => self.email,
            SortBy::Other(field_name) => self.additional_fields.get(field_name).cloned(),
        }
    }
}
pub trait Sort{
    fn sort(self, sort_by: SortBy) -> Result<SortedPasswords>;
}
impl<T: fallible_iterator::FallibleIterator<Item = Password, Error = Error>> Sort for T {
    fn sort(self, sort_by: SortBy) -> Result<SortedPasswords> {
        let result = SortedPasswords::new();
        while let Some(password) = self.next()? {
            let sort_field_value=password.get_sort_field_value(&sort_by);
            match result.get_mut(&sort_field_value){
                Some(values)=>values.push(password),
                None=>{
                    result.insert(sort_field_value, vec![password]);
                }
            }
        }
        Ok(result)
    }
}
