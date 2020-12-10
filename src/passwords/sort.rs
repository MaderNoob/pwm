use std::collections::HashMap;

use crate::locker::{Error, Result};
use crate::passwords::Password;
#[derive(Debug, Clone)]
pub enum SortBy {
    Domain,
    Username,
    Other(String),
}

pub struct SortedPasswords{
    pub sort_by:SortBy,
    pub entries:HashMap<Option<String>, Vec<Password>>,
}

trait GetSortFieldValue {
    fn get_sort_field_value(&self, sort_by: &SortBy) -> Option<String>;
}
impl GetSortFieldValue for Password {
    fn get_sort_field_value(&self, sort_by: &SortBy) -> Option<String> {
        match sort_by {
            SortBy::Domain => Some(self.domain.clone()),
            SortBy::Username => Some(self.username.clone()),
            SortBy::Other(field_name) => self.additional_fields.get(field_name).cloned(),
        }
    }
}
pub trait Sort{
    fn sort(self, sort_by: SortBy) -> Result<SortedPasswords>;
}
impl<T: fallible_iterator::FallibleIterator<Item = Password, Error = Error>> Sort for T {
    fn sort(mut self, sort_by: SortBy) -> Result<SortedPasswords> {
        let mut result = SortedPasswords{
            sort_by:sort_by.clone(),
            entries:HashMap::new(),
        };
        while let Some(password) = self.next()? {
            let sort_field_value=password.get_sort_field_value(&sort_by);
            match result.entries.get_mut(&sort_field_value){
                Some(values)=>values.push(password),
                None=>{
                    result.entries.insert(sort_field_value, vec![password]);
                }
            }
        }
        Ok(result)
    }
}
