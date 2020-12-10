use crate::locker::{Error, Result};
use crate::passwords::{iterator::PasswordIterator, Password};
use fallible_iterator::FallibleIterator;
use std::collections::HashMap;

pub struct PasswordFilter {
    password_filter: Option<String>,
    domain_filter: Option<String>,
    username_filter: Option<String>,
    additional_filters: HashMap<String, String>,
}
impl PasswordFilter {
    pub fn new(
        password_filter: Option<String>,
        domain_filter: Option<String>,
        username_filter: Option<String>,
        additional_filters: HashMap<String, String>,
    ) -> PasswordFilter {
        PasswordFilter {
            password_filter,
            domain_filter,
            username_filter,
            additional_filters,
        }
    }
    pub fn test(&self, password: &Password) -> bool {
        if let Some(pf) = &self.password_filter {
            if !password.password.contains(&pf[..]) {
                return false;
            }
        }
        if let Some(df) = &self.domain_filter {
            if !password.domain.contains(&df[..]) {
                return false;
            }
        }
        if let Some(uf) = &self.username_filter {
            if !password.username.contains(&uf[..]) {
                return false;
            }
        }
        for (filter_key, filter) in &self.additional_filters {
            match password.additional_fields.get(filter_key) {
                Some(value) => {
                    if !value.contains(&filter[..]) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
    pub fn is_redundant(&self) -> bool {
        /*
             password_filter: Option<String>,
        domain_filter: Option<String>,
        username_filter: Option<String>,
        email_filter: Option<String>,
        additional_filters: HashMap<String, String>,
            */
        self.password_filter.is_none()
            && self.domain_filter.is_none()
            && self.username_filter.is_none()
            && self.additional_filters.is_empty()
    }
}

pub struct FilteredPasswordIterator<'a> {
    iterator: PasswordIterator<'a>,
    filter: PasswordFilter,
}

impl<'a> FallibleIterator for FilteredPasswordIterator<'a> {
    type Item = Password;
    type Error = Error;
    fn next(&mut self) -> Result<Option<Password>> {
        loop {
            match self.iterator.next()? {
                Some(p) => {
                    if self.filter.test(&p) {
                        return Ok(Some(p));
                    }
                }
                None => return Ok(None),
            }
        }
    }
}

pub trait Filter<'a> {
    fn filter_passwords(self, filter: PasswordFilter) -> FilteredPasswordIterator<'a>;
}
impl<'a> Filter<'a> for PasswordIterator<'a> {
    fn filter_passwords(self, filter: PasswordFilter) -> FilteredPasswordIterator<'a> {
        FilteredPasswordIterator {
            iterator: self,
            filter,
        }
    }
}
