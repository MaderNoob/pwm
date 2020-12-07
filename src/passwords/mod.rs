pub mod io;
pub mod iterator;
pub mod filter;
pub mod sort;

use std::collections::HashMap;

#[derive(Debug)]
pub struct Password{
    pub password:String,
    pub domain:String,
    pub username:String,
    pub email:Option<String>,
    pub additional_fields:HashMap<String,String>,
}
