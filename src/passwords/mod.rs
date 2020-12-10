mod io;
mod iterator;
mod filter;
mod sort;
mod generator;
pub use {io::*,iterator::*,sort::*,filter::*,generator::*};

use std::collections::HashMap;

#[derive(Debug)]
pub struct Password{
    pub password:String,
    pub domain:String,
    pub username:String,
    pub additional_fields:HashMap<String,String>,
}
