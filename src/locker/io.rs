use crate::locker::errors::{io_to_locker_error,ErrorKind,Result};

pub trait Read {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()>;
    fn read_until(&mut self, terminator: u8) -> Vec<u8>;
}
pub trait Write {
    fn write(&mut self, byte: u8) -> Result<&mut Self>;
    fn write_all(&mut self, buf: &[u8]) -> Result<&mut Self>;
    fn flush(self)->Result<()>;
}
