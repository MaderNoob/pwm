use std::{path,fs,io};
use std::io::{BufRead,Write};
use crate::locker::errors::{Result,Error,map_to_locker_error};
pub trait OpenWithLockerError{
    fn open_with_locker_error<P:AsRef<path::Path>>(&self,path:P)->Result<fs::File>;
}
impl OpenWithLockerError for fs::OpenOptions{
    fn open_with_locker_error<P:AsRef<path::Path>>(&self,path:P) ->Result<fs::File>{
        map_to_locker_error(self.open(path), Error::OpenFile)
    }
}
pub trait FillBufWithLockerError{
    fn fill_buf_with_locker_error(&mut self)->Result<&[u8]>;
}
impl FillBufWithLockerError for io::BufReader<fs::File>{
    fn fill_buf_with_locker_error(&mut self) ->Result<&[u8]> {
        map_to_locker_error(self.fill_buf(),Error::ReadFile)
    }
}
pub trait WriteExactWithLockerError{
    fn write_all_with_locker_error(&mut self,buf:&[u8])->Result<()>;
}
impl WriteExactWithLockerError for io::BufWriter<fs::File>{
    fn write_all_with_locker_error(&mut self, buf:&[u8]) ->Result<()> {
        map_to_locker_error(self.write_all(buf),Error::WriteFile)
    }
}
