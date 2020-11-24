use std::fs;
use crate::locker::errors::{Result,Error};

pub enum UnixFileFlag {
    Immutable = 0x10,
}
pub struct UnixFileFlags {
    value: i32,
}
impl UnixFileFlags {
    pub fn is_flag_set(&self,flag: UnixFileFlag) -> bool {
        self.value & (flag as i32) != 0
    }
    pub fn set_flag(&mut self,flag:UnixFileFlag){
        self.value |= flag as i32
    }
    pub fn unset_flag(&mut self,flag:UnixFileFlag){
        self.value &=!(flag as i32);
    }
}
pub trait UnixFile {
    fn get_unix_flags(&self) -> Result<UnixFileFlags>;
    fn set_unix_flags(&self, new_flags: UnixFileFlags) -> Result<()>;
}
#[cfg(unix)]
impl UnixFile for fs::File {
    fn get_unix_flags(&self) -> Result<UnixFileFlags> {
        let mut flags = 0;
        let flags_ptr = &mut flags as *mut i32;
        unsafe {
            use std::os::unix::io::AsRawFd;
            if libc::ioctl(self.as_raw_fd(), 2148034049, flags_ptr) < 0 {
                Err(Error::FileGetFlags)
            } else {
                Ok(UnixFileFlags{
                    value:flags
                })
            }
        }
    }
    fn set_unix_flags(&self, mut new_flags: UnixFileFlags) -> Result<()> {
        let flags_ptr = &mut new_flags.value as *mut i32;
        unsafe {
            use std::os::unix::io::AsRawFd;
            if libc::ioctl(self.as_raw_fd(), 1074292226, flags_ptr) < 0 {
                Err(Error::FileSetFlags)
            } else {
                Ok(())
            }
        }
    }
}
pub trait MutableFile{
    fn make_mutable(&mut self)->Result<()>;
    fn make_immutable(&mut self)->Result<()>;
}
impl<T> MutableFile for T
where T:UnixFile{
    fn make_mutable(&mut self) ->Result<()> {
        let mut flags=self.get_unix_flags()?;
        if flags.is_flag_set(UnixFileFlag::Immutable){
            flags.unset_flag(UnixFileFlag::Immutable);
            self.set_unix_flags(flags)
        }else{
            Ok(())
        }
    }
    fn make_immutable(&mut self) ->Result<()> {
        let mut flags=self.get_unix_flags()?;
        if !flags.is_flag_set(UnixFileFlag::Immutable){
            flags.set_flag(UnixFileFlag::Immutable);
            self.set_unix_flags(flags)
        }else{
            Ok(())
        }
    }
}