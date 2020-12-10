use crate::locker::Result;

pub trait EncryptedRead {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()>;
    fn read_until(&mut self, terminator: u8) -> Vec<u8>;
}
pub trait EncryptedWrite {
    fn write(&mut self, byte: u8) -> &mut Self;
    fn write_all(&mut self, buf: &[u8]) -> &mut Self;
}
pub trait EncryptedFlush{
    fn flush(self) -> Result<()>;
}
