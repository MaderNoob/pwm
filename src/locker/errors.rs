#[derive(Debug)]
pub enum Error{
    OpenFile,
    ReadFile,
    WriteFile,
    SeekFile,
    FileGetFlags,
    FileSetFlags,
    FileNotEncryptedProperly,
    GetFileMetadata,
    FileTooBig,
    MacError,
    WrongPassword,
    EncryptionError,
    DecryptionError,
}
pub type Result<T> = std::result::Result<T,Error>;
pub fn map_to_locker_error<T,E>(result:std::result::Result<T,E>,locker_error:Error)->Result<T>
where E:std::fmt::Debug{
    match result{
        Ok(v)=>Ok(v),
        Err(_)=>Err(locker_error),
    }
}