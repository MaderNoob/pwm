#[derive(Debug)]
pub enum Error{
    OpenFile,
    ReadFile,
    WriteFile,
    SeekFile,
    TruncateFile,
    FileGetFlags,
    FileSetFlags,
    FileNotEncryptedProperly,
    GetFileMetadata,
    FileTooBig,
    MacError,
    WrongPassword,
    EncryptionError,
}
pub type Result<T> = std::result::Result<T,Error>;
pub fn map_to_locker_error<T,E>(result:std::result::Result<T,E>,locker_error:Error)->Result<T>
where E:std::fmt::Debug{
    match result{
        Ok(v)=>Ok(v),
        Err(e)=>{
            println!("error: {:?}",e);
            Err(locker_error)
        },
    }
}