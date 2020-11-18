pub enum Error{
    OpenFile,
    ReadFile,
    WriteFile,
    FileGetFlags,
    FileSetFlags,
    FileNotEncryptedProperly,
}
pub type Result<T> = std::result::Result<T,Error>;
pub fn map_to_locker_error<T,E>(result:std::result::Result<T,E>,locker_error:Error)->Result<T>{
    match result{
        Ok(v)=>Ok(v),
        Err(_)=>Err(locker_error),
    }
}