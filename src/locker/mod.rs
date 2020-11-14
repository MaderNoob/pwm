mod flags;
pub enum Error{
    FileGetFlags,
    FileSetFlags,
}
pub type Result<T> = std::result::Result<T,Error>;