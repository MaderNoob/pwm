#[derive(Debug)]
pub enum ErrorKind {
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
    RevertToBackup,
    PromptPasswordIOError,
    EncodingError,
    CorruptedFile,
    HomeDir,
}
impl ErrorKind {
    pub fn without_source_error(self) -> Error {
        Error {
            kind: self,
            source_error: None,
        }
    }
    pub fn with_source_error(self, source_error: std::io::Error) -> Error {
        Error {
            kind: self,
            source_error: Some(source_error),
        }
    }
}
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source_error: Option<std::io::Error>,
}
impl Error {
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
    pub fn with_kind(self,kind:ErrorKind)->Error{
        Error{
            kind,
            source_error:self.source_error,
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub fn io_to_locker_error<T>(result: std::io::Result<T>, error_kind: ErrorKind) -> Result<T> {
    match result {
        Ok(v) => Ok(v),
        Err(e) => Err(Error {
            kind: error_kind,
            source_error: Some(e),
        }),
    }
}
pub fn to_locker_error<T, E>(
    result: std::result::Result<T, E>,
    error_kind: ErrorKind,
) -> Result<T> {
    match result {
        Ok(v) => Ok(v),
        Err(e) => Err(Error {
            kind: error_kind,
            source_error: None,
        }),
    }
}
pub fn print_error(error: Error, file_prefix: &str, error_style: &ansi_term::Style) {
    let source_error_str = match error.source_error {
        Some(e) => format!(": {}", e),
        None => String::new(),
    };
    let err=match error.kind{
        ErrorKind::OpenFile=>format!("Failed to open the {} file{}",file_prefix,source_error_str),
        ErrorKind::ReadFile=>format!("Failed to read the {} file{}",file_prefix,source_error_str),
        ErrorKind::WriteFile=>format!("Failed to write to the {} file{}",file_prefix,source_error_str),
        ErrorKind::SeekFile=>format!("Failed to seek inside the {} file{}",file_prefix,source_error_str),
        ErrorKind::TruncateFile=>format!("Failed to truncate the {} file{}",file_prefix,source_error_str),
        ErrorKind::FileGetFlags=>format!("Failed to get the unix file flags of the {} file{}",file_prefix,source_error_str),
        ErrorKind::FileSetFlags=>format!("Failed to set the unix file flags of the {} file{}",file_prefix,source_error_str),
        ErrorKind::FileNotEncryptedProperly=>format!("The {} file is corrupted or not encrypted properly{}",file_prefix,source_error_str),
        ErrorKind::GetFileMetadata=>format!("Failed to get the file metadata of the {} file{}",file_prefix,source_error_str),
        ErrorKind::FileTooBig=>format!("The {} file is too big{}",file_prefix,source_error_str),
        ErrorKind::MacError=>format!("The {} file's MAC is invalid, the file is corrupted or not encrypted properly{}",file_prefix,source_error_str),
        ErrorKind::WrongPassword=>"An unexpected error has occured (wrong password error)".to_string(),
        ErrorKind::EncryptionError=>"An unexpected enryption error has occured".to_string(),
        ErrorKind::RevertToBackup=>format!("Failed to revert the {} file to the backup{}",file_prefix,source_error_str),
        ErrorKind::PromptPasswordIOError=>format!("An unexpected IO error has occured while trying to prompt the user to enter a password{}",source_error_str),
        ErrorKind::EncodingError=>format!("Failed to decode the {} file as UTF-8{}",file_prefix,source_error_str),
        ErrorKind::CorruptedFile=>format!("The {} file is corrupted{}",file_prefix,source_error_str),
        ErrorKind::HomeDir=>format!("Failed to get the path of the current user's home directory{}",source_error_str)
    };
    eprintln!("{}", error_style.paint(err));
}
