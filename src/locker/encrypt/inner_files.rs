use crate::locker::encrypt::{EncryptedFile,EncryptedFileReader,EncryptedFileWriter,EncryptedFileAppender};
use std::fs::File;
pub trait InnerFile{
    fn inner_file(&self)->&File;
    fn inner_file_mut(&mut self)->&mut File;
}
impl InnerFile for EncryptedFile{
    fn inner_file(&self) ->&File {
        &self.file
    }
    fn inner_file_mut(&mut self) ->&mut File {
        &mut self.file
    }
}
impl<'a> InnerFile for EncryptedFileReader<'a>{
    fn inner_file(&self) ->&File {
        &self.file.file
    }
    fn inner_file_mut(&mut self) ->&mut File {
        &mut self.file.file
    }
}
impl<'a> InnerFile for EncryptedFileWriter<'a>{
    fn inner_file(&self) ->&File {
        &self.file.file
    }
    fn inner_file_mut(&mut self) ->&mut File {
        &mut self.file.file
    }
}
impl<'a> InnerFile for EncryptedFileAppender<'a>{
    fn inner_file(&self) ->&File {
        &self.file.file
    }
    fn inner_file_mut(&mut self) ->&mut File {
        &mut self.file.file
    }
}
pub trait InnerEncryptedFile{
    fn inner_encrypted_file(&self)->&EncryptedFile;
    fn inner_encrypted_file_mut(&mut self)->&mut EncryptedFile;
}
impl<'a> InnerEncryptedFile for EncryptedFileReader<'a>{
    fn inner_encrypted_file(&self) ->&EncryptedFile {
        &self.file
    }
    fn inner_encrypted_file_mut(&mut self) ->&mut EncryptedFile {
        &mut self.file
    }
}
impl<'a> InnerEncryptedFile for EncryptedFileWriter<'a>{
    fn inner_encrypted_file(&self) ->&EncryptedFile {
        &self.file
    }
    fn inner_encrypted_file_mut(&mut self) ->&mut EncryptedFile {
        &mut self.file
    }
}
impl<'a> InnerEncryptedFile for EncryptedFileAppender<'a>{
    fn inner_encrypted_file(&self) ->&EncryptedFile {
        &self.file
    }
    fn inner_encrypted_file_mut(&mut self) ->&mut EncryptedFile {
        &mut self.file
    }
}
