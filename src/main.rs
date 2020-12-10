mod commands;
mod input;
mod locker;
mod passwords;
mod styles;
mod vec_io;
use commands::pwm::printing::PrintingMode;
use passwords::{PasswordFilter, SortBy};
use std::collections::HashMap;
fn main() {
    let path = std::path::PathBuf::from("/home/clear/.pswm");
    // if path.exists() {
    //     let mut file = LockedEncryptedFile::open_write(&path)
    //         .unwrap()
    //         .unlock("putin123")
    //         .unwrap();
    //     let mut appender=file.appender();
    //     let mut fields=HashMap::new();
    //     fields.insert("Phone Number".to_string(), "0502057422".to_string());
    //     fields.insert("Recovery Mail".to_string(), "putin@1secmail.com".to_string());
    //     appender.write_password(&Password {
    //         password: "putinking1243".to_string(),
    //         domain: "instagram.com".to_string(),
    //         username: "noobnoob124.21_234".to_string(),
    //         additional_fields: fields,
    //     });
    //     appender.flush().unwrap();
    // }
    // if path.exists() {
    //     let mut file = LockedEncryptedFile::open_write(&path)
    //         .unwrap()
    //         .unlock("putin123")
    //         .unwrap();
    //     let mut appender=file.appender();
    //     appender.write_password(&Password {
    //         password: "recb".to_string(),
    //         domain: "github.com".to_string(),
    //         username: "madernoob".to_string(),
    //         additional_fields: HashMap::new(),
    //     });
    //     appender.flush().unwrap();
    // }
    let filter = PasswordFilter::new(None, None, None, HashMap::new());
    commands::pwm::get_command(filter, Some(SortBy::Other("Phone Number".to_string())), PrintingMode::Verbose);
    // commands::lock::lock_command("test.txt", "suka noob", false);
    // commands::unlock::unlock_command("test.txt");
}
