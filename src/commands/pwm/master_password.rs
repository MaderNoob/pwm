pub fn check_master_password(password: &str) -> Result<(), &'static str> {
    if password.len() < 4 {
        return Err("The entered password is too short, the master password must be at least 4 characters long");
    }
    Ok(())
}
