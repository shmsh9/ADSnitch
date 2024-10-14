use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config{
    pub login_send_alert : Vec<String>,
    pub failed_login_send_alert : Vec<String>,
    pub send_list : Vec<String>,
    pub smtp_server : String,
    pub database_server : String,
    pub database_user : String,
    pub database_password : String
}

impl Config {
    pub fn new() -> Option<Config> {
        let f = std::fs::read_to_string("config.json");
        if f.is_err() {
            return None;
        }
        let c = serde_json::from_str(&f.unwrap());
        match c {
            Ok(c) => c,
            _ => None   
        }
    }
}