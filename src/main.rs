use evtx::EvtxParser;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use lettre::message::header::ContentType;
use std::{collections::HashMap, path::PathBuf};
use lazy_regex::{Lazy, regex};
use auth_event::AuthEvent;
mod krb;
mod ntlm;
mod config;
mod auth_event;
mod database;

static RE_EVENTID : &Lazy<regex::Regex> = regex!("<EventID>([0-9]{4})<\\/EventID>");
static DEFAULT_PATH : &str = r#"C:\Windows\system32\winevt\Logs\Security.evtx"#;

#[tokio::main]
async fn main() {
    let mut last_date = chrono::offset::Utc::now();
    let fp: PathBuf = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or(DEFAULT_PATH.into())
    );
    let config = config::Config::new().unwrap();
    let db = database::DataBase::new(config).await.unwrap();
    loop {
        let config = config::Config::new().unwrap();

        let mut surveillance : HashMap<String, bool> = config.login_send_alert
            .iter()
            .map(|e| (e.to_lowercase(), false))
            .collect();

        let mut surveillance_fail : HashMap<String, bool> = config.failed_login_send_alert
            .iter()
            .map(|e| (e.to_lowercase(), false))
            .collect();
        let mut parser = EvtxParser::from_path(fp.clone()).unwrap();
        for record in parser.records() {
            match record {
                Ok(r) => {
                    if r.timestamp <= last_date{
                        continue;
                    }
                    else{
                        last_date = r.timestamp;
                    }
                    let _tmpmsg = r.data.clone();
                    let id = RE_EVENTID.captures(&r.data)
                        .unwrap()
                        .get(1)
                        .unwrap()
                        .as_str();
                    let mut a : Option<AuthEvent> =  None;
                    match id {
                        AuthEvent::KRBTICKETREQ => {
                            a = krb::KRBT::ticket_request_from_evtx_record(r);
                        },
                        AuthEvent::KRBPREAUTHFAIL =>{
                            a = krb::KRBT::preauth_fail_from_evtx_record(r);
                        }
                        AuthEvent::NTLMAUTH => {
                            a = ntlm::NTMLAuth::from_evtx_record(r);
                        },
                        AuthEvent::AUTH => {
                            a = AuthEvent::from_evtx_record(r);
                        },
                        AuthEvent::AUTHFAIL => {
                            a = AuthEvent::from_fail_evtx_record(r);
                        }
                        AuthEvent::AUTHEXPLICIT => {
                            a = AuthEvent::from_auth_explicit_evtx_record(r);
                        },
                        _ => ()
                    }
                    match a {
                        Some(a) => {
                            //if !["NTLMV1","NTLMV2","Kerberos","LDAP", "Negotiate", ""].contains(&a.auth_type.as_str()){
                                //println!("{:?}", a);
                            //}
                            db.send_auth_event(a.clone()).await.unwrap();
                            if surveillance.get(&a.target_user_name.to_lowercase()).is_some() && !surveillance.get(&a.target_user_name.to_lowercase()).unwrap() {
                                println!("{:?}", a);
                                surveillance.insert(a.target_user_name.to_lowercase(), true);
                                for address in config.send_list.clone().into_iter() {
                                    let email: Message = Message::builder()
                                    .from("ADSnitch <ADSnitch@walor.com>".parse().unwrap())
                                    .to(format!("<{}>", address).parse().unwrap())
                                    .subject(format!("ADSnitch user connection {}", a.target_user_name))
                                    .header(ContentType::TEXT_PLAIN)
                                    .body(format!("user {} connected {:?}", a.target_user_name, a))
                                    .unwrap();
                                    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(config.smtp_server.clone())
                                        .build();
                                    mailer.send(email).await.unwrap();
                                }

                            }
                            if surveillance_fail.get(&a.target_user_name.to_lowercase()).is_some() && !a.successfull && !surveillance_fail.get(&a.target_user_name.to_lowercase()).unwrap(){
                                println!("{:?}", a);
                                surveillance_fail.insert(a.target_user_name.to_lowercase(), true);
                                for address in config.send_list.clone().into_iter() {
                                    let email: Message = Message::builder()
                                    .from("ADSnitch <ADSnitch@mmt-b.com>".parse().unwrap())
                                    .to(format!("<{}>", address).parse().unwrap())
                                    .subject(format!("ADSnitch failed user connection {}", a.target_user_name))
                                    .header(ContentType::TEXT_PLAIN)
                                    .body(format!("user {} failed to connect {:?}", a.target_user_name, a))
                                    .unwrap();
                                    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(config.smtp_server.clone())
                                        .build();
                                    mailer.send(email).await.unwrap();
                                }


                            }
        
                        },
                        None => {
                        }
                    }
                },
                Err(e) => eprintln!("{}", e),
            }
        }
		std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}
