use chrono::{DateTime, Utc};
use evtx::EvtxParser;
use std::{collections::HashMap, path::PathBuf};
use lazy_regex::{Lazy, regex};
mod krb;
mod ntlm;
mod auth_event;
use auth_event::AuthEvent;

static RE_EVENTID : &Lazy<regex::Regex> = regex!("<EventID>([0-9]{4})<\\/EventID>");

fn main() {
    let mut last_date = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
    loop {
        let mut surveillance = HashMap::from([
            ("t0_vcarbonari", false),
            ("t0_damides", false),
            ("Administrator", false)
        ]);
        let fp: PathBuf = PathBuf::from(std::env::args().nth(1).unwrap());
        let mut parser = EvtxParser::from_path(fp).unwrap();
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
                            for k in surveillance.clone().keys(){                                
                                if !surveillance.get(k).unwrap(){
                                    if a.target_user_name.to_lowercase().contains(k){
                                        println!("{:?}", a);
                                        surveillance.insert(k, true);
                                    }
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
    }
}
