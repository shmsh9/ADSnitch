use chrono::{DateTime, Utc};
use evtx::SerializedEvtxRecord;
use lazy_regex::{regex, Lazy};
use regex::Regex;


/*
https://learn.microsoft.com/en-us/answers/questions/1529208/event-id-ad-account-login
Event ID 4624: This event indicates a successful logon. It logs the account name and the time of the logon. By tracking this event, you can see when and how often the account is being used.
Event ID 4625: This event indicates a failed logon attempt. It can help you identify unauthorized access attempts or issues with the account credentials.
Event ID 4648: This event is logged when a logon attempt is made with explicit credentials, such as when using the RunAs command. It can indicate that the account credentials are being used actively, even if not for interactive logons.
Event ID 4634: This event signals a logoff. While it doesn't directly indicate usage, in conjunction with logon events, it can help paint a picture of the account's activity patterns.
Event ID 4768: This event is generated when a Kerberos authentication ticket (TGT) is requested. It indicates an attempt to access network resources, suggesting the account is in use.
Event ID 4776: This event is generated when a computer attempts to validate the credentials of an account with the domain controller. It's useful for tracking when and how often the account credentials are being verified against the Active Directory.
Event ID 4740: This event indicates an account lockout, which can occur after multiple failed logon attempts. It can be a sign of either incorrect credential usage or a potential attack on the account.
*/

#[macro_export]
macro_rules! regex_evtx_data {
    ($($name:expr),*) => {
        {
            let mut result = String::new();
            $(
                result.push_str(&format!("<Data Name=\"{}\">(.*?)<\\/Data>\\s*", $name));
            )*
            result.trim_end_matches("\\s*").to_string()
        }
    };
}
pub static RE_AUTH : Lazy<Regex> = Lazy::new(|| {
    Regex::new(&regex_evtx_data!(
        "TargetUserName", 
        "TargetDomainName", 
        "TargetLogonId", 
        "LogonType", 
        "LogonProcessName",
        "AuthenticationPackageName",
        "WorkstationName",
        "LogonGuid",
        "TransmittedServices",
        "LmPackageName",
        "KeyLength",
        "ProcessId",
        "ProcessName",
        "IpAddress"
    )).unwrap()
});

static RE_AUTH_FAIL : Lazy<Regex> = Lazy::new(|| {
    Regex::new(&regex_evtx_data!(
        "TargetUserName", 
        "TargetDomainName", 
        "Status",
        "FailureReason",
        "SubStatus",
        "LogonType",
        "LogonProcessName",
        "AuthenticationPackageName",
        "WorkstationName",
        "TransmittedServices",
        "LmPackageName",
        "KeyLength",
        "ProcessId",
        "ProcessName",
        "IpAddress",
        "IpPort"
    )).unwrap()
});

static RE_AUTH_EXPLICIT : Lazy<Regex> = Lazy::new(|| {
    Regex::new(&regex_evtx_data!(
        "TargetUserName", 
        "TargetDomainName", 
        "TargetLogonGuid",
        "TargetServerName",
        "TargetInfo",
        "ProcessId",
        "ProcessName",
        "IpAddress"
    )).unwrap()
});

#[derive(Debug, Clone)]
pub struct AuthEvent{
    pub target_user_name : String,
    pub workstation_name : String,
    pub target_domain_name : String,
    pub service_name : String,
    pub ip_address : String,
    pub datetime : DateTime<Utc>,
    pub auth_type : String,
    pub status : String,
    pub successfull : bool
}
impl AuthEvent {
    pub const KRBTICKETREQ : &str = "4768";
    pub const KRBPREAUTHFAIL : &str = "4771";

    pub const NTLMAUTH : &str = "4776";
    pub const AUTH : &str = "4624";
    pub const AUTHFAIL : &str = "4625";
    pub const AUTHEXPLICIT : &str = "4648";

    pub fn from_auth_explicit_evtx_record(event : SerializedEvtxRecord<String>) -> Option<AuthEvent>{
        let cap = RE_AUTH_EXPLICIT.captures(&event.data);
        match cap {
            Some(cap) => {
                let ip: String = cap.get(8)
                    .unwrap()
                    .as_str()
                    .trim()
                    .to_string();

                let mut workstation_name = cap.get(4)
                    .unwrap()
                    .as_str()
                    .trim()
                    .to_string();
                if workstation_name == "-" {
                    let ip_clean  = ip.replace("::ffff:", "").parse();
                    workstation_name = match ip_clean {
                        Ok(i) => {
                            match dns_lookup::lookup_addr(&i){
                                Ok(i) => i,
                                _ => "".to_string()
                            }
                        },
                        _ => "".to_string()
                    };
                }
                
                Some(AuthEvent{
                    target_user_name: cap.get(1)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    target_domain_name: cap.get(2)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    service_name: "".to_string(),
                    ip_address: ip,
                    datetime: event.timestamp,
                    auth_type: "".to_string(),
                    workstation_name: workstation_name,
                    status: "".to_string(),
                    successfull: true
                })
        
            }
            None => {
                println!("{}", event.data);
                None
            }
            
        }

    }
    pub fn from_fail_evtx_record(event : SerializedEvtxRecord<String>) -> Option<AuthEvent>{
        let cap = RE_AUTH_FAIL.captures(&event.data);
        match cap {
            Some(cap) => {
                let lm: &str = cap.get(11)
                    .unwrap()
                    .as_str();
                let ip: String = cap.get(15)
                    .unwrap()
                    .as_str()
                    .trim()
                    .to_string();

                let mut workstation_name = cap.get(9)
                    .unwrap()
                    .as_str()
                    .trim()
                    .to_string();
                if workstation_name == "-" {
                    let ip_clean  = ip.replace("::ffff:", "").parse();
                    workstation_name = match ip_clean {
                        Ok(i) => {
                            match dns_lookup::lookup_addr(&i){
                                Ok(i) => i,
                                _ => "".to_string()
                            }
                        },
                        _ => "".to_string()
                    };
                }
                let status = cap.get(3)
                    .unwrap()
                    .as_str()
                    .trim();

                Some(AuthEvent{
                    target_user_name: cap.get(1)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    target_domain_name: cap.get(2)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    service_name: cap.get(7)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    ip_address: ip,
                    datetime: event.timestamp,
                    auth_type: match lm {
                        "NTLM V2" => "NTLMV2".to_string(),
                        "NTLM" => "NTLMV2".to_string(),
                        "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" => "NTLMV1".to_string(),
                        _ => {
                            let t = cap.get(8).unwrap().as_str();
                            match t {
                                "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" => "LDAP".to_string(),
                                _ => t.trim().to_string()
                            }
                        }
                    },
                    workstation_name: workstation_name,
                    status: status.to_string(),
                    successfull: match status.to_lowercase().as_str() {
                        "0xC000006e" => true,
                        _ => false
                    }
                })        
            },
            None => {
                println!("{}", event.data);
                None
            }
            
        }
    }
    pub fn from_evtx_record(event : SerializedEvtxRecord<String>) -> Option<AuthEvent> {
        let cap = RE_AUTH.captures(&event.data);
        match cap {
            Some(cap) => {
                let lm = cap.get(10)
                    .unwrap()
                    .as_str();
                let ip: String = cap.get(14)
                    .unwrap()
                    .as_str()
                    .trim()
                    .to_string();

                let mut workstation_name = cap.get(7)
                    .unwrap()
                    .as_str()
                    .trim()
                    .to_string();
                if workstation_name == "-" {
                    let ip_clean  = ip.replace("::ffff:", "").parse();
                    workstation_name = match ip_clean {
                        Ok(i) => {
                            match dns_lookup::lookup_addr(&i){
                                Ok(i) => i,
                                _ => "".to_string()
                            }
                        },
                        _ => "".to_string()
                    };
                }

                Some(AuthEvent {
                    target_user_name: cap.get(1)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    target_domain_name: cap.get(2)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    service_name: cap.get(5)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    ip_address: ip,
                    datetime: event.timestamp,
                    auth_type: match lm {
                        "NTLM V2" => "NTLMV2".to_string(),
                        "NTLM" => "NTLMV2".to_string(),
                        "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" => "NTLMV1".to_string(),
                        _ => {
                            let t = cap.get(6).unwrap().as_str();
                            match t {
                                "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" => "LDAP".to_string(),
                                _ => t.trim().to_string()
                            }
                        }
                    },
                    workstation_name: workstation_name,
                    status: "".to_string(),
                    successfull: true
                })        
            }
            None => {
                println!("{}", event.data);
                None
            }
            
        }
    }
    pub fn sql_insert(&self) -> &str {
        "INSERT INTO auth_event(target_user_name, workstation_name, target_domain_name, service_name, ip_address, datetime, auth_type, status, successfull) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    }
}