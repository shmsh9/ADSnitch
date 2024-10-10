use lazy_regex::Lazy;
use regex::Regex;
use crate::auth_event::AuthEvent;
use crate::regex_evtx_data;
use evtx::SerializedEvtxRecord;

pub struct NTMLAuth{}

static RE_NTLM : Lazy<Regex> = Lazy::new(|| {
    Regex::new(&regex_evtx_data!(
        "PackageName", 
        "TargetUserName", 
        "Workstation",
        "Status"
    )).unwrap()
});

impl NTMLAuth{

    pub fn from_evtx_record(event : SerializedEvtxRecord<String>) -> Option<AuthEvent> {
        let cap = RE_NTLM.captures(&event.data);
        match cap {
            Some(cap) => {
                let pkgname = cap.get(1).unwrap().as_str();
                Some(AuthEvent {
                    target_user_name: cap.get(2)
                        .unwrap()
                        .as_str()
                        .to_string(),
                    target_domain_name: "".to_string(),
                    service_name: "".to_string(),
                    ip_address: cap.get(3)
                        .unwrap()
                        .as_str()
                        .to_string(),
                    datetime: event.timestamp,
                    auth_type: match pkgname {
                        "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0" => "NTLMV1".to_string(),
                        _ => "NTLMV2".to_string()
                    },
                    workstation_name: "".to_string(),
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

}
