use regex::Regex;
use lazy_regex::Lazy;
use crate::auth_event::AuthEvent;
use crate::regex_evtx_data;
use evtx::SerializedEvtxRecord;



static RE_KRB_TICKET_REQUEST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&regex_evtx_data!(
        "TargetUserName", 
        "TargetDomainName", 
        "TargetSid",
        "ServiceName",
        "ServiceSid",
        "TicketOptions",
        "Status",
        "TicketEncryptionType",
        "PreAuthType",
        "IpAddress"
    )).unwrap()
});
static RE_KRB_PREAUTH_FAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(&regex_evtx_data!(
        "TargetUserName", 
        "TargetSid",
        "ServiceName",
        "TicketOptions",
        "Status",
        "PreAuthType",
        "IpAddress"
    )).unwrap()
});

pub struct KRBT{
}

impl KRBT{
    pub fn preauth_fail_from_evtx_record(event : SerializedEvtxRecord<String>) -> Option<AuthEvent> {
        let cap = RE_KRB_PREAUTH_FAIL.captures(&event.data);
        match cap {
            Some(cap) => {
                let ip: String = cap.get(7)
                    .unwrap()
                    .as_str()
                    .trim()
                    .to_string();

                let ip_clean = ip.replace("::ffff:", "").parse();
                let workstation_name = match ip_clean {
                    Ok(i) => {
                        match dns_lookup::lookup_addr(&i){
                            Ok(i) => i,
                            _ => "".to_string()
                        }
                    },
                    _ => "".to_string()
                };

                Some(AuthEvent {
                    target_user_name: cap.get(1)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    target_domain_name: "".to_string(),
                    service_name: cap.get(3)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    ip_address: ip,
                    workstation_name: workstation_name,
                    datetime: event.timestamp,
                    auth_type: "Kerberos".to_string(),
                    status: cap.get(5)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    successfull: false
                })
            }
            None => {
                println!("{}", event.data);
                None
            }
        }
    }

    pub fn ticket_request_from_evtx_record(event : SerializedEvtxRecord<String>) -> Option<AuthEvent> {
        let cap = RE_KRB_TICKET_REQUEST.captures(&event.data);
        match cap {
            Some(cap) => {
                let ip: String = cap.get(10)
                    .unwrap()
                    .as_str()
                    .trim()
                    .to_string();
                let ip_clean = ip.replace("::ffff:", "").parse();
                let workstation_name = match ip_clean {
                    Ok(i) => {
                        match dns_lookup::lookup_addr(&i){
                            Ok(i) => i,
                            _ => "".to_string()
                        }
                    },
                    _ => "".to_string()
                };
                let s = cap.get(7)
                    .unwrap()
                    .as_str()
                    .to_string();
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
                    service_name: cap.get(4)
                        .unwrap()
                        .as_str()
                        .trim()
                        .to_string(),
                    ip_address: ip,
                    workstation_name: workstation_name,
                    datetime: event.timestamp,
                    auth_type: "Kerberos".to_string(),
                    status: s.trim().to_string(),
                    successfull: match s.as_str() {
                        "0x0" => true,
                        _ => false
                    } 
                })
            }
            None => {
                println!("{}", event.data);
                None
            }
            
        }

    }
}