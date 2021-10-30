use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

use std::ffi::CString;

use anyhow::*;

use crate::utils::JailStatus;

pub struct Jail {
    jailtime: u32,
    allowance: u8,
    ipset_ptr: *const u8, // opaque C ptr to struct ipset
    remand: Mutex<HashMap<IpAddr, u8>>,
}


const ERR_MSG: &str =
    "error using ipset/iptables, maybe it's not installed, this program isn't running as root ?";

fn ipset_block(jailtime: u32, ip: IpAddr) -> Result<()> {
    let sentence = format!(
        "ipset add {} {} timeout {}",
        JAIL_NAME,
        ip.to_string(),
        jailtime
    );
    let sentence_sl: Vec<&str> = sentence.split_whitespace().collect();

    let out = Command::new("sudo").args(sentence_sl).output()?;
    if out.status.code() != Some(0) {
        eprintln!("{:?}", out);
        bail!("error executing ipset ban");
    }

    Ok(())
}

const JAIL_NAME: &str = "blockfast_jail";
const IPSET_SETNAME: u32 = 1;
const IPSET_OPT_FAMILY: u32 = 3;
const IPSET_OPT_IP: u32 = 4;
const IPSET_OPT_TIMEOUT: u32 = 10;


#[link(name = "ipset")]
extern "C" {
    fn ipset_init() -> *const u8; //
    fn ipset_session_data_set(ipset_struct: *const u8, target: u32, name: CString);
}

impl Jail {
    pub fn new(allowance: u8, jailtime: u32) -> Result<Jail> {
        let ipset_ptr = unsafe { ipset_init() };

        if ipset_ptr.is_null() {
            bail!(ERR_MSG);
        }

        let JAIL_NAME_C = CString::new("blockfast_thisisatest").unwrap();

        let a = unsafe { ipset_session_data_set(ipset_ptr, IPSET_SETNAME, JAIL_NAME_C) };

        Ok(Jail {
            allowance,
            jailtime,
            ipset_ptr,
            remand: Mutex::new(HashMap::new()),
        })
    }

    pub fn probe(&self, ip: IpAddr) -> Result<JailStatus> {
        let should_ban = {
            let mut locked_map = self.remand.lock().map_err(|_| anyhow!("cant lock"))?;

            // TODO: set time of last offence, and add grace
            let hits = *locked_map.entry(ip).and_modify(|e| *e += 1).or_insert(1);

            if hits < self.allowance {
                false
            } else {
                locked_map.remove_entry(&ip); // preserve space
                true
            }
        };

        if should_ban {
            ipset_block(self.jailtime, ip)?;
            Ok(JailStatus::Jailed(ip))
        } else {
            Ok(JailStatus::Remand)
        }
    }
}
