use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;

use anyhow::*;

use crate::utils::JailStatus;

pub struct Jail {
    jailtime: u32,
    allowance: u8,
    remand: Mutex<HashMap<IpAddr, u8>>,
}

const JAIL_NAME: &str = "blockfast_jail";

const ERR_MSG: &str =
    "error using ipset/iptables, maybe it's not installed, this program isn't running as root ?";

fn ipset_init() -> Result<()> {
    let init0 = format!("ipset create {} hash:ip timeout 0", JAIL_NAME);
    let init1 = format!(
        "iptables -I INPUT 1 -m set -j DROP --match-set {} src",
        JAIL_NAME
    );
    let init2 = format!(
        "iptables -I FORWARD 1 -m set -j DROP --match-set {} src",
        JAIL_NAME
    );

    let args0: Vec<&str> = init0.split_whitespace().collect();
    let args1: Vec<&str> = init1.split_whitespace().collect();
    let args2: Vec<&str> = init2.split_whitespace().collect();

    // create
    let out = Command::new("sudo").args(args0).output()?;
    if out.status.code() != Some(0) {
        let already_exists =
            std::str::from_utf8(&out.stderr)?.contains("set with the same name already exists");

        if already_exists {
            return Ok(());
        } else {
            eprintln!("{:?}", out);
            bail!(ERR_MSG);
        }
    }

    // setup input
    let out = Command::new("sudo").args(args1).output()?;
    if out.status.code() != Some(0) {
        eprintln!("{:?}", out);
        bail!(ERR_MSG);
    }

    // setup fwd
    let out = Command::new("sudo").args(args2).output()?;
    if out.status.code() != Some(0) {
        eprintln!("{:?}", out);
        bail!(ERR_MSG);
    }

    Ok(())
}

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

impl Jail {
    pub fn new(allowance: u8, jailtime: u32) -> Result<Jail> {
        ipset_init()?;

        Ok(Jail {
            allowance,
            jailtime,
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
