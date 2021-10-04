use std::collections::HashMap;
use std::net::IpAddr;
use std::panic::panic_any;
use std::process::Command;
use std::sync::Mutex;

pub struct Jail {
    jailtime: u32,
    allowance: u8,
    remand: Mutex<HashMap<IpAddr, u8>>,
}

const JAIL_NAME: &str = "blockfast_jail";
const GENERAL_PANIC_MSG: &str =
    "error using ipset/iptables, maybe it's not installed, this program isn't running as root ?";

fn ipset_init() -> Option<()> {
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
    let out = Command::new("sudo").args(args0).output().ok()?;

    if out.status.code()? != 0 {
        let already_exists = std::str::from_utf8(&out.stderr)
            .ok()?
            .contains("set with the same name already exists");

        if already_exists {
            return None;
        } else {
            eprintln!("{:?}", out);
            panic_any(GENERAL_PANIC_MSG);
        }
    }

    // setup input
    let out_input = Command::new("sudo").args(args1).output().ok()?;

    if out_input.status.code()? != 0 {
        eprintln!("{:?}", out_input);
        panic_any(GENERAL_PANIC_MSG);
    }

    // setup fwd
    let out_fwd = Command::new("sudo").args(args2).output().ok()?;

    if out_fwd.status.code()? != 0 {
        eprintln!("{:?}", out_fwd);
        panic_any(GENERAL_PANIC_MSG);
    }

    None
}

fn ipset_block(jailtime: u32, ip: IpAddr) -> Option<()> {
    let sentence = format!(
        "ipset add {} {} timeout {}",
        JAIL_NAME,
        ip.to_string(),
        jailtime
    );
    let sentence_sl: Vec<&str> = sentence.split_whitespace().collect();

    let out = Command::new("sudo").args(sentence_sl).output().ok()?;

    if out.status.code()? != 0 {
        return None;
    }

    Some(())
}

impl Jail {
    pub fn new(allowance: u8, jailtime: u32) -> Jail {
        if ipset_init().is_some() {
            panic_any(GENERAL_PANIC_MSG);
        };

        eprintln!(
            "+ jail setup, allowing {} offences, jailtime: {}s",
            allowance, jailtime
        );

        Jail {
            allowance,
            jailtime,
            remand: Mutex::new(HashMap::new()),
        }
    }

    pub fn probe(&self, ip: IpAddr) -> Option<()> {
        let should_ban = {
            let mut locked_map = self.remand.lock().ok()?;

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
            match ipset_block(self.jailtime, ip) {
                Some(_) => eprintln!("~ {} going to jail", ip),
                None => eprintln!("! ERR {} going to jail", ip),
            }
        }

        None
    }
}
