use crate::meta::t_point::Protocol;
use crate::meta::t_point::TechnicalPoint;
use core::fmt;

// 所有meta信息
#[derive(Debug, Default)]
pub struct Meta {
    ns_tech: Vec<TechnicalPoint>, // desc.json -- NTec
    attacker: u8,
    analysis: bool,
    app: Vec<String>, // desc.json -- affected_product
    att_tac: String,
    att_tec: String,
    attack_direction: u8,
    attack_result: u8,
    classtype: String,
    cnnvd: Vec<String>,
    confidence: u8,
    cve: Vec<String>,
    doc_links: Vec<String>,
    enabled: bool,
    flag: bool,
    gid: u8,
    id: u16,
    kill_chain_phase: String,
    msg: String,
    name: String,
    msg_ch: String,
    optional: String,
    os: String,
    priority: u8,
    protocol: Protocol,
    references: Vec<String>,
    rev: u8,
    severity: Severity,
    sfb: u8,
    sid: u16,
    source: Vec<String>,
    suggestions: String,
    threat_tag: Vec<String>,
    updated_at: String,
    version: u8,
    RTags: Vec<String>,
    RConfidence: u8,
    RTechniques: Vec<String>,
    hl_pos: u8,
    created_at: Vec<String>,
}

impl Meta {
    pub fn get_severity(&self) -> Severity {
        self.severity
    }
    // if enum Severity don't derive 'Copy' trait
    // pub fn get_severity(&self) -> &Severity {
    //     &self.severity
    // }
    pub fn set_severity(&mut self, severity: Severity) {
        self.severity = severity
    }
}

// 严重程度枚举类型
// Low (0-3.9)
// Medium (4-6.9)
// High (7-8.9)
// Critical (9-10)
#[derive(Debug, Clone, Copy)]
// #[derive(Debug, Clone, Copy, Default)]
enum Severity {
    // add Default trait, set default value to Severity enum(unstable)
    // #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "0x01"),
            Severity::Medium => write!(f, "0x02"),
            Severity::High => write!(f, "0x03"),
            Severity::Critical => write!(f, "0x04"),
        }
    }
}

// add Default trait for Severity
impl Default for Severity {
    fn default() -> Self {
        Severity::Low
    }
}

impl Severity {
    fn get_low() -> Severity {
        Self::Low
    }
    fn get_medium() -> Severity {
        Self::Medium
    }
    fn get_high() -> Severity {
        Self::High
    }
    fn get_critical() -> Severity {
        Self::Critical
    }
}

#[cfg(test)]
mod test_compound_types {
    use super::Meta;
    use super::Severity;

    // test severity enum
    #[test]
    fn test_severity1() {
        let low = Severity::Low;
        let medium = Severity::Medium;
        println!("{}", low);
        println!("{}", medium);

        let low1 = Severity::get_low();
        println!("{:#?}", low1);
    }

    #[test]
    fn test_severity_in_meta1() {
        let meta = Meta {
            severity: Severity::get_high(),
            ..Default::default()
        };
        println!("{:#?}", meta);
    }

    // test Meta struct
}

#[cfg(test)]
mod test1 {
    use serde::Deserialize;
    use serde_json::Value;
    use std::io::{BufRead, BufReader};
    use std::{error::Error, fs::File};

    #[test]
    fn get_all_meta_field() -> Result<(), Box<dyn Error>> {
        let file = File::open("D:\\work\\ruleUtils-rs\\ns_rules_utils\\src\\meta\\demo_meta.json")?;
        let reader = BufReader::new(file);
        let mut file_s = String::from("");
        for line in reader.lines() {
            let line = line?;
            file_s = file_s + &line;
        }
        // println!("{}", file_s);

        println!("start unmarshalling...");
        // as we don't know the struct, use Value
        let meta_json: Value = serde_json::from_str(file_s.as_str()).unwrap();
        println!("{:?}", meta_json);
        assert_eq!(2, 2);
        Ok(())
    }
}
