use core::fmt;

// 所有meta信息
#[derive(Debug)]
pub struct Meta {
    NTec: String,
    attacker: u8,
    analysis: bool,
    app: [u16; 10],
    att_tac: String,
    att_tec: String,
    attack_direction: u8,
    attack_result: u8,
    classtype: String,
    cnnvd: [String; 10],
    confidence: u8,
    cve: [String; 10],
    doc_links: [String; 10],
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
    protocol: String,
    references: [String; 10],
    rev: u8,
    severity: Severity,
    sfb: u8,
    sid: u16,
    source: [String; 10],
    suggestions: String,
    threat_tag: [String; 10],
    updated_at: String,
    version: u8,
    RTags: [String; 10],
    RConfidence: u8,
    RTechniques: [String; 10],
    hl_pos: u8,
    created_at: [String; 10],
}

// 严重程度枚举类型
// Low (0-3.9)
// Medium (4-6.9)
// High (7-8.9)
// Critical (9-10)
#[derive(Debug)]
enum Severity {
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

impl Severity {
    fn get_low() -> Severity {
        Self::Low
    }
}

#[cfg(test)]
mod test_compound_types {
    use super::Severity;

    #[test]
    fn test_severity() {
        let low = Severity::Low;
        let medium = Severity::Medium;
        println!("{}", low);
        println!("{}", medium);

        let low1 = Severity::get_low();
        println!("{:#?}", low1);
    }
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
