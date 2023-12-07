use std::io::Write;
use std::{error::Error, fs, ops::Deref};

use regex::Regex;
use serde::Deserializer;
use serde_json::{value, Value};
use std::collections::HashMap;
use std::fs::File;

mod meta;

fn banner() {}

fn main() -> Result<(), Box<dyn Error>> {
    let desc_path = r"C:\Users\yonggui_li\Downloads\NSPattern_nsc_1000.239.tar\NSPattern_nsc_1000.239\description.json";
    let desc_file = fs::read_to_string(desc_path)?;
    let desc_json: Value = serde_json::from_str(&desc_file)?;
    let mut rule_cves_map: HashMap<String, Vec<String>> = HashMap::new();

    let rule_cves_json_map_path = r"D:\work\ruleUtils-rs\ns_rules_utils\src\meta\rule_to_cves.json";
    let mut rule_cves_json_map_file = File::create(rule_cves_json_map_path)?;

    if let Some(descs) = desc_json.as_object() {
        for (rule, desc) in descs.iter() {
            let cves_value = desc["cves"].as_array().unwrap();
            let mut cves: Vec<String> = vec![];
            for cve in cves_value {
                cves.push(cve.to_string().replace("\"", ""))
            }
            let rule_s = rule.clone();
            rule_cves_map.insert(rule_s, cves);
        }
    }

    let file_str = serde_json::to_string_pretty(&rule_cves_map)?;
    rule_cves_json_map_file.write_all(file_str.as_bytes())?;
    Ok(())
}

fn cve_to_rules() {
    let cve_file = fs::read_to_string(r"D:\work\ruleUtils-rs\ns_rules_utils\src\cve.txt").unwrap();
    // println!("{:?}", cve_file);
    let cve_ptn = r"CVE-[0-9]{4}-[0-9]+";
    let cve_re = Regex::new(cve_ptn).unwrap();
    let mut cve_map = HashMap::new();
    for caps in cve_re.captures_iter(&cve_file) {
        for cap in caps.iter() {
            if let Some(match_cve) = cap {
                let cve = match_cve.as_str();
                // println!("{}", cve);
                cve_map.insert(cve, true);
            }
        }
    }

    let path = r"C:\Users\yonggui_li\Downloads\output.log";
    // let path = r"C:\Users\yonggui_li\Downloads\output-bid.log";
    let file_str = fs::read_to_string(path).unwrap();

    let ptn = r"->[0-9]{9}";
    let rule_ptn = Regex::new(ptn).unwrap();
    // let matches_items = rule_ptn.captures_iter(&file_str);

    // for item in matches_items {
    //     // let item = item;
    //     if let Some(match_item) = item {
    //         println!("{:?}", match_item);
    //     }
    // }

    let mut rule_map = HashMap::new();

    for caps in rule_ptn.captures_iter(&file_str) {
        for cap in caps.iter() {
            if let Some(match_str) = cap {
                // println!("{:?}", match_str.as_str());
                let match_rule = match_str.as_str();
                let match_rule = match_rule.replace("->", "");
                // println!("{:?}", match_rule);
                rule_map.insert(match_rule, vec![vec![""]]);
            }
        }
    }

    let desc_path = r"C:\Users\yonggui_li\Downloads\NSPattern_nsc_1000.239.tar\NSPattern_nsc_1000.239\description.json";
    // let desc_path = r"C:\Users\yonggui_li\Downloads\NSPattern_nsc_2000.012.tar\NSPattern_nsc_2000.012\description.json";
    let desc = fs::read_to_string(desc_path).unwrap();
    let desc_json: Value = serde_json::from_str(desc.as_str()).unwrap();

    for (key, _value) in rule_map.iter_mut() {
        // println!("{:?}", desc_json[key]["cves"]);
        let rule_cve = desc_json[key]["cves"].as_array();
        let mut cve: Vec<&str> = vec![];
        match rule_cve {
            Some(cve_t) => {
                for cve_i in cve_t {
                    cve.push(cve_i.as_str().unwrap());
                }
            }
            None => cve = vec![""],
        }
        // println!("{:?}", rule_cve);
        let rule_name = desc_json[key]["name"].as_str().unwrap();
        // println!("{:?}:{:?}", rule_name, rule_cve);
        // let mut tmp_vec = vec![];
        // tmp_vec.push(vec![rule_name]);
        // // tmp_vec.push(cve);
        // *value = tmp_vec;

        // println!("{:?} rule_name:{:?} cve:{:?}", key, rule_name, cve);
        let cve_iter = cve
            .iter()
            .map(|&x| x.to_string())
            .collect::<Vec<String>>()
            .join(" ");

        // println!("{},{},{}", key, rule_name, cve_iter);
        let mut flag = false;
        if cve.len() > 0 {
            for c in cve {
                if cve_map.contains_key(c) {
                    println!("{},{},{},{}", key, rule_name, cve_iter, "符合");
                    flag = true;
                    break;
                } else {
                    // println!("{},{},{}", key, rule_name, c);
                    continue;
                }
            }
            if !flag {
                println!("{},{},{}", key, rule_name, cve_iter);
            }
        } else {
            println!("{},{},{}", key, rule_name, cve_iter);
        }
    }
}
