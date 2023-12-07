// network attack technical point => depending on ATT&CK, etc.

#[derive(Debug, Default)]
pub struct TechnicalPoint {
    technical_name: String,
    sub_tech_points: Vec<String>,
}

#[cfg(test)]
mod test_technical_point {
    use super::TechnicalPoint;

    #[test]
    fn test_tech_point() {
        let item = TechnicalPoint {
            technical_name: "Injected Attack".to_string(),
            sub_tech_points: vec!["SQL Injection".to_string(), String::from("SSTI")],
        };
        let mut Tech_points: Vec<TechnicalPoint> = vec![item];
        // Tech_points.append(other);
        println!("{:#?}", Tech_points);
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    IP,
    ICMP,
    TCP,
    UDP,
    HTTP,
    TLS,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::TCP
    }
}

// use std::collections::HashMap;

// #[derive(Debug, Default)]
// pub struct TechnicalPoint {
//     // 一级技术点
//     first_tier_tech_point: HashMap<String, Vec<String>>,
// }

// #[cfg(test)]
// mod test_technical_point {
//     use super::TechnicalPoint;
//     use std::{collections::HashMap, vec};

//     #[test]
//     fn test_tech_point() {
//         let mut first_tier_map = HashMap::new();
//         first_tier_map.insert("sqli".to_string(), vec!["php sql injection".to_string()]);
//         let tech_point = TechnicalPoint {
//             first_tier_tech_point: first_tier_map,
//         };
//         println!("{:#?}", tech_point);
//     }
// }
