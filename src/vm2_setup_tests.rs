use std::io::Cursor;
use crate::vm2;

#[test]
fn test_init_signals_with_buses() {
    let ff = Field::new(bn254_prime);
    let inputs = r#"{
"a": [ [1, 2, 3], [4, 5, 6] ],
"b": [7, 8, 9, 10, 11, 12],
"c": {
    "start": [ { "x": [13, 14], "y": 15 }, { "x": [16, 17], "y": 18 } ],
    "end": { "x": [19, 20], "y": 21 }
},
"d": [
    {
        "start": [ { "x": [22, 23], "y": 24 }, { "x": [25, 26], "y": 27 } ],
        "end": { "x": [28, 29], "y": [30] }
    },
    {
        "start": [ { "x": [31, 32], "y": [33] }, { "x": [34, 35], "y": 36 } ],
        "end": { "x": [37, 38], "y": 39 }
    }
]
}"#.to_string();
    let inputs = Cursor::new(inputs.as_bytes());

    // [
    //   Type { name: "bus_0", fields: [TypeField { name: "x", kind: Ff, offset: 0, size: 1, dims: [2] }, TypeField { name: "y", kind: Ff, offset: 2, size: 1, dims: [] }] },
    //   Type { name: "bus_1", fields: [TypeField { name: "start", kind: Bus(0), offset: 0, size: 3, dims: [2] }, TypeField { name: "end", kind: Bus(0), offset: 6, size: 3, dims: [] }] }
    // ]
    let types = vec![
        vm2::Type{
            name: "bus_0".to_string(),
            fields: vec![
                vm2::TypeField{
                    name: "x".to_string(),
                    kind: TypeFieldKind::Ff,
                    offset: 0,
                    size: 1,
                    dims: vec![2],
                },
                vm2::TypeField{
                    name: "y".to_string(),
                    kind: TypeFieldKind::Ff,
                    offset: 2,
                    size: 1,
                    dims: vec![],
                },
            ],
        },
        vm2::Type{
            name: "bus_1".to_string(),
            fields: vec![
                vm2::TypeField{
                    name: "start".to_string(),
                    kind: TypeFieldKind::Bus(0),
                    offset: 0,
                    size: 3,
                    dims: vec![2],
                },
                vm2::TypeField{
                    name: "end".to_string(),
                    kind: TypeFieldKind::Bus(0),
                    offset: 6,
                    size: 3,
                    dims: vec![],
                },
            ],
        }
    ];

    // a: offset 7, lengths [2,3] → 6 signals (7-12)
    // b: offset 13, lengths [3,2] → 6 signals (13-18)
    // c: offset 19, bus_1 → 9 signals (19-27)
    // d: offset 28, bus_1[2] → 18 signals (28-45)
    let input_infos = vec![
        vm2::InputInfo{
            name: "a".to_string(),
            offset: 7,
            lengths: vec![2, 3],
            type_id: None,
        },
        vm2::InputInfo{
            name: "b".to_string(),
            offset: 13,
            lengths: vec![3, 2],
            type_id: None,
        },
        vm2::InputInfo{
            name: "c".to_string(),
            offset: 19,
            lengths: vec![],
            type_id: Some("bus_1".to_string()),
        },
        vm2::InputInfo{
            name: "d".to_string(),
            offset: 28,
            lengths: vec![2],
            type_id: Some("bus_1".to_string()),
        },
    ];

    let mut component = vm2::Component::new(
        1, 0, vec![], 39,
    45);

    init_signals(inputs, &ff, &types, &input_infos, &mut component).unwrap();

    let mut signals = vec![];
    component.write_all_signals(&mut signals);

    let want = vec![
        None,
        None,
        None,
        None,
        None,
        None,
        Some(U254::from_str_radix("1", 10).unwrap()),
        Some(U254::from_str_radix("2", 10).unwrap()),
        Some(U254::from_str_radix("3", 10).unwrap()),
        Some(U254::from_str_radix("4", 10).unwrap()),
        Some(U254::from_str_radix("5", 10).unwrap()),
        Some(U254::from_str_radix("6", 10).unwrap()),
        Some(U254::from_str_radix("7", 10).unwrap()),
        Some(U254::from_str_radix("8", 10).unwrap()),
        Some(U254::from_str_radix("9", 10).unwrap()),
        Some(U254::from_str_radix("10", 10).unwrap()),
        Some(U254::from_str_radix("11", 10).unwrap()),
        Some(U254::from_str_radix("12", 10).unwrap()),
        Some(U254::from_str_radix("13", 10).unwrap()),
        Some(U254::from_str_radix("14", 10).unwrap()),
        Some(U254::from_str_radix("15", 10).unwrap()),
        Some(U254::from_str_radix("16", 10).unwrap()),
        Some(U254::from_str_radix("17", 10).unwrap()),
        Some(U254::from_str_radix("18", 10).unwrap()),
        Some(U254::from_str_radix("19", 10).unwrap()),
        Some(U254::from_str_radix("20", 10).unwrap()),
        Some(U254::from_str_radix("21", 10).unwrap()),
        Some(U254::from_str_radix("22", 10).unwrap()),
        Some(U254::from_str_radix("23", 10).unwrap()),
        Some(U254::from_str_radix("24", 10).unwrap()),
        Some(U254::from_str_radix("25", 10).unwrap()),
        Some(U254::from_str_radix("26", 10).unwrap()),
        Some(U254::from_str_radix("27", 10).unwrap()),
        Some(U254::from_str_radix("28", 10).unwrap()),
        Some(U254::from_str_radix("29", 10).unwrap()),
        Some(U254::from_str_radix("30", 10).unwrap()),
        Some(U254::from_str_radix("31", 10).unwrap()),
        Some(U254::from_str_radix("32", 10).unwrap()),
        Some(U254::from_str_radix("33", 10).unwrap()),
        Some(U254::from_str_radix("34", 10).unwrap()),
        Some(U254::from_str_radix("35", 10).unwrap()),
        Some(U254::from_str_radix("36", 10).unwrap()),
        Some(U254::from_str_radix("37", 10).unwrap()),
        Some(U254::from_str_radix("38", 10).unwrap()),
        Some(U254::from_str_radix("39", 10).unwrap()),
    ];
    assert_eq!(want, signals);
    // component.write_all_signals()
}
