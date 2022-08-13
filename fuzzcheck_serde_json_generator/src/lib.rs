#![feature(no_coverage)]
#![feature(type_alias_impl_trait)]

use fuzzcheck::mutators::bool::BoolMutator;
use fuzzcheck::mutators::integer::U64Mutator;
use fuzzcheck::mutators::recursive::RecurToMutator;
use fuzzcheck::mutators::string::string_mutator;
use fuzzcheck::mutators::string::StringMutator;
use fuzzcheck::mutators::tuples::{Tuple2, Tuple2Mutator, TupleMutatorWrapper};
use fuzzcheck::DefaultMutator;

use fuzzcheck::{
    make_mutator,
    mutators::{map::MapMutator, vector::VecMutator},
    Mutator,
};
use serde_json::{Number, Value};

/// A mutator for [`serde_json::Value`].
///
/// The mutator is a bit too conservative at present (it will generate most of
/// the JSON specification, apart from strings where it will not output the
/// characters '"' and '\').
///
/// Example usage with Fuzzcheck (see the
/// [guide](https://fuzzcheck.neocities.org/tutorial1_writing_fuzz_target.html)
/// if you're unsure on how this works).
///
/// ```ignore
///     use std::str::FromStr;
/// use fuzzcheck::fuzz_test;
/// let result = fuzz_test(|value: &Value| {
///     let v = value.to_string();
///     let new_v = Value::from_str(&v).unwrap();
///     value == &new_v
/// })
/// .mutator(json_value_mutator())
/// .serde_serializer()
/// .default_sensor_and_pool()
/// .arguments_from_cargo_fuzzcheck()
/// .launch();
/// assert!(!result.found_test_failure)
/// ```
pub fn json_value_mutator() -> impl Mutator<Value> {
    MapMutator::new(
        InternalJsonValue::default_mutator(),
        |value: &Value| map_serde_json_to_internal(value.clone()),
        |internal_json_value| map_internal_jv_to_serde(internal_json_value.clone()),
        |input, _| calculate_output_cplx(input),
    )
}

// each byte = 1 unit of complexity (?)
fn calculate_output_cplx(input: &Value) -> f64 {
    match input {
        Value::Null => 1.0,
        Value::Bool(_) => 1.0,
        Value::Number(_) => {
            // 64-bit
            1.0 + 8.0
        }
        Value::String(string) => 1.0 + string.len() as f64,
        Value::Array(array) => array
            .iter()
            .fold(1.0, |acc, next| acc + calculate_output_cplx(next)),
        Value::Object(object) => object.iter().fold(1.0, |acc, (key, value)| {
            acc + 1.0 + key.len() as f64 + calculate_output_cplx(value) as f64
        }),
    }
}

fn map_serde_json_to_internal(value: Value) -> Option<InternalJsonValue> {
    match value {
        Value::Null => Some(InternalJsonValue::Null),
        Value::Bool(bool) => Some(InternalJsonValue::Bool { inner: bool }),
        Value::Number(n) => n
            .as_u64()
            .map(|number| InternalJsonValue::Number { inner: number }),
        Value::String(string) => Some(InternalJsonValue::String { inner: string }),
        Value::Array(array) => {
            let array = array
                .into_iter()
                .map(map_serde_json_to_internal)
                .collect::<Vec<_>>();
            if array.iter().all(Option::is_some) {
                Some(InternalJsonValue::Array {
                    inner: array.into_iter().map(|item| item.unwrap()).collect(),
                })
            } else {
                None
            }
        }
        Value::Object(object) => Some(InternalJsonValue::Object {
            inner: {
                let vec = object
                    .into_iter()
                    .map(|(key, value)| (key, map_serde_json_to_internal(value)))
                    .collect::<Vec<_>>();
                if vec.iter().all(|(_, o)| o.is_some()) {
                    vec.into_iter()
                        .map(|(key, val)| (key, val.unwrap()))
                        .collect()
                } else {
                    return None;
                }
            },
        }),
    }
}

fn map_internal_jv_to_serde(internal: InternalJsonValue) -> Value {
    match internal {
        InternalJsonValue::Null => Value::Null,
        InternalJsonValue::Bool { inner } => Value::Bool(inner),
        InternalJsonValue::Number { inner } => Value::Number(Number::from(inner)),
        InternalJsonValue::String { inner } => Value::String(remove_special_characters(inner)),
        InternalJsonValue::Array { inner } => {
            Value::Array(inner.into_iter().map(map_internal_jv_to_serde).collect())
        }
        InternalJsonValue::Object { inner } => Value::Object(
            inner
                .into_iter()
                .map(|(key, value)| {
                    (
                        remove_special_characters(key),
                        map_internal_jv_to_serde(value),
                    )
                })
                .collect(),
        ),
    }
}

fn remove_special_characters(string: String) -> String {
    string.replace(&['"', '\\'], "")
}

#[derive(Clone)]
enum InternalJsonValue {
    Null,
    Bool {
        inner: bool,
    },
    Number {
        inner: u64,
    },
    String {
        inner: String,
    },
    Array {
        inner: Vec<InternalJsonValue>,
    },
    Object {
        inner: Vec<(String, InternalJsonValue)>,
    },
}

make_mutator! {
    name: InternalJsonValueMutator,
    recursive: true,
    default: true,
    type: enum InternalJsonValue {
        Null,
        Bool {
            #[field_mutator(BoolMutator)]
            inner: bool
        },
        Number {
            #[field_mutator(U64Mutator)]
            inner: u64
        },
        String {
            #[field_mutator(StringMutator = {string_mutator()})]
            inner: String
        },
        Array {
            #[field_mutator(
                VecMutator<
                    InternalJsonValue,
                    RecurToMutator<InternalJsonValueMutator>
                > = {
                    VecMutator::new(self_.into(), 0..=usize::MAX)
                }
            )]
            inner: Vec<InternalJsonValue>,
        },
        Object {
            #[field_mutator(
                VecMutator<
                    (String, InternalJsonValue),
                    TupleMutatorWrapper<
                        Tuple2Mutator<StringMutator, RecurToMutator<InternalJsonValueMutator>>,
                        Tuple2<String, InternalJsonValue>
                    >
                > = {
                    VecMutator::new(
                        TupleMutatorWrapper::new(
                            Tuple2Mutator::new(
                                string_mutator(),
                                self_.into()
                            )
                        ),
                        0..=usize::MAX
                    )
                }
            )]
            inner: Vec<(String, InternalJsonValue)>,
        },
    }
}

#[cfg(test)]
#[test]
fn check_validity() {
    use std::str::FromStr;

    use fuzzcheck::fuzz_test;

    let result = fuzz_test(|value: &Value| {
        let v = value.to_string();
        let new_v = Value::from_str(&v).unwrap();
        value == &new_v
    })
    .mutator(json_value_mutator())
    .serde_serializer()
    .default_sensor_and_pool()
    .arguments_from_cargo_fuzzcheck()
    .launch();
    assert!(!result.found_test_failure)
}
