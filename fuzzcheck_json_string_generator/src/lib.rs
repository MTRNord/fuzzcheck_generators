use std::rc::Rc;

use fuzzcheck::{
    mutators::grammar::{
        alternation, concatenation, grammar_based_ast_mutator, literal, recurse, recursive, regex,
        repetition, Grammar, AST,
    },
    Mutator,
};

/// Generates valid JSON strings which can be used to test programs which
/// operate on JSON data.
///
/// You will most likely want to use this directly as part of a
/// [`fuzzcheck::fuzz_test`] (or use it to build more complex mutators on top of
/// this one).
///
/// This generator is conservative; it may not generate every valid JSON string
/// (yet - patches to improve it are welcome) but every string it generates
/// should be valid JSON (and I've fuzzed it against serde_json to check).
pub fn json_grammar_mutator() -> impl Mutator<(String, AST)> {
    let grammar = recursive(|json| {
        alternation([
            // null
            regex("null"),
            // bool
            alternation([regex("true"), regex("false")]),
            // number
            number(),
            // string
            concatenation([quote(), valid_possibly_empty_string(), quote()]),
            // array
            concatenation([
                literal('['),
                repetition(concatenation([recurse(json), literal(',')]), 0..=usize::MAX),
                // can't have a trailing comma here
                recurse(json),
                literal(']'),
            ]),
            // object
            concatenation([
                literal('{'),
                repetition(
                    concatenation([
                        quote(),
                        valid_possibly_empty_string(),
                        quote(),
                        literal(':'),
                        recurse(json),
                        literal(','),
                    ]),
                    0..=usize::MAX,
                ),
                concatenation([
                    quote(),
                    valid_possibly_empty_string(),
                    quote(),
                    literal(':'),
                    recurse(json),
                ]),
                literal('}'),
            ]),
        ])
    });
    grammar_based_ast_mutator(grammar).with_string()
}

fn quote() -> Rc<Grammar> {
    literal('"')
}

fn number() -> Rc<Grammar> {
    concatenation([digits(), fraction(), exponent()])
}

/// We only generate a subset of numbers because if the numbers are too big then
/// serde_json will refuse to deserialize them.
fn digits() -> Rc<Grammar> {
    concatenation([regex("[1-9]"), repetition(digit(), 0..=32)])
}

fn digit() -> Rc<Grammar> {
    regex("[0-9]")
}

fn fraction() -> Rc<Grammar> {
    alternation([
        // i.e. nothing
        blank(),
        concatenation([literal('.'), digits()]),
    ])
}

/// We only generate a few numbers for the exponent, because many parsers (e.g.
/// Rust's serde_json) refuse to parse integers larger than than the language
/// provided types.
fn exponent() -> Rc<Grammar> {
    alternation([
        blank(),
        concatenation([
            literal('E'),
            sign(),
            regex("[1-9]"),
            repetition(regex("[0-9]"), 0..=1),
        ]),
        concatenation([
            literal('e'),
            sign(),
            regex("[1-9]"),
            repetition(regex("[0-9]"), 0..=1),
        ]),
    ])
}

fn sign() -> Rc<Grammar> {
    alternation([blank(), literal('+'), literal('-')])
}

fn valid_possibly_empty_string() -> Rc<Grammar> {
    regex("[a-zA-Z0-9_]*")
}

fn blank() -> Rc<Grammar> {
    repetition(literal(' '), 0..=0)
}

#[cfg(test)]
#[test]
fn test_mutator() {
    use std::str::FromStr;

    use fuzzcheck::fuzz_test;
    use serde_json::Value;

    let result = fuzz_test(|(string, _): &(String, AST)| {
        Value::from_str(string).unwrap();
    })
    .mutator(json_grammar_mutator())
    .serde_serializer()
    .default_sensor_and_pool()
    .arguments_from_cargo_fuzzcheck()
    .launch();

    assert!(!result.found_test_failure)
}
