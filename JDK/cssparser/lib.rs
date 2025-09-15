/* This Source Code Form is subject to the terms of the Mozilla Public
2 * License, v. 2.0. If a copy of the MPL was not distributed with this
3 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
4
5#![crate_name = "cssparser"]
6#![crate_type = "rlib"]
7#![cfg_attr(feature = "bench", feature(test))]
8#![deny(missing_docs)]
9
10/*!
11
12Implementation of [CSS Syntax Module Level 3](https://drafts.csswg.org/css-syntax/) for Rust.
13
14# Input
15
16Everything is based on `Parser` objects, which borrow a `&str` input.
17If you have bytes (from a file, the network, or something)
18and want to support character encodings other than UTF-8,
19see the `stylesheet_encoding` function,
20which can be used together with rust-encoding or encoding-rs.
21
22# Conventions for parsing functions
23
24* Take (at least) a `input: &mut cssparser::Parser` parameter
25* Return `Result<_, ()>`
26* When returning `Ok(_)`,
27  the function must have consumed exactly the amount of input that represents the parsed value.
28* When returning `Err(())`, any amount of input may have been consumed.
29
30As a consequence, when calling another parsing function, either:
31
32* Any `Err(())` return value must be propagated.
33  This happens by definition for tail calls,
34  and can otherwise be done with the `?` operator.
35* Or the call must be wrapped in a `Parser::try` call.
36  `try` takes a closure that takes a `Parser` and returns a `Result`,
37  calls it once,
38  and returns itself that same result.
39  If the result is `Err`,
40  it restores the position inside the input to the one saved before calling the closure.
41
42Examples:
43
44```{rust,ignore}
45// 'none' | <image>
46fn parse_background_image(context: &ParserContext, input: &mut Parser)
47                                    -> Result<Option<Image>, ()> {
48    if input.try_parse(|input| input.expect_ident_matching("none")).is_ok() {
49        Ok(None)
50    } else {
51        Image::parse(context, input).map(Some)  // tail call
52    }
53}
54```
55
56```{rust,ignore}
57// [ <length> | <percentage> ] [ <length> | <percentage> ]?
58fn parse_border_spacing(_context: &ParserContext, input: &mut Parser)
59                          -> Result<(LengthOrPercentage, LengthOrPercentage), ()> {
60    let first = LengthOrPercentage::parse?;
61    let second = input.try_parse(LengthOrPercentage::parse).unwrap_or(first);
62    (first, second)
63}
64```
65
66*/
67
68#![recursion_limit = "200"] // For color::parse_color_keyword
69
70pub use crate::cow_rc_str::CowRcStr;
71pub use crate::from_bytes::{stylesheet_encoding, EncodingSupport};
72#[doc(hidden)]
73pub use crate::macros::{
74    _cssparser_internal_create_uninit_array, _cssparser_internal_to_lowercase,
75};
76pub use crate::nth::parse_nth;
77pub use crate::parser::{BasicParseError, BasicParseErrorKind, ParseError, ParseErrorKind};
78pub use crate::parser::{Delimiter, Delimiters, Parser, ParserInput, ParserState};
79pub use crate::rules_and_declarations::{parse_important, parse_one_declaration};
80pub use crate::rules_and_declarations::{parse_one_rule, StyleSheetParser};
81pub use crate::rules_and_declarations::{AtRuleParser, QualifiedRuleParser};
82pub use crate::rules_and_declarations::{DeclarationParser, RuleBodyItemParser, RuleBodyParser};
83pub use crate::serializer::{serialize_identifier, serialize_name, serialize_string};
84pub use crate::serializer::{CssStringWriter, ToCss, TokenSerializationType};
85pub use crate::tokenizer::{SourceLocation, SourcePosition, Token};
86pub use crate::unicode_range::UnicodeRange;
87pub use cssparser_macros::*;
88#[doc(hidden)]
89pub use phf as _cssparser_internal_phf;
90
91#[macro_use]
92mod macros;
93
94mod rules_and_declarations;
95mod tokenizer;
96
97pub mod color;
98mod cow_rc_str;
99mod from_bytes;
100mod nth;
101mod parser;
102mod serializer;
103mod unicode_range;
104
105#[cfg(test)]
106mod size_of_tests;
107#[cfg(test)]
108mod tests;
