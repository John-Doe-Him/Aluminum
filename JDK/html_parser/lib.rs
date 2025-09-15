//! [![github]](https://github.com/mathiversen/html-parser)
2//!
3//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
4//!
5//! # Html parser
6//!
7//! A simple and general purpose html/xhtml parser lib/bin, using [Pest](https://pest.rs/).
8//!
9//! ## Features
10//! - Parse html & xhtml (not xml processing instructions)
11//! - Parse html-documents
12//! - Parse html-fragments
13//! - Parse empty documents
14//! - Parse with the same api for both documents and fragments
15//! - Parse custom, non-standard, elements; `<cat/>`, `<Cat/>` and `<C4-t/>`
16//! - Removes comments
17//! - Removes dangling elements
18//! - Iterate over all nodes in the dom tree
19//!
20//! ## What is it not
21//!
22//! - It's not a high-performance browser-grade parser
23//! - It's not suitable for html validation
24//! - It's not a parser that includes element selection or dom manipulation
25//!
26//! If your requirements matches any of the above, then you're most likely looking for one of the crates below:
27//!
28//! - [html5ever](https://crates.io/crates/html5ever)
29//! - [kuchiki](https://crates.io/crates/kuchiki)
30//! - [scraper](https://crates.io/crates/scraper)
31//! - or other crates using the `html5ever` parser
32//!
33//! ## Examples bin
34//!
35//! Parse html file
36//!
37//! ```shell
38//! html_parser index.html
39//!
40//! ```
41//!
42//! Parse stdin with pretty output
43//!
44//! ```shell
45//! curl <website> | html_parser -p
46//! ```
47//!
48//! ## Examples lib
49//!
50//! Parse html document
51//!
52//! ```rust
53//!     use html_parser::Dom;
54//!
55//!     fn main() {
56//!         let html = r#"
57//!             <!doctype html>
58//!             <html lang="en">
59//!                 <head>
60//!                     <meta charset="utf-8">
61//!                     <title>Html parser</title>
62//!                 </head>
63//!                 <body>
64//!                     <h1 id="a" class="b c">Hello world</h1>
65//!                     </h1> <!-- comments & dangling elements are ignored -->
66//!                 </body>
67//!             </html>"#;
68//!
69//!         assert!(Dom::parse(html).is_ok());
70//!     }
71//! ```
72//!
73//! Parse html fragment
74//!
75//! ```rust
76//!     use html_parser::Dom;
77//!
78//!     fn main() {
79//!         let html = "<div id=cat />";
80//!         assert!(Dom::parse(html).is_ok());
81//!     }
82//! ```
83//!
84//! Print to json
85//!
86//! ```rust
87//!     use html_parser::{Dom, Result};
88//!
89//!     fn main() -> Result<()> {
90//!         let html = "<div id=cat />";
91//!         let json = Dom::parse(html)?.to_json_pretty()?;
92//!         println!("{}", json);
93//!         Ok(())
94//!     }
95//! ```
96
97#![allow(clippy::needless_doctest_main)]
98
99mod dom;
100mod error;
101mod grammar;
102
103use grammar::Rule;
104
105pub use crate::dom::element::{Element, ElementVariant};
106pub use crate::dom::node::Node;
107pub use crate::dom::Dom;
108pub use crate::dom::DomVariant;
109pub use crate::error::Error;
110pub use crate::error::Result;
