//! The v1 condition grammar (docs/guide/architecture.md §5):
//! field references, `==` `!=` `in` `contains` `matches` `<` `>` `<=` `>=`, boolean
//! `and`/`or`/`not`, parens. One rule reads one collector's fact — no cross-collector
//! joins in v1. The four comparison operators are numeric-only (added for threshold rules
//! like password-aging policy; string ordering isn't meaningful for the fact fields v1
//! collectors produce, so it's deliberately not supported).

use crate::models::Fact;
use regex::Regex;
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Str(String),
    Num(f64),
    Bool(bool),
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
    In,
    Contains,
    Matches,
    And,
    Or,
    Not,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
}

#[derive(Debug, thiserror::Error)]
pub enum ConditionError {
    #[error("unexpected character '{0}' at position {1}")]
    UnexpectedChar(char, usize),
    #[error("unterminated string literal")]
    UnterminatedString,
    #[error("unexpected end of condition")]
    UnexpectedEof,
    #[error("unexpected token: {0:?}")]
    UnexpectedToken(String),
    #[error("field '{0}' not found in collected fact")]
    MissingField(String),
    #[error("invalid regex in 'matches': {0}")]
    InvalidRegex(String),
    #[error("trailing input after a complete expression")]
    TrailingInput,
    #[error("'{0}' requires numeric operands, got a non-number")]
    NonNumericComparison(&'static str),
    #[error("condition nesting is too deep (max {0})")]
    TooDeep(usize),
}

fn lex(src: &str) -> Result<Vec<Token>, ConditionError> {
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut tokens = Vec::new();

    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '[' => {
                tokens.push(Token::LBracket);
                i += 1;
            }
            ']' => {
                tokens.push(Token::RBracket);
                i += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            '=' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(Token::Eq);
                i += 2;
            }
            '!' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(Token::Neq);
                i += 2;
            }
            '<' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(Token::Lte);
                i += 2;
            }
            '>' if chars.get(i + 1) == Some(&'=') => {
                tokens.push(Token::Gte);
                i += 2;
            }
            '<' => {
                tokens.push(Token::Lt);
                i += 1;
            }
            '>' => {
                tokens.push(Token::Gt);
                i += 1;
            }
            '"' | '\'' => {
                let quote = c;
                let mut s = String::new();
                i += 1;
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == quote {
                        closed = true;
                        i += 1;
                        break;
                    }
                    s.push(chars[i]);
                    i += 1;
                }
                if !closed {
                    return Err(ConditionError::UnterminatedString);
                }
                tokens.push(Token::Str(s));
            }
            c if c.is_ascii_digit()
                || (c == '-' && chars.get(i + 1).is_some_and(|n| n.is_ascii_digit())) =>
            {
                let start = i;
                i += 1;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let s: String = chars[start..i].iter().collect();
                let n: f64 = s
                    .parse()
                    .map_err(|_| ConditionError::UnexpectedChar(c, start))?;
                tokens.push(Token::Num(n));
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.')
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                tokens.push(match word.as_str() {
                    "and" => Token::And,
                    "or" => Token::Or,
                    "not" => Token::Not,
                    "in" => Token::In,
                    "contains" => Token::Contains,
                    "matches" => Token::Matches,
                    "true" => Token::Bool(true),
                    "false" => Token::Bool(false),
                    _ => Token::Ident(word),
                });
            }
            other => return Err(ConditionError::UnexpectedChar(other, i)),
        }
    }
    Ok(tokens)
}

#[derive(Debug, Clone)]
enum Literal {
    Str(String),
    Num(f64),
    Bool(bool),
    List(Vec<Literal>),
}

impl fmt::Display for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Literal::Str(s) => write!(f, "\"{s}\""),
            Literal::Num(n) => write!(f, "{n}"),
            Literal::Bool(b) => write!(f, "{b}"),
            Literal::List(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
        }
    }
}

#[derive(Debug, Clone)]
enum CmpOp {
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
    In,
    Contains,
    Matches,
}

#[derive(Debug, Clone)]
enum Expr {
    Cmp {
        field: String,
        op: CmpOp,
        value: Literal,
        /// The compiled regex for a `matches` comparison, built once at parse time. Compiling here
        /// (rather than on every evaluation) means an invalid regex is a load-time `RuleLoadError`
        /// caught by `rules validate`, not a per-scan failure that only surfaces once a collector
        /// happens to yield a row — and it removes a per-row recompile from the scan hot path.
        matcher: Option<Regex>,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

/// Three-valued (Kleene) truth for condition evaluation. `Unknown` carries the name of the field
/// whose absence made the result indeterminate, so a genuinely-undetermined top-level result can
/// still report *which* field was missing.
enum Tri {
    True,
    False,
    Unknown(String),
}

/// Hard bound on parser recursion. The recursive-descent parser recurses on every `(` and `[`, and
/// a rules directory is attacker-supplied in the threat model (see `engine.rs` — it's passed into
/// the root pkexec scan, which is why the size cap and O_NOFOLLOW guard exist). Without a bound, a
/// planted rule of ~200k nested parens (well under the 1 MiB rule-size cap) overflows the stack and
/// *aborts* the process — an uncatchable DoS that `load_rules`' `Result`-filtering can't contain.
/// This turns that into a catchable `TooDeep` error instead. 128 is far deeper than any real rule.
const MAX_PARSE_DEPTH: usize = 128;

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    /// Enters one level of recursion, erroring if the nesting bound is exceeded. Every recursive
    /// parse entry point calls this and decrements on the way out.
    fn enter(&mut self) -> Result<(), ConditionError> {
        self.depth += 1;
        if self.depth > MAX_PARSE_DEPTH {
            return Err(ConditionError::TooDeep(MAX_PARSE_DEPTH));
        }
        Ok(())
    }

    fn advance(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn expect(&mut self, expected: &Token) -> Result<(), ConditionError> {
        match self.advance() {
            Some(ref t) if t == expected => Ok(()),
            Some(t) => Err(ConditionError::UnexpectedToken(format!("{t:?}"))),
            None => Err(ConditionError::UnexpectedEof),
        }
    }

    fn parse_or(&mut self) -> Result<Expr, ConditionError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ConditionError> {
        let mut left = self.parse_unary()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, ConditionError> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.advance();
            let inner = self.parse_unary()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, ConditionError> {
        if matches!(self.peek(), Some(Token::LParen)) {
            self.advance();
            self.enter()?; // bound recursion through parenthesised sub-expressions
            let inner = self.parse_or()?;
            self.depth -= 1;
            self.expect(&Token::RParen)?;
            return Ok(inner);
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> Result<Expr, ConditionError> {
        let field = match self.advance() {
            Some(Token::Ident(s)) => s,
            Some(t) => return Err(ConditionError::UnexpectedToken(format!("{t:?}"))),
            None => return Err(ConditionError::UnexpectedEof),
        };
        let op = match self.advance() {
            Some(Token::Eq) => CmpOp::Eq,
            Some(Token::Neq) => CmpOp::Neq,
            Some(Token::Lt) => CmpOp::Lt,
            Some(Token::Gt) => CmpOp::Gt,
            Some(Token::Lte) => CmpOp::Lte,
            Some(Token::Gte) => CmpOp::Gte,
            Some(Token::In) => CmpOp::In,
            Some(Token::Contains) => CmpOp::Contains,
            Some(Token::Matches) => CmpOp::Matches,
            Some(t) => return Err(ConditionError::UnexpectedToken(format!("{t:?}"))),
            None => return Err(ConditionError::UnexpectedEof),
        };
        let value = self.parse_literal()?;
        // Compile a `matches` regex now, so a bad pattern is a load-time error, not a lurking
        // per-scan one.
        let matcher = if matches!(op, CmpOp::Matches) {
            let pattern = match &value {
                Literal::Str(s) => s.clone(),
                other => other.to_string(),
            };
            Some(Regex::new(&pattern).map_err(|e| ConditionError::InvalidRegex(e.to_string()))?)
        } else {
            None
        };
        Ok(Expr::Cmp {
            field,
            op,
            value,
            matcher,
        })
    }

    fn parse_literal(&mut self) -> Result<Literal, ConditionError> {
        match self.advance() {
            Some(Token::Str(s)) => Ok(Literal::Str(s)),
            Some(Token::Num(n)) => Ok(Literal::Num(n)),
            Some(Token::Bool(b)) => Ok(Literal::Bool(b)),
            Some(Token::LBracket) => {
                self.enter()?; // bound recursion through nested list literals
                let mut items = Vec::new();
                if !matches!(self.peek(), Some(Token::RBracket)) {
                    loop {
                        items.push(self.parse_literal()?);
                        if matches!(self.peek(), Some(Token::Comma)) {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                }
                self.expect(&Token::RBracket)?;
                self.depth -= 1;
                Ok(Literal::List(items))
            }
            Some(t) => Err(ConditionError::UnexpectedToken(format!("{t:?}"))),
            None => Err(ConditionError::UnexpectedEof),
        }
    }
}

/// A parsed, ready-to-evaluate condition. Rules are parsed once at load time, not per-scan.
pub struct Condition {
    expr: Expr,
    source: String,
}

impl Condition {
    pub fn parse(src: &str) -> Result<Self, ConditionError> {
        let tokens = lex(src)?;
        let mut parser = Parser {
            tokens,
            pos: 0,
            depth: 0,
        };
        let expr = parser.parse_or()?;
        if parser.pos != parser.tokens.len() {
            return Err(ConditionError::TrailingInput);
        }
        Ok(Condition {
            expr,
            source: src.to_string(),
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// Looks up `field` in `fact`. A leading `<collector>.` namespace segment is accepted
    /// for readability (e.g. `sshd.password_authentication`) and stripped if the fact
    /// doesn't have a top-level key by that exact dotted name — collectors expose flat maps.
    fn resolve<'a>(field: &str, fact: &'a Fact) -> Option<&'a Value> {
        if let Some(v) = fact.get(field) {
            return Some(v);
        }
        if let Some((_, rest)) = field.split_once('.') {
            return fact.get(rest);
        }
        None
    }

    pub fn eval(&self, fact: &Fact) -> Result<bool, ConditionError> {
        // Evaluate with three-valued logic, then collapse: a determinate result is returned as-is,
        // but an `Unknown` — the condition's outcome genuinely depends on a field the collector
        // didn't emit — is surfaced as `MissingField` exactly as before, so a rule that can't be
        // decided is withheld (collector_error) rather than silently passing or failing.
        match Self::eval_tri(&self.expr, fact)? {
            Tri::True => Ok(true),
            Tri::False => Ok(false),
            Tri::Unknown(field) => Err(ConditionError::MissingField(field)),
        }
    }

    /// Kleene-logic evaluation. The point is operand-order independence with correct short-circuit
    /// over a missing field: `A or B` is true when B is true even if A's field is absent, and
    /// `A and B` is false when B is false even if A's field is absent — instead of the old behavior
    /// where the *left* operand's missing field aborted the whole condition regardless of what the
    /// right operand would have decided. A result that truly hinges on the missing field stays
    /// `Unknown` and is reported as such.
    fn eval_tri(expr: &Expr, fact: &Fact) -> Result<Tri, ConditionError> {
        match expr {
            Expr::And(l, r) => {
                let a = Self::eval_tri(l, fact)?;
                if matches!(a, Tri::False) {
                    return Ok(Tri::False); // false AND anything = false, even if `r` is unknown
                }
                let b = Self::eval_tri(r, fact)?;
                Ok(match (a, b) {
                    (_, Tri::False) => Tri::False,
                    (Tri::True, Tri::True) => Tri::True,
                    (Tri::Unknown(f), _) | (_, Tri::Unknown(f)) => Tri::Unknown(f),
                    // a is True (handled above for False), so only (True, True) reaches True.
                    _ => unreachable!(),
                })
            }
            Expr::Or(l, r) => {
                let a = Self::eval_tri(l, fact)?;
                if matches!(a, Tri::True) {
                    return Ok(Tri::True); // true OR anything = true, even if `r` is unknown
                }
                let b = Self::eval_tri(r, fact)?;
                Ok(match (a, b) {
                    (_, Tri::True) => Tri::True,
                    (Tri::False, Tri::False) => Tri::False,
                    (Tri::Unknown(f), _) | (_, Tri::Unknown(f)) => Tri::Unknown(f),
                    _ => unreachable!(),
                })
            }
            Expr::Not(inner) => Ok(match Self::eval_tri(inner, fact)? {
                Tri::True => Tri::False,
                Tri::False => Tri::True,
                Tri::Unknown(f) => Tri::Unknown(f),
            }),
            Expr::Cmp {
                field,
                op,
                value,
                matcher,
            } => match Self::resolve(field, fact) {
                None => Ok(Tri::Unknown(field.clone())),
                Some(actual) => Ok(if Self::eval_cmp(actual, op, value, matcher)? {
                    Tri::True
                } else {
                    Tri::False
                }),
            },
        }
    }

    fn eval_cmp(
        actual: &Value,
        op: &CmpOp,
        expected: &Literal,
        matcher: &Option<Regex>,
    ) -> Result<bool, ConditionError> {
        match op {
            CmpOp::Eq => Ok(value_eq(actual, expected)),
            CmpOp::Neq => Ok(!value_eq(actual, expected)),
            CmpOp::Lt | CmpOp::Gt | CmpOp::Lte | CmpOp::Gte => {
                let (Value::Number(a), Literal::Num(b)) = (actual, expected) else {
                    return Err(ConditionError::NonNumericComparison(match op {
                        CmpOp::Lt => "<",
                        CmpOp::Gt => ">",
                        CmpOp::Lte => "<=",
                        _ => ">=",
                    }));
                };
                let a = a
                    .as_f64()
                    .ok_or(ConditionError::NonNumericComparison("<"))?;
                Ok(match op {
                    CmpOp::Lt => a < *b,
                    CmpOp::Gt => a > *b,
                    CmpOp::Lte => a <= *b,
                    CmpOp::Gte => a >= *b,
                    _ => unreachable!(),
                })
            }
            CmpOp::In => match expected {
                Literal::List(items) => Ok(items.iter().any(|item| value_eq(actual, item))),
                _ => Ok(false),
            },
            CmpOp::Contains => {
                let hay = value_as_str(actual);
                let needle = match expected {
                    Literal::Str(s) => s.clone(),
                    other => other.to_string(),
                };
                Ok(hay.contains(&needle))
            }
            CmpOp::Matches => {
                let hay = value_as_str(actual);
                // Compiled at parse time (see parse_comparison); a `matches` comparison always
                // carries its matcher. The fallback recompile is defensive only.
                match matcher {
                    Some(re) => Ok(re.is_match(&hay)),
                    None => {
                        let pattern = match expected {
                            Literal::Str(s) => s.clone(),
                            other => other.to_string(),
                        };
                        let re = Regex::new(&pattern)
                            .map_err(|e| ConditionError::InvalidRegex(e.to_string()))?;
                        Ok(re.is_match(&hay))
                    }
                }
            }
        }
    }
}

fn value_as_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn value_eq(actual: &Value, expected: &Literal) -> bool {
    match (actual, expected) {
        (Value::String(a), Literal::Str(b)) => a == b,
        (Value::Number(a), Literal::Num(b)) => a.as_f64().is_some_and(|a| a == *b),
        (Value::Bool(a), Literal::Bool(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(pairs: &[(&str, Value)]) -> Fact {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn simple_eq() {
        let c = Condition::parse(r#"sshd.password_authentication == "yes""#).unwrap();
        let f = fact(&[("password_authentication", Value::String("yes".into()))]);
        assert!(c.eval(&f).unwrap());
        let f2 = fact(&[("password_authentication", Value::String("no".into()))]);
        assert!(!c.eval(&f2).unwrap());
    }

    #[test]
    fn neq() {
        let c = Condition::parse(r#"permit_root_login != "no""#).unwrap();
        let f = fact(&[("permit_root_login", Value::String("yes".into()))]);
        assert!(c.eval(&f).unwrap());
    }

    #[test]
    fn and_or_not() {
        let c = Condition::parse(
            r#"(password_authentication == "yes" or permit_root_login == "yes") and not disabled == true"#,
        )
        .unwrap();
        let f = fact(&[
            ("password_authentication", Value::String("yes".into())),
            ("permit_root_login", Value::String("no".into())),
            ("disabled", Value::Bool(false)),
        ]);
        assert!(c.eval(&f).unwrap());
    }

    #[test]
    fn deeply_nested_parens_error_instead_of_overflowing_the_stack() {
        // A planted rule with pathological nesting must be a catchable parse error, not a process
        // abort (the rules dir is attacker-supplied and feeds the root pkexec scan).
        let bomb = format!("{}x == 1{}", "(".repeat(5000), ")".repeat(5000));
        assert!(matches!(
            Condition::parse(&bomb),
            Err(ConditionError::TooDeep(_))
        ));
        // A long FLAT condition (many parens, shallow nesting) must still parse fine — the bound is
        // on depth, not on total paren count.
        let flat: Vec<String> = (0..200).map(|i| format!("(a == {i})")).collect();
        assert!(Condition::parse(&flat.join(" or ")).is_ok());
    }

    #[test]
    fn or_is_order_independent_over_a_missing_field() {
        // The Kleene fix: `A or B` is true when B is true even if A's field is absent — regardless
        // of which side is written first. Previously the left operand's missing field aborted it.
        let f = fact(&[("b", Value::from(2))]);
        assert!(Condition::parse("a == 1 or b == 2")
            .unwrap()
            .eval(&f)
            .unwrap());
        assert!(Condition::parse("b == 2 or a == 1")
            .unwrap()
            .eval(&f)
            .unwrap());
        // And `A and B` is false when B is false even if A is missing.
        assert!(!Condition::parse("a == 1 and b == 3")
            .unwrap()
            .eval(&f)
            .unwrap());
        // A result that genuinely hinges on the missing field is still withheld (MissingField).
        assert!(matches!(
            Condition::parse("a == 1 or b == 3").unwrap().eval(&f),
            Err(ConditionError::MissingField(_))
        ));
    }

    #[test]
    fn an_invalid_matches_regex_is_a_parse_error_not_a_lurking_eval_error() {
        // Compiled at parse time, so `rules validate` catches it — it no longer loads clean and
        // then fails (or silently never runs) at scan time.
        assert!(matches!(
            Condition::parse(r#"x matches "([""#),
            Err(ConditionError::InvalidRegex(_))
        ));
    }

    #[test]
    fn in_list() {
        let c = Condition::parse(r#"port in [22, 23, 2323]"#).unwrap();
        let f = fact(&[("port", Value::from(23))]);
        assert!(c.eval(&f).unwrap());
        let f2 = fact(&[("port", Value::from(8080))]);
        assert!(!c.eval(&f2).unwrap());
    }

    #[test]
    fn contains_and_matches() {
        let c1 = Condition::parse(r#"exec_start contains "curl""#).unwrap();
        let f1 = fact(&[(
            "exec_start",
            Value::String("/bin/bash -c 'curl https://evil.example'".into()),
        )]);
        assert!(c1.eval(&f1).unwrap());

        let c2 = Condition::parse(r#"exec_start matches "ngrok|cloudflared""#).unwrap();
        let f2 = fact(&[("exec_start", Value::String("/usr/bin/ngrok tcp 22".into()))]);
        assert!(c2.eval(&f2).unwrap());
        let f3 = fact(&[("exec_start", Value::String("/usr/bin/nginx".into()))]);
        assert!(!c2.eval(&f3).unwrap());
    }

    #[test]
    fn numeric_comparisons() {
        let f = fact(&[("pass_max_days", Value::from(99999))]);
        assert!(Condition::parse("pass_max_days > 365")
            .unwrap()
            .eval(&f)
            .unwrap());
        assert!(!Condition::parse("pass_max_days < 365")
            .unwrap()
            .eval(&f)
            .unwrap());
        assert!(Condition::parse("pass_max_days >= 99999")
            .unwrap()
            .eval(&f)
            .unwrap());
        assert!(Condition::parse("pass_max_days <= 99999")
            .unwrap()
            .eval(&f)
            .unwrap());
    }

    #[test]
    fn numeric_comparison_against_non_number_is_an_error() {
        let f = fact(&[("port", Value::String("not-a-number".into()))]);
        let c = Condition::parse("port > 100").unwrap();
        assert!(matches!(
            c.eval(&f),
            Err(ConditionError::NonNumericComparison(_))
        ));
    }

    #[test]
    fn missing_field_is_an_error_not_a_silent_false() {
        let c = Condition::parse(r#"nonexistent == "x""#).unwrap();
        let f = fact(&[("something_else", Value::String("y".into()))]);
        assert!(matches!(c.eval(&f), Err(ConditionError::MissingField(_))));
    }

    #[test]
    fn lexer_rejects_an_unexpected_character() {
        assert!(matches!(
            Condition::parse("field == @weird"),
            Err(ConditionError::UnexpectedChar('@', _))
        ));
    }

    #[test]
    fn lexer_rejects_an_unterminated_string() {
        assert!(matches!(
            Condition::parse(r#"field == "never closed"#),
            Err(ConditionError::UnterminatedString)
        ));
    }

    #[test]
    fn parser_rejects_trailing_input() {
        assert!(matches!(
            Condition::parse(r#"field == "x" garbage"#),
            Err(ConditionError::TrailingInput)
        ));
    }

    #[test]
    fn parser_reports_unexpected_eof_and_token_in_a_dangling_comparison() {
        // No operator/value after the field at all.
        assert!(matches!(
            Condition::parse("field"),
            Err(ConditionError::UnexpectedEof)
        ));
        // A keyword where a comparison operator was expected.
        assert!(matches!(
            Condition::parse("field and true"),
            Err(ConditionError::UnexpectedToken(_))
        ));
        // A keyword where a literal value was expected.
        assert!(matches!(
            Condition::parse("field == and"),
            Err(ConditionError::UnexpectedToken(_))
        ));
        // Unbalanced parens, nothing left where a closing paren was expected.
        assert!(matches!(
            Condition::parse(r#"(field == "x""#),
            Err(ConditionError::UnexpectedEof)
        ));
        // Unbalanced parens, but the wrong token where a closing paren was expected.
        assert!(matches!(
            Condition::parse(r#"(field == "x"]"#),
            Err(ConditionError::UnexpectedToken(_))
        ));
    }

    #[test]
    fn source_returns_the_original_condition_text() {
        let src = r#"password_authentication == "yes""#;
        let c = Condition::parse(src).unwrap();
        assert_eq!(c.source(), src);
    }

    #[test]
    fn contains_against_a_non_string_literal_uses_its_display_form() {
        // Exercises Literal::Display for a non-Str variant (Contains/Matches otherwise only
        // ever format string literals) — a plausible real rule shape, e.g. matching a port
        // number as a substring of a raw config value stored as a string.
        let c = Condition::parse("raw_value contains 22").unwrap();
        let f = fact(&[("raw_value", Value::String("listen:2200".into()))]);
        assert!(c.eval(&f).unwrap());
    }
}
