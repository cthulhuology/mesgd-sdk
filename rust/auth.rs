//! Stateless mesgd authentication. Implement Transport using your HTTPS stack.
use serde_json::{json, Value};
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum AuthError { InvalidInput, Http(u16), Transport }
impl fmt::Display for AuthError {
 fn fmt(&self, f:&mut fmt::Formatter<'_>)->fmt::Result {
  match self { Self::Http(s)=>write!(f,"mesgd authentication HTTP {}",s), Self::InvalidInput=>write!(f,"invalid authentication input"), Self::Transport=>write!(f,"authentication transport failed") }
 }
}
impl std::error::Error for AuthError {}
pub trait Transport {
 fn send(&mut self, method:&str, path:&str, body:Option<Value>, token:Option<&str>)->Result<(u16,Value),AuthError>;
}
impl<F> Transport for F where F:FnMut(&str,&str,Option<Value>,Option<&str>)->Result<(u16,Value),AuthError> {
 fn send(&mut self,m:&str,p:&str,b:Option<Value>,t:Option<&str>)->Result<(u16,Value),AuthError>{self(m,p,b,t)}
}
pub struct AuthClient<T:Transport> { pub transport:T }
fn otp(code:&str)->Result<&str,AuthError>{ if code.len()==6 && code.bytes().all(|b| b.is_ascii_digit()){Ok(code)}else{Err(AuthError::InvalidInput)} }
fn public_keys(keys:Vec<Value>)->Result<Vec<Value>,AuthError>{
 if keys.len()>2 || keys.iter().any(|k| !k.is_object() || ["d","p","q","dp","dq","qi","oth","k"].iter().any(|f| k.get(*f).is_some())) {Err(AuthError::InvalidInput)}else{Ok(keys)}
}
impl<T:Transport> AuthClient<T> {
 pub fn new(transport:T)->Self{Self{transport}}
 fn request(&mut self,m:&str,p:&str,b:Option<Value>,t:Option<&str>)->Result<Value,AuthError>{let(s,v)=self.transport.send(m,p,b,t)?;if (200..300).contains(&s){Ok(v)}else{Err(AuthError::Http(s))}}
 pub fn signup(&mut self,user:&str,email:&str,password:&str,keys:Vec<Value>)->Result<Value,AuthError>{self.request("POST","/auth/signup",Some(json!({"user":user,"email":email,"password":password,"public_keys":public_keys(keys)?})),None)}
 pub fn confirm(&mut self,user:&str,enrollment:&str,code:&str)->Result<Value,AuthError>{self.request("POST","/auth/signup/confirm",Some(json!({"user":user,"enrollment_token":enrollment,"otp":otp(code)?})),None)}
 pub fn login(&mut self,user:&str,password:&str,code:&str)->Result<Value,AuthError>{self.request("POST","/auth/login",Some(json!({"user":user,"password":password,"otp":otp(code)?})),None)}
 pub fn reset_password(&mut self,user:&str,recovery:&str,password:&str,code:&str)->Result<Value,AuthError>{self.request("POST","/auth/password/reset",Some(json!({"user":user,"recovery_code":recovery,"new_password":password,"otp":otp(code)?})),None)}
 pub fn keys(&mut self,token:&str)->Result<Value,AuthError>{self.request("GET","/auth/keys",None,Some(token))}
 pub fn set_keys(&mut self,token:&str,password:&str,code:&str,keys:Vec<Value>)->Result<Value,AuthError>{self.request("PUT","/auth/keys",Some(json!({"password":password,"otp":otp(code)?,"public_keys":public_keys(keys)?})),Some(token))}
 pub fn logout(&mut self,token:&str)->Result<Value,AuthError>{self.request("POST","/auth/logout",None,Some(token))}
}
