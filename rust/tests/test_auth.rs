use mesgd_pki::auth::{AuthClient,AuthError,Transport};
use serde_json::{json,Value};
struct Mock { row:Value }
impl Transport for Mock {
 fn send(&mut self,m:&str,p:&str,b:Option<Value>,t:Option<&str>)->Result<(u16,Value),AuthError>{
  assert_eq!(m,self.row["method"]);assert_eq!(p,self.row["path"]);assert_eq!(b.unwrap_or(Value::Null),self.row["body"]);assert_eq!(t.map(Value::from).unwrap_or(Value::Null),self.row["token"]);Ok((200,self.row["result"].clone()))
 }
}
#[test]
fn auth_contract(){
 let rows:Vec<Value>=serde_json::from_str(include_str!("../../fixtures/auth_contract.json")).unwrap();
 for r in rows {
  let a=r["args"].as_array().unwrap();let s=|i:usize|a[i].as_str().unwrap();let keys=|i:usize|a[i].as_array().unwrap().clone();let mut c=AuthClient::new(Mock{row:r.clone()});
  let result=match r["op"].as_str().unwrap(){"signup"=>c.signup(s(0),s(1),s(2),keys(3)),"confirm"=>c.confirm(s(0),s(1),s(2)),"login"=>c.login(s(0),s(1),s(2)),"reset_password"=>c.reset_password(s(0),s(1),s(2),s(3)),"keys"=>c.keys(s(0)),"set_keys"=>c.set_keys(s(0),s(1),s(2),keys(3)),"logout"=>c.logout(s(0)),_=>panic!("unknown op")};
  assert_eq!(result.unwrap(),r["result"]);
 }
}
struct Denied;
impl Transport for Denied {fn send(&mut self,_:&str,_:&str,_:Option<Value>,_:Option<&str>)->Result<(u16,Value),AuthError>{Ok((401,json!({"secret":"DO_NOT_LOG"})))}}
#[test]
fn validation(){let mut c=AuthClient::new(Denied);assert_eq!(c.login("u","p","012345"),Err(AuthError::Http(401)));assert_eq!(c.login("u","p","12345"),Err(AuthError::InvalidInput));for f in ["d","p","q","dp","dq","qi","oth","k"]{assert_eq!(c.signup("u","e","p",vec![json!({f:"PRIVATE"})]),Err(AuthError::InvalidInput));}}
