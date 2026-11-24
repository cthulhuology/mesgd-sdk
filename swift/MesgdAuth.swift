import Foundation

public enum MesgdAuthError: Error { case invalidInput, http(Int) }
/// Inject a verified HTTPS transport returning the status and decoded JSON object.
public final class MesgdAuth {
 public typealias Transport = (String,String,[String:Any]?,String?) async throws -> (Int,[String:Any])
 private let transport: Transport
 public init(transport: @escaping Transport) { self.transport=transport }
 private func request(_ m:String,_ p:String,_ b:[String:Any]?=nil,_ t:String?=nil) async throws -> [String:Any] {
  let (status,body)=try await transport(m,p,b,t)
  guard (200..<300).contains(status) else {throw MesgdAuthError.http(status)}
  return body
 }
 private func otp(_ code:String) throws -> String {
  guard code.utf8.count==6 && code.utf8.allSatisfy({$0>=48 && $0<=57}) else {throw MesgdAuthError.invalidInput}
  return code
 }
 private func keys(_ keys:[[String:Any]]) throws -> [[String:Any]] {
  guard keys.count<=2 && keys.allSatisfy({k in ["d","p","q","dp","dq","qi","oth","k"].allSatisfy({k[$0]==nil})}) else {throw MesgdAuthError.invalidInput}
  return keys
 }
 public func signup(_ u:String,_ e:String,_ p:String,_ k:[[String:Any]] = []) async throws -> [String:Any] {try await request("POST","/auth/signup",["user":u,"email":e,"password":p,"public_keys":try keys(k)])}
 public func confirm(_ u:String,_ t:String,_ o:String) async throws -> [String:Any] {try await request("POST","/auth/signup/confirm",["user":u,"enrollment_token":t,"otp":try otp(o)])}
 public func login(_ u:String,_ p:String,_ o:String) async throws -> [String:Any] {try await request("POST","/auth/login",["user":u,"password":p,"otp":try otp(o)])}
 public func resetPassword(_ u:String,_ r:String,_ p:String,_ o:String) async throws -> [String:Any] {try await request("POST","/auth/password/reset",["user":u,"recovery_code":r,"new_password":p,"otp":try otp(o)])}
 public func publicKeys(_ t:String) async throws -> [String:Any] {try await request("GET","/auth/keys",nil,t)}
 public func setKeys(_ t:String,_ p:String,_ o:String,_ k:[[String:Any]]) async throws -> [String:Any] {try await request("PUT","/auth/keys",["password":p,"otp":try otp(o),"public_keys":try keys(k)],t)}
 public func logout(_ t:String) async throws -> [String:Any] {try await request("POST","/auth/logout",nil,t)}
}
