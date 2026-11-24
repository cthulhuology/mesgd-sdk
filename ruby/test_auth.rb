require 'json'
require 'minitest/autorun'
require_relative 'auth'
class AuthTests < Minitest::Test
 def test_contract
  JSON.parse(File.read(File.join(__dir__,'../fixtures/auth_contract.json'))).each do |r|
   c=Mesgd::AuthClient.new(->(m,p,b,t){assert_equal [r['method'],r['path'],r['body'],r['token']],[m,p,b && JSON.parse(JSON.generate(b)),t];[200,r['result']]})
   assert_equal r['result'],c.public_send(r['op'],*r['args'])
  end
 end
 def test_validation
  c=Mesgd::AuthClient.new(->(*a){flunk 'invalid input reached transport'})
  [123456,'12345','01234x',"012345\n"].each{|o|assert_raises(ArgumentError){c.login('u','p',o)}}
  %w[d p q dp dq qi oth k].each{|f|assert_raises(ArgumentError){c.signup('u','e','p',[{f=>'PRIVATE'}])}}
  assert_raises(ArgumentError){Mesgd::AuthClient.https_transport('http://localhost')}
 end
 def test_error
  c=Mesgd::AuthClient.new(->(*a){[401,{'secret'=>'DO_NOT_LOG'}]})
  e=assert_raises(Mesgd::AuthError){c.login('u','p','012345')}; assert_equal 401,e.status;refute_includes e.message,'DO_NOT_LOG'
 end
end
