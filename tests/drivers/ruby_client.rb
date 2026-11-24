require 'json'
require_relative '../../ruby/auth'
r=JSON.parse(STDIN.read)
c=Mesgd::AuthClient.new(Mesgd::AuthClient.https_transport(ENV.fetch('MESGD_AUTH_URL'),ca_file:ENV.fetch('MESGD_AUTH_CA_FILE')))
begin
 puts JSON.generate({result:c.public_send(r['op'],*r['args'])})
rescue Mesgd::AuthError=>e
 puts JSON.generate({status:e.status})
end
