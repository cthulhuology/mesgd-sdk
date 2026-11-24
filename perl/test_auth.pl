use strict;
use warnings;
use FindBin;use lib $FindBin::Bin;
use MesgdAuth;
use JSON::PP;
use Test::More;
open my $fh,'<',"$FindBin::Bin/../fixtures/auth_contract.json" or die $!;
local $/;my $rows=decode_json(<$fh>);my $json=JSON::PP->new->canonical;
for my $r (@$rows){
 my $client=MesgdAuth->new(sub{my($m,$p,$b,$t)=@_;is($json->encode([$m,$p,$b,$t]),$json->encode([$r->{method},$r->{path},$r->{body},$r->{token}]),$r->{op}.' wire');return(200,$r->{result});});
 my $method=$r->{op};is_deeply($client->$method(@{$r->{args}}),$r->{result},$method.' response');
}
my $client=MesgdAuth->new(sub{return(401,{secret=>'DO_NOT_LOG'})});
eval{$client->login('u','p','012345')};isa_ok($@,'MesgdAuth::Error');is($@->{status},401,'status');unlike("$@",qr/DO_NOT_LOG/,'redacted error');
for my $o ('12345','01234x',"012345\n"){eval{$client->login('u','p',$o)};like("$@",qr/OTP must/,'invalid OTP');}
for my $f(qw(d p q dp dq qi oth k)){eval{$client->signup('u','e','p',[{$f=>'PRIVATE'}])};like("$@",qr/private JWK/,'private field rejected');}
done_testing;
