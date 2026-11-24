package MesgdAuth;
use strict;
use warnings;
use Scalar::Util qw(looks_like_number);
sub new { my ($class,$transport)=@_; bless {transport=>$transport},$class }
sub otp { my ($code)=@_; die "OTP must be a six-digit string\n" if !defined($code) || ref($code) || $code !~ /\A[0-9]{6}\z/; return "$code"; }
sub public_keys {
 my ($keys)=@_; die "expected public JWKs\n" unless ref($keys) eq 'ARRAY' && @$keys<=2;
 for my $k (@$keys) {die "expected public JWKs\n" unless ref($k) eq 'HASH'; for my $f (qw(d p q dp dq qi oth k)){die "private JWKs are not accepted\n" if exists $k->{$f};}}
 return $keys;
}
sub request {
 my ($self,$method,$path,$body,$token)=@_;
 my ($status,$result)=$self->{transport}->($method,$path,$body,$token);
 die bless({status=>$status},'MesgdAuth::Error') if $status<200 || $status>=300;
 return $result;
}
sub signup { my($s,$u,$e,$p,$k)=@_;$s->request('POST','/auth/signup',{user=>$u,email=>$e,password=>$p,public_keys=>public_keys($k//[])},undef) }
sub confirm { my($s,$u,$t,$o)=@_;$s->request('POST','/auth/signup/confirm',{user=>$u,enrollment_token=>$t,otp=>otp($o)},undef) }
sub login { my($s,$u,$p,$o)=@_;$s->request('POST','/auth/login',{user=>$u,password=>$p,otp=>otp($o)},undef) }
sub reset_password { my($s,$u,$r,$p,$o)=@_;$s->request('POST','/auth/password/reset',{user=>$u,recovery_code=>$r,new_password=>$p,otp=>otp($o)},undef) }
sub keys { my($s,$t)=@_;$s->request('GET','/auth/keys',undef,$t) }
sub set_keys { my($s,$t,$p,$o,$k)=@_;$s->request('PUT','/auth/keys',{password=>$p,otp=>otp($o),public_keys=>public_keys($k)},$t) }
sub logout { my($s,$t)=@_;$s->request('POST','/auth/logout',undef,$t) }
package MesgdAuth::Error;
use overload '""'=>sub {"mesgd authentication HTTP $_[0]->{status}"}, fallback=>1;
1;
