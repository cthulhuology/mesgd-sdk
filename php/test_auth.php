<?php
require __DIR__.'/auth.php';
function check($ok){if(!$ok)throw new RuntimeException('auth assertion failed');}
foreach(json_decode(file_get_contents(__DIR__.'/../fixtures/auth_contract.json'),true) as $r){
 $client=new MesgdAuthClient(function($m,$p,$b,$t)use($r){check([$m,$p,$b,$t]==[$r['method'],$r['path'],$r['body'],$r['token']]);return [200,$r['result']];});
 $method=['reset_password'=>'resetPassword','set_keys'=>'setKeys'][$r['op']]??$r['op'];check($client->$method(...$r['args'])==$r['result']);
}
$client=new MesgdAuthClient(fn()=>[401,['secret'=>'DO_NOT_LOG']]);
try{$client->login('u','p','012345');throw new RuntimeException('expected rejection');}catch(MesgdAuthError $e){check($e->status===401 && !str_contains($e->getMessage(),'DO_NOT_LOG'));}
foreach([123456,'12345','01234x',"012345\n"] as $code){try{$client->login('u','p',$code);throw new RuntimeException('expected validation');}catch(InvalidArgumentException $e){}}
foreach(['d','p','q','dp','dq','qi','oth','k'] as $f){try{$client->signup('u','e','p',[[$f=>'PRIVATE']]);throw new RuntimeException('expected validation');}catch(InvalidArgumentException $e){}}
try{MesgdAuthClient::httpsTransport('http://localhost');throw new RuntimeException('expected HTTPS validation');}catch(InvalidArgumentException $e){}
echo "PHP auth contract and validation passed\n";
