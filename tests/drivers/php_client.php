<?php
require __DIR__.'/../../php/auth.php';
$r=json_decode(file_get_contents('php://stdin'),true);
$c=new MesgdAuthClient(MesgdAuthClient::httpsTransport(getenv('MESGD_AUTH_URL')));
$method=['reset_password'=>'resetPassword','set_keys'=>'setKeys'][$r['op']]??$r['op'];
try{echo json_encode(['result'=>$c->$method(...$r['args'])]);}catch(MesgdAuthError $e){echo json_encode(['status'=>$e->status]);}
