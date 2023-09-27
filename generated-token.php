<?php
declare(strict_types=1);

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token\Builder;

require 'vendor/autoload.php';

$tokenBuilder = (new Builder(new JoseEncoder(), ChainedFormatter::default()));
$algorithm    = new Sha256();
$signingKey   = InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=');

$now   = new DateTimeImmutable();
$token = $tokenBuilder
    // Configures the issuer (iss claim)
    ->issuedBy('Acme Toothpics Ltd')
    // Configures the audience (aud claim)
    ->permittedFor('www.yoyooyo.com')
    // Configures the id (jti claim)
    ->identifiedBy('4f1g23a12aa')
    // Configures the time that the token was issue (iat claim)
    ->issuedAt($now)
    // Configures the time that the token can be used (nbf claim)
    ->canOnlyBeUsedAfter($now->modify('+1 minute'))
    // Configures the expiration time of the token (exp claim)
    ->expiresAt($now->modify('-20 years'))
    // Configures a new claim, called "uid"
    ->withClaim('uid', 1)
    // Configures a new header, called "foo"
    ->withHeader('foo', 'bar')
    // Builds a new token
    ->getToken($algorithm, $signingKey);

echo $token->toString()."\n";



$parser = new \Lcobucci\JWT\Token\Parser(new JoseEncoder());


try {
    $token = $parser->parse(
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImZvbyI6ImJhciJ9.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJhdWQiOiJ3d3cuZXhhbXBsZS5jb20iLCJqdGkiOiI0ZjFnMjNhMTJhYSIsImlhdCI6MTY5NTgzNDExMC4wOTQzNSwibmJmIjoxNjk1ODM0MTcwLjA5NDM1LCJleHAiOjIzMjY5ODYxMTAuMDk0MzUsInVpZCI6MX0.dWWimi1NJK_8roOV4S8K5KXOq--aNSLLTTOnWAN-Jo4'
    );
} catch (Throwable $exception) {
    echo $exception;exit;
}

var_dump($token);
echo $token->headers()->get('sub') . "\n"; // will print "4f1g23a12aa"
