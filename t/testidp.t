#!/usr/bin/env perl
#
use strict;
use warnings FATAL => 'all';

use Apache::Test qw(-withtestmore);
use Apache::TestRequest;
use Apache::TestUtil;

use URI::Escape;

use HTTP::Cookies;

my $cookie_jar = HTTP::Cookies->new();
Apache::TestRequest::user_agent(cookie_jar => $cookie_jar);

plan tests => 4 + 2 , need_module('JSON');

require JSON;
JSON->import;

my $idp = "http://personatestuser.org";

#email_with_assertion/https%3A%2F%2Fmaximus.local

my $audience = uri_escape("http://" . Apache::Test::vars('servername'));

my $ua = LWP::UserAgent->new;

my ($assertion, $password, $email);

{
  my $res = GET "$idp/email";

  ok $res->is_success;

  my $data = decode_json($res->content);

  $password = $data->{'pass'};
  $email = $data->{'email'};

  t_debug("email=$email");
  t_debug("password=$password");

  ok ($email and $password);
}

{ 
  my $res = GET "$idp/assertion/$audience/$email/$password";
  
  ok $res->is_success;
  
  my $data = decode_json($res->content);

  $assertion = $data->{assertion};
  
  t_debug("assertion=$assertion");
  ok ($assertion);
}

subtest 'Remote Verification' => sub { basic_flow("/auth/") };
subtest 'Local Verification' => sub { basic_flow("/auth-local/") };

# 10 tests
sub basic_flow {
  plan tests => 10;
  my $url = shift;

{ #Initial request
  my $res = GET "$url";
  ok t_cmp( $res->code, 401, "$url: Initial request unauthorized");
}

{ #Request with assertion
  my $res = POST "$url", 'X-Persona-Assertion' => $assertion;
  ok t_cmp( $res->code, 200, "$url: Initial request success");
}

{ #Request with session cookie
  my $res = GET "$url";
  ok t_cmp( $res->code, 200, "$url: Initial request unauthorized");
}

{ #request with modified cookie
  my ($version, $key, $val, $path, $domain, $port, $path_spec, $secure, $expires, $discard);
  my $cookie_count = 0;
  $cookie_jar->scan(sub { ($version, $key, $val, $path, $domain, $port, $path_spec, $secure, $expires, $discard) = @_; $cookie_count++});

  ok t_cmp( $cookie_count, 1, "$url: One cookie set");
  ok t_debug("Persona cookie $key: $val");

  $val = "x" . $val . "x";

  $cookie_jar->set_cookie( $version, $key, $val, $path, $domain, $port, $path_spec, $secure, $expires, $discard);

  t_server_log_error_is_expected();
  my $res = GET "$url";

  ok t_cmp( $res->code, 401, "$url: Cookie tampering");

  $cookie_count = 0;
  $cookie_jar->scan(sub { $cookie_count++ });

  ok t_cmp( $cookie_count, 0, "$url: Cookie got deleted");
}

{ #Login again with assertion
  my $res = POST "$url", 'X-Persona-Assertion' => $assertion;
  ok t_cmp( $res->code, 200, "$url: Re-login request success");
}

{ #Logout
  my $res = GET "$url" . "logout.shtml";
  ok t_cmp( $res->code, 200, "$url: Logout request success");
  
  my $cookie_count = 0;
  $cookie_jar->scan(sub { $cookie_count++ });

  ok t_cmp( $cookie_count, 0, "$url: Cookie got deleted");
}

}
