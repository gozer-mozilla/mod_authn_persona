#!/usr/bin/env perl
#
use strict;
use warnings FATAL => 'all';

use Apache::Test;
use Apache::TestRequest;
use Apache::TestUtil;

use URI::Escape;

use HTTP::Cookies;

my $cookie_jar = HTTP::Cookies->new();
Apache::TestRequest::user_agent(cookie_jar => $cookie_jar);

plan tests => 11, need_module('JSON');

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

{ #Initial request
  my $res = GET "/auth/";
  ok t_cmp( $res->code, 401, "Initial request unauthorided");
}

{ #Request with assertion
  my $res = POST "/auth/", 'X-Persona-Assertion' => $assertion;
  ok t_cmp( $res->code, 200, "Initial request success");
}

{ #Request with session cookie
  my $res = GET "/auth/";
  ok t_cmp( $res->code, 200, "Initial request unauthorized");
}

{ #request with modified cookie
  my ($version, $key, $val, $path, $domain, $port, $path_spec, $secure, $expires, $discard);
  my $cookie_count = 0;
  $cookie_jar->scan(sub { ($version, $key, $val, $path, $domain, $port, $path_spec, $secure, $expires, $discard) = @_; $cookie_count++});
  
  ok t_cmp( $cookie_count, 1, "One cookie set");
  ok t_debug("Persona cookie $key: $val");
  
  $val = "x" . $val . "x";
  
  $cookie_jar->set_cookie( $version, $key, $val, $path, $domain, $port, $path_spec, $secure, $expires, $discard);
  
  t_server_log_error_is_expected();
  my $res = GET "/auth/";
  
  ok t_cmp( $res->code, 401, "Cookie tampering");
  
  $cookie_count = 0;
  $cookie_jar->scan(sub { $cookie_count++ });
  
  ok t_cmp( $cookie_count, 0, "Cookie got deleted");
  
}
