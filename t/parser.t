#!/usr/bin/env perl

use lib 'lib';
use v5.14.0;
use strict;
use warnings;
use experimental 'signatures';
use Test::More;
use CycloneDX::Parser::Checks ':all';
use CycloneDX::Parser;

sub parser ($json) {
    my $parser = CycloneDX::Parser->new( json_string => $json );
    $parser->_push_stack('test');
    return $parser;
}

my $json = <<'END';    # minimal valid SBOM
{
    "bomFormat": "CycloneDX",
    "specVersion": 1.5
}
END

ok my $parser = parser($json),        'parser() should succeed';
ok $parser->isa('CycloneDX::Parser'), '... and return a CycloneDX::Parser object';
is $parser->json, $json, '... and the JSON should be the same as the input';

done_testing;
