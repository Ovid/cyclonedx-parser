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
    return CycloneDX::Parser->new( json_string => $json );
}

my $json = <<'END';    # minimal valid SBOM
{
    "bomFormat": "CycloneDX",
    "specVersion": 1.5
}
END

subtest 'is_foo simple string matching' => sub {
    ok my $is_foo = is_string('foo'), 'is_string($some_string) should succeed';
    is ref $is_foo, 'CODE', 'is_string() should return a subref';
    my $p = parser($json);
    ok $is_foo->( $p, 'foo' ),  'is_string() should return true if the string value exactly matches';
    ok $p->is_valid,            '... and we should have no errors';
    ok !$is_foo->( $p, 'bar' ), 'is_string() should return false if the value does not exactly match';
    ok !$p->is_valid,           '... and we should have errors';
    my @errors = $p->errors;
    is @errors, 1, '... and we should have one error';
    like $errors[0], qr/Must be 'foo', not 'bar'/, '... and the error should be the expected one';
};

done_testing;
