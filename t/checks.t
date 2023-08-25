#!/usr/bin/env perl

use lib 'lib';
use v5.14.0;
use strict;
use warnings;
use experimental 'signatures';
use Test::Most;
use CycloneDX::Parser::Checks ':all';
use CycloneDX::Parser;

sub parser ( $json, %args ) {
    my $parser = CycloneDX::Parser->new( json_string => $json, %args );
    $parser->_push_stack('test');
    return $parser;
}

my $json = <<'END';    # minimal valid SBOM
{
    "bomFormat": "CycloneDX",
    "specVersion": 1.5
}
END

subtest 'is_string simple string matching' => sub {
    ok my $is_string = is_string('foo'), 'is_string($some_string) should succeed';
    is ref $is_string, 'CODE', 'is_string() should return a subref';
    my $p = parser($json);
    ok $is_string->( $p, 'foo' ),  'is_string() should return true if the string value exactly matches';
    ok $p->is_valid,               '... and we should have no errors';
    ok !$is_string->( $p, 'bar' ), 'is_string() should return false if the value does not exactly match';
    ok !$p->is_valid,              '... and we should have errors';
    my @errors = $p->errors;
    is @errors, 1, '... and we should have one error';
    like $errors[0], qr/Must be 'foo', not 'bar'/, '... and the error should be the expected one';
};

subtest 'is_string regex matching' => sub {
    ok my $is_regex = is_string(qr/^[0-9]+$/), 'is_string($some_regex) should succeed';
    is ref $is_regex, 'CODE', 'is_string() should return a subref';
    my $p = parser($json);
    ok $is_regex->( $p, '123' ),  'is_string() should return true if the string value matches the regex';
    ok $p->is_valid,              '... and we should have no errors';
    ok !$is_regex->( $p, 'bar' ), 'is_string() should return false if the value does not exactly match';
    ok !$p->is_valid,             '... and we should have errors';
    my @errors = $p->errors;
    is @errors, 1, '... and we should have one error';
    like $errors[0], qr/Must match '[^']+', not 'bar'/, '... and the error should be the expected one';
};

subtest 'is_string enums' => sub {
    ok my $is_enum = is_string( [qw/red green blue/] ), 'is_string($some_arrayref) should succeed';
    is ref $is_enum, 'CODE', 'is_string() should return a subref';
    my $p = parser($json);
    ok $is_enum->( $p, 'red' ),  'is_string() should return true if the string value matches an element of the enum';
    ok $p->is_valid,             '... and we should have no errors';
    ok !$is_enum->( $p, 'bar' ), 'is_string() should return false if the value does not exactly match';
    ok !$p->is_valid,            '... and we should have errors';
    my @errors = $p->errors;
    is @errors, 1, '... and we should have one error';
    like $errors[0], qr/Must be one of '[^']+', not 'bar'/, '... and the error should be the expected one';
};

subtest 'is_object' => sub {
    my $object = {
        color => is_string( [qw/red green blue/] ),
        name  => is_string(qr/^[a-zA-Z ]+$/),
    };
    ok my $is_object = is_object($object), 'is_object($some_hashref) should succeed';
    is ref $is_object, 'CODE', 'is_object() should return a subref';
    my $p = parser($json);
    ok $is_object->( $p, { color => 'red', name => 'foo' } ), 'is_object() should return true if the hashref value matches the schema';
    ok $p->is_valid,                                          '... and we should have no errors';
    ok $is_object->( $p, { name => 'foo' } ),                 '... and keys can be optional';
    ok $p->is_valid,                                          '... and we should have no errors';
    ok !$is_object->( $p, { name => '!!!' } ),                '... but they had better be the right values';
    ok !$p->is_valid,                                         '... and we should have errors';

    $p         = parser($json);
    $is_object = is_object( $object, ['color'] );

    ok $is_object->( $p, { color => 'red', name => 'foo' } ), 'is_object() should return true if the hashref value matches the schema';
    ok $p->is_valid,                                          '... and we should have no errors';
    ok !$is_object->( $p, { name => 'foo' } ),                '... but missing required keys should return false';
    ok !$p->is_valid,                                         '... and we should have errors';
    my @errors = $p->errors;
    is @errors, 1, '... and we should have one error';
    like $errors[0], qr/Missing required field 'test\.color'/, '... and the error should be the expected one';

    $p         = parser($json);
    $is_object = is_object($object);
    ok !$is_object->( $p, 'bar' ), 'is_object() should return false if the value does not exactly match';
    ok !$p->is_valid,              '... and we should have errors';
    @errors = $p->errors;
    is @errors, 1, '... and we should have one error';
    like $errors[0], qr/Value test must be an object/, '... and the error should be the expected one';
};

subtest 'is_array_of' => sub {
    my $object = is_object(
        {
            color => is_string( [qw/red green blue/] ),
            name  => is_string(qr/^[a-zA-Z ]+$/),
        }
    );
    ok my $is_aoh = is_array_of($object), 'is_array_of($some_hashref) should succeed';
    is ref $is_aoh, 'CODE', 'is_array_of() should return a subref';
    my $p = parser($json);
    ok $is_aoh->(
        $p,
        [   { color => 'red',   name => 'foo' },
            { color => 'green', name => 'wib ble' },

        ]
      ),
      'is_array_of() should return true if the aoh matches the schema';
    ok $p->is_valid,                            '... and we should have no errors';
    ok $is_aoh->( $p, [ { name => 'foo' } ] ),  '... and keys can be optional';
    ok $p->is_valid,                            '... and we should have no errors';
    ok !$is_aoh->( $p, [ { name => '!!!' } ] ), '... but they had better be the right values';
    ok !$p->is_valid,                           '... and we should have errors';

    $p = parser($json);
    my $object2 = is_object(
        {
            color => is_string( [qw/red green blue/] ),
            name  => is_string(qr/^[a-zA-Z ]+$/),
        },
        ['color']
    );
    $is_aoh = is_array_of($object2);

    ok $is_aoh->( $p, [ { color => 'red', name => 'foo' } ] ), 'is_array_of() should return true if the hashref value matches the schema';
    ok $p->is_valid,                                           '... and we should have no errors';
    ok !$is_aoh->( $p, [ { name => 'foo' } ] ),                '... but missing required keys should return false';
    ok !$p->is_valid,                                          '... and we should have errors';
    my @errors = $p->errors;
    is @errors, 2, '... and we should have two errors';
    like $errors[0], qr/Missing required field 'test\.0\.color'/, '... and the error should be the expected one';

    $p      = parser($json);
    $is_aoh = is_array_of($object);
    ok !$is_aoh->( $p, 'bar' ), 'is_array_of() should return false if the value does not exactly match';
    ok !$p->is_valid,           '... and we should have errors';
    @errors = $p->errors;
    is @errors, 1, '... and we should have one error';
    like $errors[0], qr/Value test must be an arrayref, not a scalar/, '... and the error should be the expected one';
};

subtest 'is_one_of' => sub {
    my $object = {
        color => is_string( [qw/red green blue/] ),
        name  => is_string(qr/^[a-zA-Z ]+$/),
    };
    my $is_object = is_object($object);
    my $is_string = is_string('bob');

    ok my $is_one_of = is_one_of( $is_object, $is_string ), 'is_one_of($is_object, $is_string) should succeed';

    my $p = parser($json);
    is $p->_stack, 'test', 'Our stack should be correct';
    ok $is_one_of->( $p, { color => 'red', name => 'foo' } ), 'is_one_of() should return true if value matches one of the checks';
    is $p->_stack, 'test', 'Our stack should be correct';
    ok $p->is_valid,              '... and we should have no errors';
    ok $is_one_of->( $p, 'bob' ), 'is_one_of() should return true if value matches one of the checks';
    ok $p->is_valid,              '... and we should have no errors';
};

done_testing;
