#!/usr/bin/env perl

use lib 'lib';
use v5.14.0;
use strict;
use warnings;
use experimental 'signatures';
use Test::More;
use CycloneDX::Parser;
use File::Basename 'basename';

#use Test2::Plugin::BailOnFail;

my %files = invalid_files();
foreach my $file ( sort keys %files ) {
    my $reason        = $files{$file};
    my $assumed_valid = basename($file) =~ /^valid/;
    my $parser        = CycloneDX::Parser->new( json => $file );
    if ($reason) {
        my $name = ref $reason ? $reason->[0] : $reason;
        subtest "$name: $file" => sub {
            ok !$parser->is_valid, "The SBOM should be invalid";
            has_errors( $parser, $reason ) or do {
                diag $parser->json;
                die "Halting test. Check the JSON";
            };
        };
    }
    else {
        if ( !$parser->is_valid ) {
            if ($assumed_valid) {
                fail "Unexpected Errors in $file:\n" . join( "\n", $parser->errors );
            }
            else {
                die "Unexpected Errors in $file:\n" . join( "\n", $parser->errors );
            }
        }
    }
}

sub has_errors ( $parser, $reasons ) {
    my @errors = $parser->errors;
    $reasons = [$reasons] unless 'ARRAY' eq ref $reasons;

    my $passed = 1;
    if ( !@errors ) {
        fail sprintf "Expected errors %s not found because there were no errors", join( ', ', @$reasons );
        return;
    }

    local $Test::Builder::Level = $Test::Builder::Level + 1;

    my %found;
    ERROR: foreach my $error (@errors) {
        my $found = 0;
        REASON: foreach my $reason (@$reasons) {
            if ( $error =~ /$reason/ ) {
                $found = 1;
                $found{error}{$error}++;
                $found{reason}{$reason}++;
                pass "Found expected error '$reason'";
                next ERROR;
            }
        }
    }

    if ( my $missing_reasons = join "    \n", grep { !$found{reason}{$_} } @$reasons ) {
        fail "Expected errors not found:\n$missing_reasons";
        $passed = 0;
    }
    @errors = grep { !$found{error}{$_} } @errors;

    if (@errors) {
        use Data::Dumper;
        diag Dumper [ $parser->errors ];
        fail "Unexpected errors:\n" . join( "\n", @errors );
        $passed = 0;
    }
    return $passed;
}

done_testing;

sub invalid_files {
    return (
        't/data/1.5/invalid-bomformat-1.5.json'        => "Invalid bomFormat. Must be 'CycloneDX', not 'AnotherFormat'",
        't/data/1.5/invalid-specversion-1.5.json'      => "Invalid specVersion. Must be '1.5', not '1.3'",
        't/data/1.5/invalid-version-1.5.json'          => "Invalid version. Must match .*?, not '12.3'",
        't/data/1.5/invalid-hash-sha256-1.5.json'      => "",
        't/data/1.5/invalid-patch-type-1.5.json'       => "",
        't/data/1.5/valid-component-swid-1.5.json'     => "",
        't/data/1.5/valid-license-expression-1.5.json' => "",
        't/data/1.5/valid-metadata-supplier-1.5.json'  => "",
        't/data/1.5/valid-service-1.5.json'            => "",
        't/data/1.5/invalid-component-ref-1.5.json'    => [
            "components.1.bom-ref: Duplicate bom-ref '123'",
            "Invalid components.2.bom-ref. Must match .*?, not ''",
        ],
        't/data/1.5/invalid-hash-sha512-1.5.json'            => "",
        't/data/1.5/invalid-scope-1.5.json'                  => "Invalid components.0.scope. Must be one of 'excluded optional required', not 'foo'",
        't/data/1.5/valid-component-swid-full-1.5.json'      => "",
        't/data/1.5/valid-license-id-1.5.json'               => "",
        't/data/1.5/valid-metadata-timestamp-1.5.json'       => "",
        't/data/1.5/valid-service-empty-objects-1.5.json'    => "",
        't/data/1.5/invalid-component-swid-1.5.json'         => "",
        't/data/1.5/invalid-issue-type-1.5.json'             => "",
        't/data/1.5/invalid-serialnumber-1.5.json'           => "Invalid serialNumber. Must match '[^']+', not 'urn:uuid:3e671687-395b-41f5-a30f'",
        't/data/1.5/valid-component-types-1.5.json'          => "",
        't/data/1.5/valid-license-licensing-1.5.json'        => "",
        't/data/1.5/valid-metadata-tool-1.5.json'            => "",
        't/data/1.5/valid-signatures-1.5.json'               => "",
        't/data/1.5/invalid-component-type-1.5.json'         => "Invalid components.0.type. Must be one of .*?, not 'foo'",
        't/data/1.5/invalid-license-choice-1.5.json'         => "",
        't/data/1.5/invalid-service-data-1.5.json'           => "",
        't/data/1.5/valid-compositions-1.5.json'             => "",
        't/data/1.5/valid-license-name-1.5.json'             => "",
        't/data/1.5/valid-metadata-tool-deprecated-1.5.json' => "",
        't/data/1.5/valid-vulnerability-1.5.json'            => "",
        't/data/1.5/invalid-dependency-1.5.json'             => "",
        't/data/1.5/invalid-license-encoding-1.5.json'       => "",
        't/data/1.5/valid-annotation-1.5.json'               => "",
        't/data/1.5/valid-dependency-1.5.json'               => "",
        't/data/1.5/valid-machine-learning-1.5.json'         => "",
        't/data/1.5/valid-minimal-viable-1.5.json'           => "",
        't/data/1.5/invalid-empty-component-1.5.json'        => "Missing required field 'components.0.name'",
        't/data/1.5/invalid-license-id-1.5.json'             => "",
        't/data/1.5/valid-assembly-1.5.json'                 => "",
        't/data/1.5/valid-empty-components-1.5.json'         => "",
        't/data/1.5/valid-metadata-author-1.5.json'          => "",
        't/data/1.5/valid-patch-1.5.json'                    => "",
        't/data/1.5/invalid-hash-alg-1.5.json'               => "",
        't/data/1.5/invalid-metadata-license-1.5.json'       => "",
        't/data/1.5/valid-bom-1.5.json'                      => "",
        't/data/1.5/valid-evidence-1.5.json'                 => "",
        't/data/1.5/valid-metadata-license-1.5.json'         => "",
        't/data/1.5/valid-properties-1.5.json'               => "",
        't/data/1.5/invalid-properties-1.5.json'             => [
            "Invalid metadata.properties.0.name. Must match '[^']+', not ''",
            'Invalid metadata.properties. Does not match any of the specified checks'
        ],
        't/data/1.5/invalid-hash-md5-1.5.json'               => "",
        't/data/1.5/invalid-metadata-timestamp-1.5.json'     => "Invalid metadata.timestamp. Must match '[^']+', not '2020-04-13'",
        't/data/1.5/valid-component-hashes-1.5.json'         => "",
        't/data/1.5/valid-external-reference-1.5.json'       => "",
        't/data/1.5/valid-metadata-lifecycle-1.5.json'       => "",
        't/data/1.5/valid-release-notes-1.5.json'            => "",
        't/data/1.5/invalid-hash-sha1-1.5.json'              => "",
        't/data/1.5/invalid-missing-component-type-1.5.json' => "Missing required field 'components.0.type'",
        't/data/1.5/valid-component-ref-1.5.json'            => "",
        't/data/1.5/valid-formulation-1.5.json'              => "",
        't/data/1.5/valid-metadata-manufacture-1.5.json'     => "",
        't/data/1.5/valid-saasbom-1.5.json'                  => "",
    );
}
