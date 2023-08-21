#!/usr/bin/env perl

use lib 'lib';
use v5.14.0;
use strict;
use warnings;
use experimental 'signatures';
use Test::More;
use CycloneDX::Parser;
use File::Basename 'basename';

my %files = invalid_files();
while ( my ( $file, $reason ) = each %files ) {
    my $assumed_valid = basename($file) =~ /^valid/;
    if ($reason) {
        subtest "$reason: $file" => sub {
            my $parser = CycloneDX::Parser->new( json => $file );
            ok !$parser->is_valid,            "The SBOM should be invalid because $reason";
            ok has_error( $parser, $reason ), "The SBOM should be invalid because $reason";
        };
    }
    else {
        my $parser = CycloneDX::Parser->new( json => $file );
        if ( !$parser->is_valid ) {
            if ( $assumed_valid ) {
                fail "Unexpected Errors in $file:\n" . join( "\n", $parser->errors );
            }
            else {
                diag "Unexpected Errors in $file:\n" . join( "\n", $parser->errors );
            }
        }
    }
}

sub has_error ( $parser, $reason ) {
    my @errors = $parser->errors;
    my $found  = grep {/$reason/} @errors;
    unless ($found) {
        diag "Expected error '$reason' not found in:\n" . join( "\n", @errors );
    }
    return $found;
}

done_testing;

sub invalid_files {
    return (
        't/data/1.5/invalid-bomformat-1.5.json'              => "Invalid bomFormat. Must be 'CycloneDX', not 'AnotherFormat'",
        't/data/1.5/invalid-specversion-1.5.json'            => "Invalid specVersion. Must be '1.5', not '1.3'",
        't/data/1.5/invalid-version-1.5.json'                => "Invalid version. Must match .*?, not '12.3'",
        't/data/1.5/invalid-hash-sha256-1.5.json'            => '',
        't/data/1.5/invalid-patch-type-1.5.json'             => '',
        't/data/1.5/valid-component-swid-1.5.json'           => '',
        't/data/1.5/valid-license-expression-1.5.json'       => '',
        't/data/1.5/valid-metadata-supplier-1.5.json'        => '',
        't/data/1.5/valid-service-1.5.json'                  => '',
        't/data/1.5/invalid-component-ref-1.5.json'          => '',
        't/data/1.5/invalid-hash-sha512-1.5.json'            => '',
        't/data/1.5/invalid-scope-1.5.json'                  => '',
        't/data/1.5/valid-component-swid-full-1.5.json'      => '',
        't/data/1.5/valid-license-id-1.5.json'               => '',
        't/data/1.5/valid-metadata-timestamp-1.5.json'       => '',
        't/data/1.5/valid-service-empty-objects-1.5.json'    => '',
        't/data/1.5/invalid-component-swid-1.5.json'         => '',
        't/data/1.5/invalid-issue-type-1.5.json'             => '',
        't/data/1.5/invalid-serialnumber-1.5.json'           => '',
        't/data/1.5/valid-component-types-1.5.json'          => '',
        't/data/1.5/valid-license-licensing-1.5.json'        => '',
        't/data/1.5/valid-metadata-tool-1.5.json'            => '',
        't/data/1.5/valid-signatures-1.5.json'               => '',
        't/data/1.5/invalid-component-type-1.5.json'         => "Invalid component.type. Must be one of .*?, not 'foo'",
        't/data/1.5/invalid-license-choice-1.5.json'         => '',
        't/data/1.5/invalid-service-data-1.5.json'           => '',
        't/data/1.5/valid-compositions-1.5.json'             => '',
        't/data/1.5/valid-license-name-1.5.json'             => '',
        't/data/1.5/valid-metadata-tool-deprecated-1.5.json' => '',
        't/data/1.5/valid-vulnerability-1.5.json'            => '',
        't/data/1.5/invalid-dependency-1.5.json'             => '',
        't/data/1.5/invalid-license-encoding-1.5.json'       => '',
        't/data/1.5/valid-annotation-1.5.json'               => '',
        't/data/1.5/valid-dependency-1.5.json'               => '',
        't/data/1.5/valid-machine-learning-1.5.json'         => '',
        't/data/1.5/valid-minimal-viable-1.5.json'           => '',
        't/data/1.5/invalid-empty-component-1.5.json'        => '',
        't/data/1.5/invalid-license-id-1.5.json'             => '',
        't/data/1.5/valid-assembly-1.5.json'                 => '',
        't/data/1.5/valid-empty-components-1.5.json'         => '',
        't/data/1.5/valid-metadata-author-1.5.json'          => '',
        't/data/1.5/valid-patch-1.5.json'                    => '',
        't/data/1.5/invalid-hash-alg-1.5.json'               => '',
        't/data/1.5/invalid-metadata-license-1.5.json'       => '',
        't/data/1.5/valid-bom-1.5.json'                      => '',
        't/data/1.5/valid-evidence-1.5.json'                 => '',
        't/data/1.5/valid-metadata-license-1.5.json'         => '',
        't/data/1.5/valid-properties-1.5.json'               => '',
        't/data/1.5/invalid-hash-md5-1.5.json'               => '',
        't/data/1.5/invalid-metadata-timestamp-1.5.json'     => '',
        't/data/1.5/valid-component-hashes-1.5.json'         => '',
        't/data/1.5/valid-external-reference-1.5.json'       => '',
        't/data/1.5/valid-metadata-lifecycle-1.5.json'       => '',
        't/data/1.5/valid-release-notes-1.5.json'            => '',
        't/data/1.5/invalid-hash-sha1-1.5.json'              => '',
        't/data/1.5/invalid-missing-component-type-1.5.json' => "Missing required field 'component.type'",
        't/data/1.5/valid-component-ref-1.5.json'            => '',
        't/data/1.5/valid-formulation-1.5.json'              => '',
        't/data/1.5/valid-metadata-manufacture-1.5.json'     => '',
        't/data/1.5/valid-saasbom-1.5.json'                  => '',
    );
}
