package CycloneDX::Parser::Checks;

# ABSTRACT: Simple "type" checks for the JSON structure

use v5.14.0;
use strict;
use warnings;
use experimental 'signatures';
use Carp 'croak';
use Digest::Sha 'sha1_hex', 'sha256_hex', 'sha384_hex', 'sha512_hex';

use parent 'Exporter';
our @EXPORT_OK = qw(
  is_string
);
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

# Some of these will not take the $parser argument, but it's easier to have
# them all the same. Because this is core, we're using exported subs as "poor
# man roles"

=head2 C<is_string($thing)>

Returns a sub that will check that the value is a string. If C<$thing> is a
not a reference, it will check that the value is equal to C<$thing>. If
C<$thing> is a regular expression, it will check that the value matches the
regular expression. If C<$thing> is an array reference, it will check that the
value is one of the elements of the array.

Will croak if <$matching> is not a string, regular expression, or array.

=cut

sub is_string ($matching) {
    if ( 'ARRAY' eq ref $matching ) {

        # make sure we have deterministic results
        @$matching = sort @$matching;
    }
    return sub ( $parser, $value ) {

        # if errors are reported, this curious little construct will make sure
        # that the error is reported with the correct sub name, not "ANON"
        local *__ANON__ = 'is_string';
        my $name = $parser->_stack;
        if ( !ref $matching ) {
            if ( $value ne $matching ) {
                $parser->_add_error("Invalid $name. Must be '$matching', not '$value'");
            }
        }
        elsif ( ref $matching eq 'Regexp' ) {
            if ( $value !~ $matching ) {
                $parser->_add_error("Invalid $name. Must match '$matching', not '$value'");
            }
        }
        elsif ( ref $matching eq 'ARRAY' ) {
            if ( !grep { $_ eq $value } @$matching ) {
                $parser->_add_error("Invalid $name. Must be one of '@$matching', not '$value'");
            }
        }
        else {
            croak "Invalid matching type for is_string: $matching";
        }
    };
}

1;
