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
  any_string
  is_string
  non_empty_string
  is_object
);
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

# Because this is core, we're using exported subs as "poor man roles"
#
# Guidelines: C<croak()> if the error in our add code. Use C<_add_error> if
# the error is in their SBOM data.

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
        if ( my $ref = ref $value ) {
            croak("Value $name must be a string, not a $ref'");
        }

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

sub is_object (@matching) {
    if ( @matching != grep { 'ARRAY' eq ref $_ } @matching ) {
        croak("is_object must be passed a list of arrayrefs");
    }

    return sub ( $parser, $value ) {

        # if errors are reported, this curious little construct will make sure
        # that the error is reported with the correct sub name, not "ANON"
        local *__ANON__ = 'is_object';
        my $name = $parser->_stack;

        if ( 'HASH' ne ref $value ) {
            $parser->_add_error("$name: Value $name must be an object, not a " . ref($value));
            return;
        }

        $parser->_validate(
            keys => \@matching,
            source => $value,
            # XXX how to handle required?
        );
    }
}

=head2 C<any_string>

Returns a sub that will check that the value is a string. Contents of the
string do not matter.

=cut

sub any_string () {
    return is_string(qr/./);
}

=head2 C<non_empty_string>

Returns a sub that will check that the value is a string and that it contains
at least one non-whitespace character.

=cut

sub non_empty_string () {
    return is_string(qr/\S/);
}

1;
