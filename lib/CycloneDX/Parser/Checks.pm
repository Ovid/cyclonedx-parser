package CycloneDX::Parser::Checks;

# ABSTRACT: Simple "type" checks for the JSON structure

use v5.14.0;
use warnings;
use experimental 'signatures';
use Carp 'croak';
use Digest::Sha 'sha1_hex', 'sha256_hex', 'sha384_hex', 'sha512_hex';

use parent 'Exporter';
our @EXPORT_OK = qw(
  any_string
  is_array_of
  is_one_of
  is_object
  is_string
  non_empty_string
);
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

our $VERSION = '0.01';

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

        # rewrite it as a hash for faster lookup
        $matching = { map { $_ => 1 } @$matching };
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
                return;
            }
        }
        elsif ( ref $matching eq 'Regexp' ) {
            if ( $value !~ $matching ) {
                $parser->_add_error("Invalid $name. Must match '$matching', not '$value'");
                return;
            }
        }
        elsif ( ref $matching eq 'HASH' ) {
            if ( !$matching->{$value} ) {
                my @matching = sort keys %$matching;
                $parser->_add_error("Invalid $name. Must be one of '@matching', not '$value'");
                return;
            }
        }
        else {
            croak "Invalid matching type for is_string: $matching";
        }
        return 1;
    };
}

sub is_object ( $matching, $required = [] ) {
    if ( 'HASH' ne ref $matching ) {
        croak("is_object must be passed a hashref");
    }

    return sub ( $parser, $value ) {

        # if errors are reported, this curious little construct will make sure
        # that the error is reported with the correct sub name, not "ANON"
        local *__ANON__ = 'is_object';
        my $name = $parser->_stack;

        if ( 'HASH' ne ref $value ) {
            my $ref = _get_type($value);
            $parser->_add_error("$name: Value $name must be an object, not a $ref");
            return;
        }

        $parser->_validate(
            object   => $matching,
            source   => $value,
            required => $required,
        );
    }
}

# XXX TODOO: Make sure we can at least name whick keys fail, and where
sub is_array_of ($matches) {
    if ( 'CODE' ne ref $matches ) {
        croak("is_array_of must be passed a coderef");
    }
    return sub ( $parser, $arrayref ) {
        my $name = $parser->_stack;
        if ( 'ARRAY' ne ref $arrayref ) {
            $parser->_add_error( "Value $name must be an arrayref, not a " . _get_type($arrayref) );
            return;
        }
        my $success = 1;
        THING: for my $i ( 0 .. $#$arrayref ) {
            my $item = $arrayref->[$i];
            $parser->_push_stack($i);
            if ( !$parser->$matches($item) ) {
                $success = 0;
            }
            $parser->_pop_stack;
        }
        if ( !$success ) {
            $parser->_add_error("Invalid $name. Does not match any of the specified checks");
        }
        return $success;
    }
}

sub _get_type ($value) {
    return
        defined ref $value && ref $value ? ref $value
      : defined ref $value               ? 'scalar'
      :                                    'undef';
}

=head2 C<is_one_of>

    is_one_of(
        is_object(
            {
                color => [qw/ red green blue /],
                name  => qr/^[a-z]+$/,
            }
        ),
        is_string('Cyberdyne Systems'),
    );

Returns a sub that will check that the value is one of the things passed to it. Those "things"
need to be subroutines that return true if the value is valid.

=cut

sub is_one_of (@things) {
    if ( @things < 2 ) {
        croak("is_one_of must be passed at least two things");
    }
    if ( @things != grep { 'CODE' eq ref $_ } @things ) {
        croak("is_one_of must be passed only CODE refs");
    }
    return sub ( $parser, $value ) {
        my $name    = $parser->_stack;
        my $success = 0;

        my ( @errors, @warnings );
        THING: for my $thing (@things) {
            $parser->_stash_error_state;
            if ( $parser->$thing($value) ) {
                $success = 1;
            }
            my ( $addded_errors, $added_warnings ) = $parser->_unstash_error_state;
            push @errors,   @$addded_errors;
            push @warnings, @$added_warnings;
            last THING if $success;
        }
        if ( !$success ) {
            foreach my $error (@errors) {
                $parser->_add_error($error);
            }
            foreach my $warning (@warnings) {
                $parser->_add_warning($warning);
            }
            $parser->_add_error("Invalid $name. Does not match any of the specified checks");
        }
        return $success;
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
