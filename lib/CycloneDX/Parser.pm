package CycloneDX::Parser;

# ABSTRACT: Parser for CycloneDX SBOMs

use v5.14.0;
use strict;
use warnings;
use experimental 'signatures';

use Carp 'croak';
use JSON::PP 'decode_json';

use CycloneDX::Parser::Checks ':all';

our $VERSION = '0.01';

sub new ( $class, %arg_for ) {
    my $self = bless {}, $class;
    $self->_initialize(%arg_for);
    return $self;
}

sub _initialize ( $self, %arg_for ) {
    my $json     = $arg_for{json} or croak 'No JSON provided';
    my $filename = $json;
    if ( ref $json ) {
        $json = $$json;
        undef $filename;
    }
    else {
        open my $fh, '<', $json or croak "Can't open $json: $!";
        $json = do { local $/; <$fh> };
    }
    $self->{source}        = $filename || $json;
    $self->{json}          = decode_json($json);    # the JSON as a Perl structure
    $self->{errors}        = [];                    # accumulate errors
    $self->{warnings}      = [];                    # accumulate warnings
    $self->{stack}         = [];                    # track the current location in the JSON
    $self->{bom_refs_seen} = {};                    # track bom-ref ids to ensure they are unique
    $self->_validate(
        keys => [
            [ 'bomFormat',   is_string('CycloneDX') ],
            [ 'specVersion', is_string('1.5') ],
            [ 'version',     is_string(qr/^[1-9][0-9]*$/) ],
        ],
        required => 1,
        source   => $self->sbom_spec,
    );
    $self->_validate(
        keys => [
            [ 'components', \&_validate_components ],
        ],
        source => $self->sbom_spec,
    );

    return $self;
}

sub is_valid ($self) {
    return !@{ $self->{errors} };
}

sub errors ($self) {
    return @{ $self->{errors} };
}

sub _add_error ( $self, $error ) {
    push @{ $self->{errors} }, $error;
}

sub warnings ($self) {
    return @{ $self->{warnings} };
}

sub _add_warning ( $self, $warning ) {
    push @{ $self->{warnings} }, $warning;
}

sub sbom_spec ($self) {
    return $self->{json};
}

sub _push_stack ( $self, $name ) {
    push @{ $self->{stack} }, $name;
}

sub _pop_stack ($self) {
    pop @{ $self->{stack} };
}

sub _stack ($self) {
    return join '.', @{ $self->{stack} };
}

# Yes, this should use a JSON validator, but we need it to be lightweight
# and not require any non-core modules.
sub _validate ( $self, %arg_for ) {
    foreach my $key ( @{ $arg_for{keys} } ) {
        $self->_push_stack( $key->[0] );
        $self->_validate_key(
            inspect  => $arg_for{source},
            required => $arg_for{required},
            key      => $key->[0],
            matches  => $key->[1],
        );
        $self->_pop_stack;
    }
}

sub _validate_key ( $self, %arg_for ) {
    my ( $data, $key, $required, $matches ) = @arg_for{qw(inspect key required matches )};
    my $name = $self->_stack;
    if ( !exists $data->{$key} ) {
        if ($required) {
            $self->_add_error("Missing required field '$name'");
        }
        return;
    }
    my $value = $data->{$key};
    if ( ref $matches eq 'CODE' ) {
        $self->$matches($value);
    }
    else {
        croak "Invalid matches type: $matches";
    }
}

sub _bom_ref_seen ( $self, $bom_ref ) {
    my $seen = $self->{bom_refs_seen}{$bom_ref};
    $self->{bom_refs_seen}{$bom_ref}++;
    return $seen;
}

sub _validate_components ( $self, $components ) {
    unless ( ref $components eq 'ARRAY' ) {
        $self->_add_error('Components must be an array');
        return;
    }

    foreach my $i ( 0 .. $#$components ) {
        $self->_push_stack($i);
        my $component = $components->[$i];
        $self->_validate(
            keys => [
                [   'type',
                    is_string(
                        [   "application", "framework", "library", "container", "platform", "operating-system", "device", "device-driver", "firmware", "file",
                            "machine-learning-model", "data",
                        ]
                    ),
                ],
                [ 'name', is_string(qr/\S/) ],
            ],
            required => 1,
            source   => $component,
        );
        $self->_validate(
            keys => [
                [ 'version',     is_string(qr/\S/) ],                               # version not enforced
                [ 'mime-type',   is_string( qr{^[-+a-z0-9.]+/[-+a-z0-9.]+$}, ) ],
                [ 'bom-ref',     is_string(qr/\S/) ],
                [ 'author',      is_string(qr/./) ],
                [ 'publisher',   is_string(qr/./) ],
                [ 'group',       is_string(qr/./) ],
                [ 'description', is_string(qr/./) ],
                [ 'scope',       is_string( [qw/required optional excluded/] ) ],
            ],
            source => $component,
        );

        my $name = $self->_stack;

        # bom-ref must be unique
        if ( exists $component->{'bom-ref'} ) {
            if ( $self->_bom_ref_seen( $component->{'bom-ref'} ) ) {
                $self->_add_error( sprintf "$name.bom-ref: Duplicate bom-ref '%s'", $component->{'bom-ref'} );
            }

            # XXX later, we'll have more validation
        }

        if ( exists $component->{modified} ) {
            $self->_add_warning('$name.modified is deprecated and should not be used.');
        }

        # supplier is an object
        #
        $self->_pop_stack;
    }
}

1;

__END__

=head1 SYNOPSIS

        my $parser = CycloneDX::Parser->new( json => $file );
        if ( $parser->is_valid ) {
            my $data = $parser->sbom_spec;
        }
        else {
            my @errors = $parser->errors;
            ...
        }

=head1 DESCRIPTION

This module parses CycloneDX Software Bill of Materials (SBOMs), version 1.5
JSON. It is a work in progress.

Eventually earlier versions will be supported, but for now, trying to get it
working and seeing how the design evolves.
