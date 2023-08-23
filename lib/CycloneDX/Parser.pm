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
    my $json        = $arg_for{json};
    my $json_string = $arg_for{json_string};

    if ( $json && $json_string ) {
        my $class = ref $self;
        croak "You must specify only one of 'json' and 'json_string' when contructing a $class";
    }

    my $filename = $json;
    if ($json_string) {
        undef $filename;
    }
    if ( ref $json ) {
        $json = $$json;
        undef $filename;
    }
    else {
        open my $fh, '<', $json or croak "Can't open $json: $!";
        $json_string = do { local $/; <$fh> };
    }
    $self->{filename}  = $filename;                    # the source of the JSON, if file passed
    $self->{raw_json}  = $json_string;                 # the JSON as a string
    $self->{sbom_data} = decode_json($json_string);    # the JSON as a Perl structure
    $self->validate;

    if ( $self->has_warnings ) {

        # note: currenty the only warnings is about the deprected 'modified' field
        warn "Warnings:\n";
        foreach my $warning ( $self->warnings ) {
            warn "  $warning\n";
        }
    }

    return $self;
}

sub validate ($self) {

    # make sure theyse are empty before we start validation.
    $self->{errors}        = [];    # accumulate errors
    $self->{warnings}      = [];    # accumulate warnings
    $self->{stack}         = [];    # track the current location in the JSON
    $self->{bom_refs_seen} = {};    # track bom-ref ids to ensure they are unique

    # for 1.5, these are the only required fields. `version` is no longer required
    # because if it's missing, it has an optional value of 1.
    $self->_validate(
        object => {
            bomFormat   => is_string('CycloneDX'),
            specVersion => is_string('1.5'),
        },
        required => 1,
        source   => $self->sbom_data,
    );
    $self->_validate(
        object => {
            components   => \&_validate_components,
            serialNumber => is_string(qr/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
            version      => is_string(qr/^[1-9][0-9]*$/),
            metadata     => is_object(
                {
                    timestamp  => is_string(qr/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\+\d\d:\d\d)?Z?$/),
                    properties => is_arrayref_of_objects(
                        {
                            name  => non_empty_string,    # valid-properties not failing if I put an empty name
                            value => non_empty_string,
                        }
                    ),
                },
            ),

            # lifecycles
            # services
            # dependencies
            # externalReferences
            # properties
            # vulnerabilities
            # annotations
            # formulation
            # properties
            # signature
        },
        source => $self->sbom_data,
    );
}

sub raw_json ($self) {
    return $self->{raw_json};
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

sub has_warnings ($self) {
    return !!@{ $self->{warnings} };
}

sub _add_warning ( $self, $warning ) {
    push @{ $self->{warnings} }, $warning;
}

sub sbom_data ($self) {
    return $self->{sbom_data};
}

sub _push_stack ( $self, $name ) {
    push @{ $self->{stack} }, $name;
}

sub _pop_stack ($self) {
    pop @{ $self->{stack} };
}

sub _stack ($self) {
    my $stack = join '.', @{ $self->{stack} };
    $stack = "<unknown>" if !length $stack;
    return $stack;
}

# Yes, this should use a JSON validator, but we need it to be lightweight
# and not require any non-core modules.
# Also, "No additional properties" is hard to properly handle until we have
# the full list of properties included.
sub _validate ( $self, %arg_for ) {
    foreach my $key ( sort keys %{ $arg_for{object} } ) {
        my $matches = $arg_for{object}->{$key};
        $self->_push_stack($key);
        $self->_validate_key(
            inspect  => $arg_for{source},
            required => $arg_for{required},
            key      => $key,
            matches  => $matches,
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
            object => {
                name => is_string(qr/\S/),
                type => is_string(
                    [   "application",
                        "framework",
                        "library",
                        "container",
                        "platform",
                        "operating-system",
                        "device",
                        "device-driver",
                        "firmware",
                        "file",
                        "machine-learning-model",
                        "data",
                    ]
                ),
            },
            required => 1,
            source   => $component,
        );
        $self->_validate(
            object => {
                version     => non_empty_string,                                # version not enforced
                'mime-type' => is_string( qr{^[-+a-z0-9.]+/[-+a-z0-9.]+$}, ),
                'bom-ref'   => non_empty_string,
                author      => any_string,
                publisher   => any_string,
                group       => any_string,
                description => any_string,
                scope       => is_string( [qw/required optional excluded/] ),
                copyright   => any_string,
                cpe         => any_string,                                      # dont' have great info on matching a "well-formed CPE string"
                    # See # https://metacpan.org/dist/URI-PackageURL/source/lib/URI/PackageURL.pm # for purl
                purl       => is_string(qr{^pkg:[A-Za-z\\.\\-\\+][A-Za-z0-9\\.\\-\\+]*/.+}),
                components => \&_validate_components,                                          # yup, components can take components

                # supplier is an object
                # hashes is an array of objects
                # licenses is an array of objects
                # externalReferences is an array of objects
                # data is an array of objects
                # properties is an array of objects
                # swid is an object
                # pedigree is an object
                # evidence is an object
                # releaseNotes is an object
                # modelCard is an object
                # signature is an object
            },
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

        $self->_pop_stack;
    }
}

1;

__END__

=head1 SYNOPSIS

        my $parser = CycloneDX::Parser->new( json => $file );
        # or
        my $parser = CycloneDX::Parser->new( json_string => $json_string );
        if ( $parser->is_valid ) {
            my $data = $parser->sbom_data;
        }
        else {
            my @errors = $parser->errors;
            ...
        }


=head1 DESCRIPTION

This module parses CycloneDX Software Bill of Materials (SBOMs), version 1.5
JSON. It is a work in progress.

Eventually earlier versions will be supported, but for now, trying to get it
working and seeing how the design evolves. The code is written with core Perl
because with the upcoming Cyber Security Act (CRA) in the EU, L<open-source
code may become a
liability|https://devops.com/the-cyber-resilience-act-threatens-the-future-of-open-source/>
for many companies. By starting to build out programmatically discoverable
Software Bill of Materials (or SBOMs), we can make it easier for companies to
comply with the CRA.

Non-compliance with CRA can mean fines for companies of €15 million, or 2.5%
of global revenue, whichever is higher.  This will give many companies a
I<major> incentive to avoid using open-source, since much of it is not
designed to be easily audited.

=head1 METHODS

=head2 new

        my $parser = CycloneDX::Parser->new( json => $file );
        # or
        my $parser = CycloneDX::Parser->new( json_string => $json_string );

Creates a new parser object. The only argument is a hashref with a single key.
Thay key is C<json> and the value is the JSON file to parse. If you wish to
pass in raw JSON instead of a file, use the C<json_string> key instead.

=head2 is_valid

        if ( $parser->is_valid ) {
            ...
        }

Returns true if the SBOM is valid (warnings are OK, but errors means it's invalid).

=head2 errors

        my @errors = $parser->errors;

Returns a list of errors as printable strings. If the SBOM is valid, the list
will be empty.

=head2 warnings

        my @warnings = $parser->warnings;

Returns a list of warnings as printable strings. If there are no warnings, the
list will be empty.

=head2 sbom_data

        my $data = $parser->sbom_data;

Returns a hashref of the SBOM data I<as_is>. Note that this is mutable, so changing the data
means you should call C<< $self->validate >> again.
