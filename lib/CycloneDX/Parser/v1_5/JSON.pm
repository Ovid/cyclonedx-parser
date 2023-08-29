package CycloneDX::Parser::v1_5::JSON;

# ABSTRACT: JSON parser for CycloneDX SBOMs, v1.5

use v5.14.0;
use warnings;
use experimental 'signatures';

use Carp qw(cluck carp croak);
use JSON::PP 'decode_json';

use CycloneDX::Parser::Checks ':all';
use parent 'Exporter';

our @EXPORT_OK = qw(
  sbom_spec
);
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

our $VERSION = '0.01';

# Need to read more about where bom-refs are defined (so we can better ensure
# uniqueness) and where they're consumed (where uniqueness isn't required)

sub sbom_spec () {
    return {
        object => {
            bomFormat    => is_string('CycloneDX'),
            specVersion  => is_string('1.5'),
            components   => \&_validate_components,
            serialNumber => is_string(qr/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
            version      => is_string(qr/^[1-9][0-9]*$/),
            metadata     => is_object(
                {
                    timestamp  => is_string(qr/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\+\d\d:\d\d)?Z?$/),
                    properties => is_array_of(
                        is_object(
                            {
                                name  => non_empty_string,    # valid-properties not failing if I put an empty name
                                value => non_empty_string,
                            }
                        ),
                    ),
                    lifecycles => is_array_of(
                        is_one_of(
                            is_object(
                                {
                                    phase => is_string( [ "design", "pre-build", "build", "post-build", "operations", "discovery", "decommission" ] ),
                                },
                                ['phase']
                            ),
                            is_object( { name => any_string, description => any_string }, ['name'] ),
                        )
                    ),
                    authors => is_array_of(
                        is_object(
                            {
                                name      => non_empty_string,
                                email     => any_string,
                                phone     => any_string,
                                'bom-ref' => non_empty_string,
                            }
                        ),
                    ),
                    manufacture => is_object(
                        {
                            name      => non_empty_string,
                            url       => is_array_of(any_string),
                            'bom-ref' => non_empty_string,
                            contact   => is_array_of(
                                is_object(
                                    {
                                        name      => non_empty_string,
                                        email     => any_string,
                                        phone     => any_string,
                                        'bom-ref' => non_empty_string,
                                    }
                                ),
                            ),
                        }
                    ),
                },

                # tools
                # component
                # supplier
                # licenses
            ),

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

        # for 1.5, these are the only required fields. `version` is no longer required
        # because if it's missing, it has an optional value of 1.
        required => [qw(bomFormat specVersion )],
    };
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
                    ],
                ),
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
            required => [qw( name type )],
            source   => $component,
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
