package CycloneDX::Parser;

# ABSTRACT: Parser for CycloneDX SBOMs

use v5.14.0;
use strict;
use warnings;
use experimental 'signatures';

use Carp qw(cluck carp croak);
use JSON::PP 'decode_json';

use CycloneDX::Parser::Checks ':all';

our $VERSION = '0.01';

sub new ( $class, %arg_for ) {
    my $self = bless {}, $class;
    $self->_initialize(%arg_for);
    return $self;
}

sub _initialize ( $self, %arg_for ) {
    my $filename    = $arg_for{json} // '';
    my $json_string = $arg_for{json_string};

    if ( $filename && $json_string ) {
        my $class = ref $self;
        croak "You must specify only one of 'json' and 'json_string' when contructing a $class";
    }

    if ($filename) {
        open my $fh, '<', $filename or croak "Can't open $filename for reading: $!";
        $json_string = do { local $/; <$fh> };
    }
    $self->{filename}    = $filename;              # the source of the JSON, if file passed
    $self->{json}        = $json_string;           # the JSON as a string
    $self->{debug}       = $arg_for{debug} // 0;
    $self->{error_state} = {                       # will be used to stash error state from recoverable errors
        stashed  => undef,                         # have we previously stashed an error?
        errors   => [],
        warnings => [],
    };
    $self->{sbom_data} = eval {
        decode_json($json_string);                 # the JSON as a Perl structure
    } or do {
        croak "Invalid JSON in $filename: $@";
    };

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
        required => [qw( bomFormat specVersion )],
        source   => $self->sbom_data,
    );
}

sub json ($self) {
    return $self->{json};
}

sub is_valid ($self) {
    return !@{ $self->{errors} };
}

sub errors ($self) {
    return @{ $self->{errors} };
}

sub warnings ($self) {
    return @{ $self->{warnings} };
}

sub has_warnings ($self) {
    return !!@{ $self->{warnings} };
}

sub sbom_data ($self) {
    return $self->{sbom_data};
}

sub set_debug_level ( $self, $level ) {
    $self->{debug} = $level;
}

sub _stash_error_state ($self) {
    my $error_state = $self->{error_state};
    my $stack       = $self->_stack;
    $self->_debug( 1, "Stashing error state at $stack" );
    $self->_debug_dump( 1, { error_state => $error_state, errors => $self->{errors}, warnings => $self->{warnings} } );
    if ( my $stack = $error_state->{stashed} ) {

        # I might want a true stack here and push errors onto
        # the stack and pop them off as appropriate
        croak "Can't stash error state twice: $stack";
    }
    $error_state->{stashed} = $self->_stack;

    # shallow copies to avoid referencing
    $error_state->{errors}   = [ @{ $self->{errors} } ];
    $error_state->{warnings} = [ @{ $self->{warnings} } ];
}

sub _unstash_error_state ($self) {
    my $error_state = $self->{error_state};
    if ( !$error_state->{stashed} ) {
        croak "Can't unstash error state when it hasn't been stashed";
    }

    my $stashed_error_state   = $error_state->{errors};
    my $stashed_warning_state = $error_state->{warnings};
    my $old_error_count       = @$stashed_error_state;
    my $old_warning_count     = @$stashed_warning_state;

    my @new_errors   = @{ $self->{errors} };
    my @new_warnings = @{ $self->{warnings} };

    my @added_errors   = splice @new_errors,   0, $old_error_count;
    my @added_warnings = splice @new_warnings, 0, $old_warning_count;

    # shallow copies to avoid referencing
    $self->{errors}   = [@$stashed_error_state];
    $self->{warnings} = [@$stashed_warning_state];

    $error_state->{stashed} = undef;
    my $stack = $self->_stack;
    $self->_debug( 0, "Unstashed error state at $stack" );
    $self->_debug_dump( 0, { error_state => $error_state, errors => $self->{errors}, warnings => $self->{warnings} } );

    return \@added_errors, \@added_warnings;
}

sub _add_error ( $self, $error ) {
    push @{ $self->{errors} }, $error;
}

sub _add_warning ( $self, $warning ) {
    push @{ $self->{warnings} }, $warning;
}

sub _push_stack ( $self, $name ) {
    if ( $self->_is_debugging ) {
        my $stack = $self->_stack;
        $self->_debug( 1, "Pushing $name onto stack: $stack" );
    }
    push @{ $self->{stack} }, $name;
}

sub _debug_leader ( $self, $char ) {
    my $stack = $self->_stack;
    my $num   = 1 + $stack =~ tr/././;
    $num *= 2;
    return $char x $num;
}

sub _pop_stack ($self) {
    my $name = pop @{ $self->{stack} };
    if ( $self->_is_debugging ) {
        my $stack = $self->_stack;
        $self->_debug( 0, "Popped $name off stack: $stack" );
    }
}

sub _is_debugging ($self) {
    return $self->{debug};
}

sub _debug ( $self, $in, $string ) {
    return unless $self->_is_debugging;
    my $leader = $self->_debug_leader( $in ? '>' : '<' );
    $string = "$leader $string";
    1 == $self->{debug} ? carp $string : carp $string;
}

sub _debug_dump ( $self, $in, $data ) {
    return unless $self->_is_debugging > 1;
    my $leader = $self->_debug_leader( $in ? '>' : '<' );
    my $spaces = ' ' x length $leader;

    require Data::Dumper;
    no warnings 'once';
    local $Data::Dumper::Terse     = 1;
    local $Data::Dumper::Indent    = 1;
    local $Data::Dumper::Sortkeys  = 1;
    local $Data::Dumper::Quotekeys = 0;
    $data = Data::Dumper::Dumper($data);
    $data =~ s/^/$spaces /mg;
    $data =~ s/$spaces/$leader/;
    carp $data;
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
    my $required = $arg_for{required} // [];
    my $source   = $arg_for{source};

    my %is_required = map { $_ => 1 } @$required;

    my @errors = $self->errors;
    KEY: foreach my $key ( sort keys %{ $arg_for{object} } ) {
        my $matches = $arg_for{object}{$key};
        $self->_push_stack($key);
        my $name = $self->_stack;
        if ( !exists $source->{$key} ) {
            if ( $is_required{$key} ) {
                $self->_add_error("Missing required field '$name'");
            }
        }
        else {
            my $value = $source->{$key};
            if ( ref $matches eq 'CODE' ) {
                $self->$matches($value);
            }
            else {
                croak "Invalid matches type: $matches";
            }
        }
        $self->_pop_stack;
    }
    if ( $self->errors > @errors ) {

        # new errors were found, so we return false
        return;
    }
    return 1;
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
