# NAME

CycloneDX::Parser - Parser for CycloneDX SBOMs

# VERSION

version 0.01

# SYNOPSIS

```perl
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
```

# DESCRIPTION

This module parses CycloneDX Software Bill of Materials (SBOMs), version 1.5
JSON. It is a work in progress.

Eventually earlier versions will be supported, but for now, trying to get it
working and seeing how the design evolves. The code is written with core Perl
because with the upcoming Cyber Security Act (CRA) in the EU, [open-source
code may become a
liability](https://devops.com/the-cyber-resilience-act-threatens-the-future-of-open-source/)
for many companies. By starting to build out programmatically discoverable
Software Bill of Materials (or SBOMs), we can make it easier for companies to
comply with the CRA.

Non-compliance with CRA can mean fines for companies of €15 million, or 2.5%
of global revenue, whichever is higher.  This will give many companies a
_major_ incentive to avoid using open-source, since much of it is not
designed to be easily audited.

# METHODS

## new

```perl
    my $parser = CycloneDX::Parser->new( json => $file );
    # or
    my $parser = CycloneDX::Parser->new( json_string => $json_string );
```

Creates a new parser object. The only argument is a hashref with a single key.
Thay key is `json` and the value is the JSON file to parse. If you wish to
pass in raw JSON instead of a file, use the `json_string` key instead.

## is\_valid

```
    if ( $parser->is_valid ) {
        ...
    }
```

Returns true if the SBOM is valid (warnings are OK, but errors means it's invalid).

## errors

```perl
    my @errors = $parser->errors;
```

Returns a list of errors as printable strings. If the SBOM is valid, the list
will be empty.

## warnings

```perl
    my @warnings = $parser->warnings;
```

Returns a list of warnings as printable strings. If there are no warnings, the
list will be empty.

## sbom\_data

```perl
    my $data = $parser->sbom_data;
```

Returns a hashref of the SBOM data _as\_is_. Note that this is mutable, so changing the data
means you should call `$self->validate` again.

# AUTHOR

Curtis "Ovid" Poe <curtis.poe@gmail.com>

# COPYRIGHT AND LICENSE

This software is Copyright (c) 2023 by Curtis "Ovid" Poe.

This is free software, licensed under:

```
The Artistic License 2.0 (GPL Compatible)
```
