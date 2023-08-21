# NAME

CycloneDX::Parser - Parser for CycloneDX SBOMs

# VERSION

version 0.01

# SYNOPSIS

```perl
    my $parser = CycloneDX::Parser->new( json => $file );
    if ( $parser->is_valid ) {
        my $data = $parser->sbom_spec;
    }
    else {
        my @errors = $parser->errors;
        ...
    }
```

# DESCRIPTION

This module parses CycloneDX Software Bill of Materials (SBOMs), version 1.5 JSON.

# AUTHOR

Curtis "Ovid" Poe <curtis.poe@gmail.com>

# COPYRIGHT AND LICENSE

This software is Copyright (c) 2023 by Curtis "Ovid" Poe.

This is free software, licensed under:

```
The Artistic License 2.0 (GPL Compatible)
```
