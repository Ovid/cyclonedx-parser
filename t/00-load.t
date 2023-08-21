#!/usr/bin/env perl

use lib 'lib';
use Test::Most;

use CycloneDX::Parser ();

pass "We were able to lood our primary modules";

diag "Testing CycloneDX::Parser CycloneDX::Parser:VERSION, Perl $], $^X";

done_testing;
