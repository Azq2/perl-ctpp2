# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl HTML-CTPP2.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 3;
use HTML::CTPP2_8;
BEGIN { use_ok('HTML::CTPP2_8') };

use strict;
use MIME::Base64;

my $T = new HTML::CTPP2_8();
ok( ref $T eq "HTML::CTPP2_8", "Create object.");

$T -> json_param('{ "foo": "bar", "baz" : 123}');

ok (encode_base64($T -> dump_params()) eq "ewogICdiYXonIDogMTIzLAogICdmb28nIDogImJhciIKfQ==\n");
