# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl HTML-CTPP2.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 5;
use HTML::CTPP2_8;
BEGIN { use_ok('HTML::CTPP2_8') };

use strict;
use MIME::Base64;
use IO::Scalar;

my $T = new HTML::CTPP2_8();
ok( ref $T eq "HTML::CTPP2_8", "Create object.");

my $Bytecode = $T -> parse_template("charset_recoder.tmpl");
ok( ref $Bytecode eq "HTML::CTPP2_8::Bytecode", "Create object.");

my $data = '���� ��������� ';
my $SH = new IO::Scalar \$data;
$SH -> print('CP-1251');

my %H = ("a" => $SH);
ok( $T -> param(\%H) == 0);

my $Result = encode_base64($T -> output($Bytecode));
ok( $Result eq "0uXx8jog0uXx8iDq7uTo8O7i6uggQ1AtMTI1MQo=\n");

$T -> reset();
