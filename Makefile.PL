use ExtUtils::MakeMaker;
use Config;
use Cwd qw /abs_path/;

my @include_dirs = (
	$ENV{'CTPP2_INCLUDE'}, 
	"/usr/local/include/ctpp2", 
	"/usr/include/ctpp2", 
	"/opt/include/ctpp2", 
	"/opt/REKIctpp2/include/ctpp2", 
	"/usr/local/ctpp2/include"
);
my @LibDirs = (
	$ENV{'CTPP2_LIB'},
	"/usr/local/lib",
	"/usr/lib",
	"/opt/lib",
	"/opt/REKIctpp2/lib",
	"/usr/local/ctpp2/lib"
);

sub search_dir {
	my ($f, $dirs) = @_;
	foreach (@{$dirs}) {
		return $_ if (-e "$_/$f");
	}
	return undef;
}

my $ctpp2_inc_dir = search_dir("CDT.hpp", \@include_dirs);
my $ctpp2_lib_dir = search_dir("libctpp2.so.2", \@LibDirs);

if (!$ctpp2_lib_dir || !$ctpp2_inc_dir) {
	die "CTPP2 not found!\n";
}

$ctpp2_lib_dir = abs_path($ctpp2_lib_dir);
$ctpp2_inc_dir = abs_path($ctpp2_inc_dir);

WriteMakefile(
	'NAME'          => 'HTML::CTPP2_8',
	'VERSION_FROM'  => 'lib/HTML/CTPP2_8.pm',
	'LIBS'          => "-L$ctpp2_lib_dir -L/usr/lib -lm -lctpp2 $rpath",
	'DEFINE'        => '-fexceptions -O2 -Wno-deprecated -Wall '.$Config{ccflags},
	'INC'           => "-I$ctpp2_inc_dir -I/usr/include -I/usr/local/include -I. ",
	'CC'            => 'g++',
	'LD'            => 'g++',
	'XSOPT'         => '-C++',
	'clean'         => { 'FILES' => '*.ct2' },
	'TYPEMAPS'      => ['perlobject.map'], 
	'OBJECT'        => 'CTPP2_8.o ctpp2.o ctpp2_functions.o'
);
