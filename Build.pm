use v6;
use LibraryMake;

class Build {
    method build($dist) {
        if !$*DISTRO.is-win {
            my $ext = "$dist/ext/argon2-20210621";
            my $res = "$dist/resources/libraries";

            my %vars = get-vars($ext);

            mkdir("$dist/resources");
            mkdir($res);
            chdir($ext);
            my $make = %vars<MAKE>;
            # ensure enums are always a full-sized int
            my $env = (|%*ENV, :CFLAGS<-fno-short-enums>);
            my $proc = shell("$make libs", :$env);

            if $proc.exitcode != 0 {
                die("make failure: "~$proc.exitcode);
            }

            my $so = %vars<SO>;
            move("$ext/libargon2$so.1", "$res/libargon2$so");
        }
    }

    method isa($what) {
        return True if $what.^name eq 'Panda::Builder';
        callsame;
    }
}
