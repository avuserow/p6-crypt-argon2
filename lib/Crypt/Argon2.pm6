use v6;
use strict;
use Crypt::Random;
use Crypt::Argon2::Base;

sub EXPORT {
    return Map.new(
        'Argon2Type' => Argon2Type,
        'Argon2_i'   => Argon2_i,
        'Argon2_d'   => Argon2_d,
        'Argon2_id'  => Argon2_id,
    );
}

unit module Crypt::Argon2;

sub argon2-hash(Str $pwd, :$t_cost = 2, :$m_cost = 1 +< 16,
                :$parallelism = 2, :$hashlen = 16,
                Argon2Type :$type = Argon2_i) is export {
    my $saltlen = 16;
    my $encodedlen = argon2_encodedlen($t_cost, $m_cost, $parallelism,
                                       $saltlen, $hashlen, $type.Int);

    my $salt = crypt_random_buf($saltlen);
    my $encoded = Buf.new;
    $encoded[$encodedlen - 1] = 0;

    my $err = do given $type {
        when Argon2_d {
            argon2d_hash_encoded($t_cost, $m_cost, $parallelism,
                                 $pwd, $pwd.encode.bytes,
                                 $salt, $saltlen, $hashlen,
                                 $encoded, $encodedlen);
        }
        when Argon2_i {
            argon2i_hash_encoded($t_cost, $m_cost, $parallelism,
                                 $pwd, $pwd.encode.bytes,
                                 $salt, $saltlen, $hashlen,
                                 $encoded, $encodedlen);
        }
        when Argon2_id {
            argon2id_hash_encoded($t_cost, $m_cost, $parallelism,
                                  $pwd, $pwd.encode.bytes,
                                  $salt, $saltlen, $hashlen,
                                  $encoded, $encodedlen);
        }
        default {
            "unknown type: $type";
        }
    };

    if $err { die("Hashing failed with error code: "~$err); }

    $encoded.decode;
}

sub argon2-find-type($encoded) {
    return Argon2_id if $encoded.starts-with('$argon2id$');
    return Argon2_i if $encoded.starts-with('$argon2i$');
    return Argon2_d if $encoded.starts-with('$argon2d$');
    Argon2Type;
}

sub argon2-verify($encoded, $pwd, Argon2Type :$type is copy) is export {
    $type //= argon2-find-type($encoded);

    my $result = do given $type {
        when Argon2_d {
            argon2d_verify($encoded, $pwd, $pwd.encode.bytes);
        }
        when Argon2_i {
            argon2i_verify($encoded, $pwd, $pwd.encode.bytes);
        }
        when Argon2_id {
            argon2id_verify($encoded, $pwd, $pwd.encode.bytes);
        }
        default {
            -1;
        }
    }

    # ARGON2_OK = 0
    return $result == 0;
}
