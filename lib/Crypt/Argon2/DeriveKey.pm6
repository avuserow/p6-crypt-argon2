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

unit module Crypt::Argon2::DeriveKey;



class Argon2-meta is export {
    has uint32 $.t_cost is required;
    has uint32 $.m_cost is required;
    has uint32 $.parallelism is required;
    has uint32 $.hashlen is required;
    has Buf $.salt is required;
    has Argon2Type $.type = Argon2_i;
}



multi sub argon2-derive-key(Str $pwd, :$t_cost = 3, :$m_cost = 1 +< 17,
                            :$parallelism = 2, :$hashlen = 32,
                            Argon2Type :$type = Argon2_i) is export {

    my $saltlen = 16;
    my $salt = crypt_random_buf($saltlen);

    my $meta = Argon2-meta.new(:$t_cost, :$m_cost, :$parallelism,
                               :$hashlen, :$salt, :$type);

    my $key = argon2-derive-key($pwd, $meta);
    $key, $meta;
}

multi sub argon2-derive-key(Str $pwd, Argon2-meta $meta) is export {
    my $key = Buf.new;
    $key[$meta.hashlen - 1] = 0;

    my $err = do given $meta.type {
        when Argon2_d {
            argon2d_hash_raw($meta.t_cost, $meta.m_cost, $meta.parallelism,
                             $pwd, $pwd.encode.bytes,
                             $meta.salt, $meta.salt.elems,
                             $key, $meta.hashlen);
        }
        when Argon2_i {
            argon2i_hash_raw($meta.t_cost, $meta.m_cost, $meta.parallelism,
                             $pwd, $pwd.encode.bytes,
                             $meta.salt, $meta.salt.elems,
                             $key, $meta.hashlen);
        }
        when Argon2_id {
            argon2id_hash_raw($meta.t_cost, $meta.m_cost, $meta.parallelism,
                              $pwd, $pwd.encode.bytes,
                              $meta.salt, $meta.salt.elems,
                              $key, $meta.hashlen);
        }
        default {
            "unknown Argon2 type: {$meta.type}";
        }
    }

    if $err { die("Hashing failed with error code: "~$err); }

    $key;
}

