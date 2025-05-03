use Test;

use lib 'lib';

use Crypt::Argon2::DeriveKey;



my ($key, $meta) = argon2-derive-key("password");

my $test = argon2-derive-key("password", $meta);

ok $test eqv $key, "Key can be successfully re-derived";

for (Argon2_i, Argon2_d, Argon2_id) -> $type {
    my ($key, $meta) = argon2-derive-key("password", :$type);
    is $meta.type, $type, "meta has correct type when using $type";
    is-deeply $key, argon2-derive-key("password", $meta), "can re-derive key using $type";
}


done-testing;
