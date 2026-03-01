use Test;

use lib 'lib';

use Crypt::Argon2;


my $hash = argon2-hash("password");
my $hash-reference = '$argon2i$v=19$m=65536,t=4,p=2$QXtq7Djxz/q2h2uAFTy46g$D14zBbQDvfxjIOjCNCM0CsymTb5lns04CoOIMQUJYcs';

ok argon2-verify($hash, "password"), "Verify true new hash";
ok argon2-verify($hash-reference, "password"), "Verify true reference hash";

nok argon2-verify($hash, "password1"), "False-check on new hash";
nok argon2-verify($hash-reference, "password1"), "False-check on reference hash";

for (Argon2_i, Argon2_d, Argon2_id) -> $type {
    ok(
        argon2-verify(argon2-hash("password", :$type), "password"),
        "roundtrip with $type, verify auto-detects type",
    );

    nok(
        argon2-verify(argon2-hash("password", :$type), "password1"),
        "incorrect value with $type, auto-detects type",
    );

    ok(
        argon2-verify(argon2-hash("password", :$type), "password", :$type),
        "roundtrip with $type, explicit type in verify",
    );

    nok(
        argon2-verify(argon2-hash("password", :$type), "password1", :$type),
        "incorrect value with $type, auto-detects type",
    );
}

nok argon2-verify($hash-reference.subst(/^ '$' argon2/, '$argon1'), "password"), "verify false on invalid type";

done-testing;
