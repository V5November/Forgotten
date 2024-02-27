use strict;
use warnings;

my $ciphertext = "+\x7ft1*iK\x1c[Io\x16\x1a\x00o\x1aYS\x03+\x10\x00B\t";
#unpacks the ciphertext string into an array
my @ciphertext_bytes = unpack("C*", $ciphertext);

# Iterate over the key bytes
#These nested for loops iterate over all possible combinations of four bytes ($k1, $k2, $k3, $k4) representing the key. The range (32..126) represents the printable ASCII characters.
for my $k1 (32..126) {
    for my $k2 (32..126) {
        for my $k3 (32..126) {
            for my $k4 (32..126) {
                my @key = ($k1, $k2, $k3, $k4);

                my $plaintext = '';
                for my $i (0..$#ciphertext_bytes) {
                    my $key_byte = $key[$i % 4]; #Retrieves the corresponding key byte from the @key array, ensuring that the key bytes repeat cyclically
                    my $decrypted_byte = $ciphertext_bytes[$i] ^ $key_byte; #XORs the current byte of the ciphertext with the corresponding key byte to decrypt the byte
                    # Check if the decrypted byte is a printable ASCII character
                    if ($decrypted_byte >= 32 && $decrypted_byte <= 126) {
                        $plaintext .= chr($decrypted_byte);
                    } else {
                        last; # Skip this key if decrypted byte is not printable ASCII
                    }
                }

                if ($plaintext =~ /CODEBY\{/) {
                    print "Found key: @key\n";
                    print "Plaintext: $plaintext\n";
                    exit; # Exit the script after finding the key
                }
            }
        }
    }
}
