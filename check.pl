my $key=shift;

open my $F,'<','All.md';

while(<$F>) {
    print "$_\n" if /$key/;

}
