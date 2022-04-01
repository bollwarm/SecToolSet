my $key=shift;
die "请给出commit消息" unless $key;

`git add .`;
`git commit -m "$key"`;

`git push  && git push github`; 

