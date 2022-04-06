my $key=shift;
die "请给出commit消息" unless $key;

`cat Practice_CTF.md Scanner.md Defence.md PenetrationTest.md ProofofConcept_Exploit.md BinaryAnalysis.md ThreatIntelligence_Honey.md SecurityDoucument.md > ALL.md`;
`git add .`;
`git commit -m "$key"`;

`git push  && git push github`; 

