makecert -r -sv test.pvk -n "CN=KTLiang" test.cer
pvk2pfx -pvk test.pvk -spc test.cer -pfx test.pfx -po 123
