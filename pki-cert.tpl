{{ with pkiCert "pki_int/issue/win-iis" "common_name=ip-172-31-67-198.ec2.internal" "ttl=2m"}}
{{ .Data.Cert }}{{ .Data.CA }}{{ .Data.Key }}
{{ .Data.Key | writeToFile "C:/ProgramData/Vault/ip-172-31-67-198-ec2.key" "" "" "0644"}}
{{ .Data.Cert | writeToFile "C:/ProgramData/Vault/ip-172-31-67-198-ec2.cer" "" "" "0644" }}
{{ end }}   