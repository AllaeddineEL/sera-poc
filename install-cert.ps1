Start-Process -FilePath "certutil.exe" `
    -ArgumentList "-p TestIISPassword,TestIISPassword -MergePFX iis.cer iis.pfx" `
    -Wait -NoNewWindow
Start-Process -FilePath "certutil.exe" `
    -ArgumentList "-p TestIISPassword -importPFX iis.pfx" `
    -Wait -NoNewWindow    

  