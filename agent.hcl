# Update this file for your environment before production use.
pid_file = "C:/ProgramData/Vault/agent.pid"

vault {
  address = "http://10.128.0.5:8200"
}

auto_auth {
  method  {
    type = "approle"
    config = {
      role_id_file_path   = "C:/ProgramData/Vault/role_id"
      secret_id_file_path = "C:/ProgramData/Vault/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink {
    type = "file"
    config = {
      path = "C:/ProgramData/Vault/token"
    }
  }
}


template_config {
  static_secret_render_interval = "5m"
}
  
template {
    source      = "C:/ProgramData/Vault/pki-cert.tpl"
    destination = "C:/ProgramData/Vault/pki-cert.pem"
    exec {
      command = ["powershell.exe", "C:/ProgramData/Vault/install-cert.ps1"]
      timeout = "30s"
    }
  }