pid_file = "./vault-agent-dynamic.pid"

vault {
  address = "http://192.168.34.25:8200"
  retry {
    num_retries = 5
  }
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "./role_id"
      secret_id_file_path = "./secret_id"
    }
  }

  sink "file" {
    config = {
      path = "../environment_config/centralized_dynamic_creds.env"
      mode = 0600
    }
  }
}

