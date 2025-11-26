pid_file = "./vault-agent.pid"

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
      role_id_file_path = "./role_id"
      secret_id_file_path = "./secret_id"
    }
  }
}

template_config {
  static_secret_render_interval = "1s"
}

template {
  source      = "./vault-template.ctmpl"
  destination = "../environment_config/centralized_static_creds.env"
  perms       = "0600"
}
