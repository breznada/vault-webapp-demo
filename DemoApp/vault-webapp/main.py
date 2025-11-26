from flask import Flask, render_template, request
import psycopg2
from dotenv import dotenv_values
import requests
from datetime import datetime, timedelta

app = Flask(__name__)

last_dynamic_creds = None
last_lease_expiry = None

def connect_db_from_env(env_file):
    try:
        creds = dotenv_values(env_file)
        conn = psycopg2.connect(
            host=creds.get("DB_HOST"),
            port=creds.get("DB_PORT"),
            dbname=creds.get("DB_NAME"),
            user=creds.get("DB_USER"),
            password=creds.get("DB_PASSWORD")
        )
        conn.close()
        return True, (
            f"<strong>Connection Successful!</strong><br><br>"
            f"<ul>"
            f"<li><strong>Host:</strong> {creds.get('DB_HOST')}</li>"
            f"<li><strong>Port:</strong> {creds.get('DB_PORT')}</li>"
            f"<li><strong>Database:</strong> {creds.get('DB_NAME')}</li>"
            f"<li><strong>User:</strong> {creds.get('DB_USER')}</li>"
            f"</ul>"
        )
    except Exception as e:
        return False, f"<strong>Connection failed:</strong><br>{str(e)}"

def connect_db_with_dynamic_secrets(vault_addr, token_file):
    global last_dynamic_creds, last_lease_expiry
    try:
        with open(token_file, 'r') as f:
            token = f.read().strip()

        headers = {"X-Vault-Token": token}
        response = requests.get(f"{vault_addr}/v1/database/creds/vault-webapp-role", headers=headers)

        if response.status_code != 200:
            return False, f"<strong>Failed to fetch dynamic secrets:</strong><br>{response.text}", None

        creds = response.json()["data"]
        lease_duration = response.json().get("lease_duration", 30)

        last_dynamic_creds = creds
        last_lease_expiry = datetime.utcnow() + timedelta(seconds=lease_duration)

        conn = psycopg2.connect(
            host="192.168.34.28",
            port="5432",
            dbname="postgres",
            user=creds["username"],
            password=creds["password"]
        )
        conn.close()

        msg = (
            f"<strong>Connected with dynamic secrets!</strong><br><br>"
            f"<ul>"
            f"<li><strong>Username:</strong> {creds['username']}</li>"
            f"<li><strong>Password:</strong> {creds['password']}</li>"
            f"</ul>"
        )
        return True, msg, last_lease_expiry

    except Exception as e:
        return False, f"<strong>Error:</strong><br>{str(e)}", None

def reconnect_with_cached_creds():
    global last_dynamic_creds
    if not last_dynamic_creds:
        return False, "<strong>No cached dynamic credentials available. First connect using dynamic secrets.</strong>"

    try:
        creds = last_dynamic_creds

        conn = psycopg2.connect(
            host="192.168.34.28",
            port="5432",
            dbname="postgres",
            user=creds["username"],
            password=creds["password"]
        )
        conn.close()

        return True, (
            f"<strong>Reconnected with cached dynamic credentials!</strong><br><br>"
            f"<ul>"
            f"<li><strong>Username:</strong> {creds['username']}</li>"
            f"<li><strong>Password:</strong> {creds['password']}</li>"
            f"</ul>"
        )

    except Exception as e:
        return False, f"<strong>Error reconnecting with cached credentials:</strong><br>{str(e)}"

@app.route("/", methods=["GET", "POST"])
def index():
    message = None
    success = False
    clicked_button = None
    lease_expiry = None

    if request.method == "POST":
        if "connect_env" in request.form:
            clicked_button = "connect_env"
            success, message = connect_db_from_env("environment_config/uncentralized_static_creds.env")
        elif "connect_vault" in request.form:
            clicked_button = "connect_vault"
            success, message = connect_db_from_env("environment_config/centralized_static_creds.env")
        elif "connect_dynamic" in request.form:
            clicked_button = "connect_dynamic"
            success, message, lease_expiry = connect_db_with_dynamic_secrets("http://192.168.34.25:8200", "environment_config/centralized_dynamic_creds.env")
        elif "reconnect_cached" in request.form:
            clicked_button = "reconnect_cached"
            success, message = reconnect_with_cached_creds()
        elif "encrypt_text" in request.form:
            clicked_button = "encrypt_text"
            text_to_encrypt = request.form.get("plaintext_input")
            try:
                with open("environment_config/centralized_dynamic_creds.env") as f:
                    token = f.read().strip()
                headers = {"X-Vault-Token": token}
                response = requests.post(
                    "http://192.168.34.25:8200/v1/transit/encrypt/vaultdemo",
                    headers=headers,
                    json={"plaintext": text_to_encrypt.encode("utf-8").hex()}
                )
                if response.ok:
                    cipher = response.json()["data"]["ciphertext"]
                    message = f"Encrypted Text: <code>{cipher}</code>"
                    success = True
                else:
                    message = f"<strong>Encryption failed:</strong> {response.text}"
                    success = False
            except Exception as e:
                message = f"<strong>Error:</strong> {str(e)}"
                success = False
        elif "decrypt_text" in request.form:
            clicked_button = "decrypt_text"
            ciphertext_input = request.form.get("ciphertext_input")
            try:
                with open("environment_config/centralized_dynamic_creds.env") as f:
                    token = f.read().strip()
                headers = {"X-Vault-Token": token}
                response = requests.post(
                    "http://192.168.34.25:8200/v1/transit/decrypt/vaultdemo",
                    headers=headers,
                    json={"ciphertext": ciphertext_input}
                )
                if response.ok:
                    plaintext_hex = response.json()["data"]["plaintext"]
                    decrypted = bytes.fromhex(plaintext_hex).decode("utf-8")
                    message = f"Decrypted Text: <code>{decrypted}</code>"
                    success = True
                else:
                    message = f"<strong>Decryption failed:</strong> {response.text}"
                    success = False
            except Exception as e:
                message = f"<strong>Error:</strong> {str(e)}"
                success = False
        elif "generate_cert" in request.form:
            clicked_button = "generate_cert"
            cn = request.form.get("common_name", "demo.tec.cz.ibm.com")  # Default if empty
            try:
                with open("environment_config/centralized_dynamic_creds.env") as f:
                    token = f.read().strip()

                headers = {"X-Vault-Token": token}
                cert_response = requests.post(
                    "http://192.168.34.25:8200/v1/pki/issue/tec-role",
                    headers=headers,
                    json={
                        "common_name": cn
                    }
                )

                if cert_response.ok:
                    cert_data = cert_response.json()["data"]
                    cert = cert_data["certificate"]
                    issuing_ca = cert_data["issuing_ca"]
                    private_key = cert_data["private_key"]
                    serial_number = cert_data["serial_number"]

                    message = (
                        "<strong>Certificate Issued Successfully!</strong><br><br>"
                        f"<strong>Serial Number:</strong> {serial_number}<br><br>"
                        f"<strong>Certificate:</strong><br><pre>{cert}</pre><br>"
                        f"<strong>Private Key:</strong><br><pre>{private_key}</pre><br>"
                        f"<strong>Issuing CA:</strong><br><pre>{issuing_ca}</pre>"
                    )
                    success = True
                else:
                    message = f"<strong>Certificate generation failed:</strong><br>{cert_response.text}"
                    success = False
            except Exception as e:
                message = f"<strong>Error:</strong><br>{str(e)}"
                success = False

    return render_template("index.html", message=message, success=success, clicked_button=clicked_button, lease_expiry=lease_expiry)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
