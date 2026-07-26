/*
 * miniadb.c — Minimal ADB client for the Anchor bootstrap.
 * Connects to localhost:5555 and authenticates with the app-private RSA key,
 * opens a shell, and runs a command. Uses dlopen(libcrypto.so) for RSA.
 */
#include "common.h"
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define A_CNXN 0x4e584e43
#define A_AUTH 0x48545541
#define A_OPEN 0x4e45504f
#define A_OKAY 0x59414b4f
#define A_WRTE 0x45545257
#define A_CLSE 0x45534c43
#define AUTH_TOKEN     1
#define AUTH_SIGNATURE 2
#define AUTH_RSAPUBKEY 3
#define ADB_VERSION    0x01000001
#define MAX_PAYLOAD    4096
#define NID_SHA1   64
#define NID_SHA256 672

struct adb_msg {
  uint32_t command, arg0, arg1, data_length, data_crc32, magic;
};

/* The app supplies its per-device ADB key pair from noBackupFilesDir. */
static const char *adb_key_path(void) {
  const char *path = getenv("ANCHOR_ADBKEY_PATH");
  return (path && path[0]) ? path : NULL;
}

static const char *adb_key_pub_path(void) {
  const char *path = getenv("ANCHOR_ADBKEY_PUB_PATH");
  return (path && path[0]) ? path : NULL;
}

static uint32_t payload_sum(const uint8_t *d, size_t n) {
  uint32_t s = 0;
  for (size_t i = 0; i < n; i++) s += d[i];
  return s;
}

static int adb_send(int fd, uint32_t cmd, uint32_t a0, uint32_t a1,
                    const void *data, uint32_t len) {
  struct adb_msg m = {cmd, a0, a1, len,
                      data ? payload_sum(data, len) : 0,
                      cmd ^ 0xffffffff};
  if (write(fd, &m, 24) != 24) return -1;
  if (len && data && write(fd, data, len) != (ssize_t)len) return -1;
  return 0;
}

static int adb_recv(int fd, struct adb_msg *m, uint8_t *buf, size_t cap) {
  if (read(fd, m, 24) != 24) return -1;
  if (m->data_length > 0) {
    if (m->data_length > cap) return -1;
    size_t got = 0;
    while (got < m->data_length) {
      ssize_t n = read(fd, buf + got, m->data_length - got);
      if (n <= 0) return -1;
      got += n;
    }
  }
  return 0;
}

static int sign_token(const uint8_t *tok, size_t tok_len,
                      uint8_t *sig, unsigned *sig_len) {
  void *lib = dlopen("libcrypto.so", RTLD_NOW);
  if (!lib) lib = dlopen("/system/lib64/libcrypto.so", RTLD_NOW);
  if (!lib) { pr_error("dlopen libcrypto: %s\n", dlerror()); return -1; }

  void *(*bio_new_file)(const char *, const char *) = dlsym(lib, "BIO_new_file");
  void *(*pem_read)(void *, void **, void *, void *) =
      dlsym(lib, "PEM_read_bio_RSAPrivateKey");
  int (*rsa_sign)(int, const uint8_t *, unsigned, uint8_t *, unsigned *, void *) =
      dlsym(lib, "RSA_sign");
  void (*rsa_free)(void *) = dlsym(lib, "RSA_free");
  void (*bio_free)(void *) = dlsym(lib, "BIO_free_all");

  if (!bio_new_file || !pem_read || !rsa_sign || !rsa_free || !bio_free) {
    pr_error("libcrypto: missing symbols\n");
    dlclose(lib);
    return -1;
  }

  const char *key_path = adb_key_path();
  if (!key_path) {
    pr_error("missing app-private adb key\n");
    dlclose(lib);
    return -1;
  }
  void *bio = bio_new_file(key_path, "r");
  if (!bio) { pr_error("cannot open %s\n", key_path); dlclose(lib); return -1; }

  void *rsa = pem_read(bio, NULL, NULL, NULL);
  bio_free(bio);
  if (!rsa) { pr_error("cannot parse %s\n", key_path); dlclose(lib); return -1; }

  /* Try SHA-1 first (older adbd), then SHA-256 (Android 14+) */
  int ok = rsa_sign(NID_SHA1, tok, tok_len, sig, sig_len, rsa);
  if (!ok) ok = rsa_sign(NID_SHA256, tok, tok_len, sig, sig_len, rsa);

  rsa_free(rsa);
  dlclose(lib);
  return ok ? 0 : -1;
}

/* adbd sends a second AUTH token when it did not accept the signature.  At
 * that point the host must offer its public key so Android can show the trust
 * prompt; treating the packet as a terminal error prevents first-time setup. */
static int load_adb_public_key(uint8_t *buf, size_t cap, uint32_t *len) {
  const char *pub_path = adb_key_pub_path();
  if (!pub_path) {
    pr_error("missing app-private adb public key\n");
    return -1;
  }
  int fd = open(pub_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_error("cannot open %s errno=%d\n", pub_path, errno);
    return -1;
  }
  ssize_t n = read(fd, buf, cap - 1);
  close(fd);
  if (n <= 0 || n == (ssize_t)(cap - 1)) {
    pr_error("invalid adb public key\n");
    return -1;
  }
  while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
  buf[n] = '\0';
  *len = (uint32_t)n + 1;  /* ADB public keys are NUL-terminated payloads. */
  return 0;
}

int mini_adb_shell(const char *shell_cmd) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) { pr_error("socket: %s\n", strerror(errno)); return -1; }

  struct sockaddr_in addr = {
    .sin_family = AF_INET, .sin_port = htons(5555),
    .sin_addr.s_addr = htonl(0x7f000001)
  };
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    pr_error("connect 5555: %s\n", strerror(errno));
    close(sock);
    return -1;
  }

  const char *banner = "host::\0";
  adb_send(sock, A_CNXN, ADB_VERSION, MAX_PAYLOAD, banner, 7);

  struct adb_msg m;
  uint8_t buf[MAX_PAYLOAD + 1];

  if (adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) {
    pr_error("adb: no response\n"); close(sock); return -1;
  }

  if (m.command == A_AUTH && m.arg0 == AUTH_TOKEN) {
    pr_info("adb: AUTH token (%u bytes), signing...\n", m.data_length);
    uint8_t sig[256];
    unsigned slen = 0;
    if (sign_token(buf, m.data_length, sig, &slen) < 0) {
      pr_error("adb: sign failed\n"); close(sock); return -1;
    }
    adb_send(sock, A_AUTH, AUTH_SIGNATURE, 0, sig, slen);

    if (adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) {
      pr_error("adb: no response after auth\n"); close(sock); return -1;
    }
    if (m.command == A_AUTH && m.arg0 == AUTH_TOKEN) {
      uint32_t pub_len = 0;
      if (load_adb_public_key(buf, sizeof(buf), &pub_len) < 0) {
        pr_error("adb: signature rejected; push adbkey.pub before retrying\n");
        close(sock);
        return -1;
      }
      pr_info("adb: signature rejected; sending public key for authorization...\n");
      if (adb_send(sock, A_AUTH, AUTH_RSAPUBKEY, 0, buf, pub_len) < 0 ||
          adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) {
        pr_error("adb: no response after public key\n");
        close(sock);
        return -1;
      }
    }
    if (m.command != A_CNXN) {
      pr_error("adb: authorization pending or rejected (%08x)\n", m.command);
      close(sock);
      return -1;
    }
  } else if (m.command != A_CNXN) {
    pr_error("adb: unexpected %08x\n", m.command);
    close(sock);
    return -1;
  }

  pr_success("adb: connected\n");

  char cmd_buf[512];
  int cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "shell:%s", shell_cmd);
  uint32_t lid = 1;
  adb_send(sock, A_OPEN, lid, 0, cmd_buf, cmd_len + 1);

  uint32_t rid = 0;
  int remote_rc = -1;
  for (;;) {
    if (adb_recv(sock, &m, buf, MAX_PAYLOAD) < 0) break;
    if (m.command == A_OKAY) {
      rid = m.arg0;
    } else if (m.command == A_WRTE) {
      buf[m.data_length] = 0;
      write(STDOUT_FILENO, buf, m.data_length);
      char *result = strstr((char *)buf, "__ANCHOR_RC=");
      if (result) remote_rc = (int)strtol(result + strlen("__ANCHOR_RC="), NULL, 10);
      adb_send(sock, A_OKAY, lid, rid, NULL, 0);
    } else if (m.command == A_CLSE) {
      break;
    }
  }

  close(sock);
  return remote_rc == 0 ? 0 : 1;
}
