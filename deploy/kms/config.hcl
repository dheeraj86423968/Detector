# Bundled OpenBao KMS for PDP (compose profile "kms"). It holds the agent CA key (pki engine) and the bundle-signing
# key (transit engine); the platform services can only ask it to sign (policy pdp-signer, tools/kms_setup.py).
# It listens only on the internal backend network (no published port, no internet egress).
storage "file" {
  path = "/openbao/file"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true     # internal Docker network only; an external KMS must use https (PDP_KMS_CACERT)
}
api_addr      = "http://kms:8200"
ui            = false
# OpenBao 2 has no mlock: disable or encrypt swap on the host (https://openbao.org/docs/install/)
