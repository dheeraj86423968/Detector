# Authenticated encryption for PDP backup archives (sourced by deploy/backup/backup.sh in the backup container and by
# deploy/restore.sh on the host; POSIX sh, openssl only). Encrypt-then-MAC: the archive is AES-256-CBC (key derived
# from the key file with PBKDF2, random salt in the header) and a sidecar <archive>.hmac holds HMAC-SHA256 over the
# ciphertext under a second key derived from the same key file. restore.sh verifies the MAC before it decrypts and
# checks every member path before anything is extracted (security review 2026-11-08, F22).
#
#   seal KEYFILE OUT          stdin -> OUT and OUT.hmac
#   verify KEYFILE ARCHIVE    0 when ARCHIVE.hmac matches ARCHIVE
#   unseal KEYFILE ARCHIVE    ARCHIVE -> stdout (plaintext); call verify first
#   safe_members TAR          0 when no member is absolute, contains "..", or is a symbolic / hard link
_pdp_mac_key() { { cat "$1"; printf 'pdp-backup-mac'; } | openssl dgst -sha256 -r | cut -d' ' -f1; }
_pdp_hmac() { openssl dgst -sha256 -mac HMAC -macopt "hexkey:$(_pdp_mac_key "$1")" -r "$2" | cut -d' ' -f1; }
seal() {
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "file:$1" -out "$2" || return 1
  _pdp_hmac "$1" "$2" > "$2.hmac"
}
verify() {
  [ -s "$2.hmac" ] || return 1
  want=$(tr -d '[:space:]' < "$2.hmac"); got=$(_pdp_hmac "$1" "$2")
  [ -n "$want" ] && [ "${#want}" -eq 64 ] && [ "$want" = "$got" ]
}
unseal() { openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:$1" -in "$2"; }
safe_members() {
  tar -tf "$1" | grep -Eq '^/|(^|/)\.\.(/|$)' && return 1
  tar -tvf "$1" | grep -Eq '^[lh]' && return 1
  return 0
}
