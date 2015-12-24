#' HMAC and RSA SHA1
#'
#' As described in \url{http://datatracker.ietf.org/doc/rfc2104/}.
#'
#' @param key secret key
#' @param string data to securely sign or hash
#' @keywords internal
#' @export
oauth_sign <- function(key, string, method) {
  if (is.character(string))
    string <- charToRaw(paste(string, collapse = "\n"))
  hash <- switch(method,
    "RSA-SHA1" = openssl::signature_create(string, hash = openssl::sha1, key = key),
    "HMAC-SHA1" = {
      if (is.character(key))
        key <- charToRaw(paste(key, collapse = "\n"))
      openssl::sha1(string, key = key)
  })
  openssl::base64_encode(hash)
}
