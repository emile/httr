#' Retrieve OAuth 1.0 access token.
#'
#' See demos for use.
#'
#' @param endpoint An OAuth endpoint, created by \code{\link{oauth_endpoint}}
#' @param app An OAuth consumer application, created by
#'    \code{\link{oauth_app}}
#' @param permission optional, a string of permissions to ask for.
#' @param is_interactive Is the current environment interactive?
#' @export
#' @keywords internal
init_oauth1.0 <- function(endpoint, app, permission = NULL,
                          is_interactive = interactive()) {

  oauth_sig <- function(url, method, token = NULL, token_secret = NULL, ...) {
    oauth_header(oauth_signature(url, method, app, token, token_secret, ...,
      callback = oauth_callback()))
  }

  # 1. Get an unauthorized request token
  response <- POST(endpoint$request, oauth_sig(endpoint$request, "POST"))
  stop_for_status(response)
  params <- content(response, type = "application/x-www-form-urlencoded")
  token <- params$oauth_token
  secret <- params$oauth_token_secret

  # 2. Authorize the token
  authorize_url <- modify_url(endpoint$authorize, query = list(
    oauth_token = token,
    permission = "read"))
  verifier <- oauth_listener(authorize_url, is_interactive)$oauth_verifier

  # 3. Request access token
  response <- POST(endpoint$access,
    oauth_sig(endpoint$access, "POST", token, secret, verifier = verifier),
    body = ""
  )
  stop_for_status(response)
  content(response, type = "application/x-www-form-urlencoded")
}

#' Retrieve OAuth 2.0 access token.
#'
#' See demos for use.
#'
#' @inheritParams init_oauth1.0
#' @param type content type used to override incorrect server response
#' @param scope a character vector of scopes to request.
#' @param use_oob if FALSE, use a local webserver for the OAuth dance.
#'     Otherwise, provide a URL to the user and prompt for a validation
#'     code. Defaults to the of the \code{"httr_oob_default"} default,
#'     or \code{TRUE} if \code{httpuv} is not installed.
#' @param is_interactive Is the current environment interactive?
#' @export
#' @keywords internal
init_oauth2.0 <- function(endpoint, app, scope = NULL, type = NULL,
                          use_oob = getOption("httr_oob_default"),
                          is_interactive = interactive()) {
  if (!use_oob && !is_installed("httpuv")) {
    message("httpuv not installed, defaulting to out-of-band authentication")
    use_oob <- TRUE
  }

  if (isTRUE(use_oob)) {
    stopifnot(interactive())
    redirect_uri <- "urn:ietf:wg:oauth:2.0:oob"
    state <- NULL
  } else {
    redirect_uri <- oauth_callback()
    state <- nonce()
  }

  scope_arg <- paste(scope, collapse = ' ')

  authorize_url <- modify_url(endpoint$authorize, query = compact(list(
    client_id = app$key,
    scope = scope_arg,
    redirect_uri = redirect_uri,
    response_type = "code",
    state = state)))
  if (isTRUE(use_oob)) {
    code <- oauth_exchanger(authorize_url)$code
  } else {
    code <- oauth_listener(authorize_url, is_interactive)$code
  }

  # Use authorisation code to get (temporary) access token
  req <- POST(endpoint$access, encode = "form",
    body = list(
      client_id = app$key,
      client_secret = app$secret,
      redirect_uri = redirect_uri,
      grant_type = "authorization_code",
      code = code))

  stop_for_status(req)
  content(req, type = type)
}
