/*******************************************************************************
 * OIDC and IdP Parameters.
 ******************************************************************************/

var oidcAuthParams = {
    // Identify the target resources the token will be used to access.
    audience: "jwtblock-demo",
    // Use auth code grant.
    responseType: "code",
    // Signal to use OIDC, include email address, and use refresh tokens.
    // https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    scope: "openid profile email",
    // After successful login, have the IdP redirect back to this app with the auth code.
    redirectUri: "",
    // Random state.
    // Set dynamically at runtime, with value in localstorage.
    // Could also be a URL path or params to append with JS.
    state: "",
    // S256 mode.
    codeChallengeMethod: "S256",
    // Set dynamically at runtime, with value in localstorage.
    codeChallenge: "",
}

var oidcTokenParams = {
    // Auth code grant.
    grantType: "authorization_code",
    // Same redirect as used in the previous 'authorization' step.
    redirectUri: "",
    // Set dynamically at runtime, with value in localstorage from previous step.
    codeVerifier: "",
    // Set dynamically at runtime, with value received from IdP to exchange for token.
    code: "",
}

/*******************************************************************************
 * Initial request handling.
 ******************************************************************************/

// Initialize configuration values from `/config.json`.
function initConfig() {
    fetch("config.json")
        .then(response => response.json())
        .then(data => {
            localStorage.setItem("client_id", data.clientId);
            document.getElementById("txtClientId").innerText = data.clientId;

            localStorage.setItem("authorization_endpoint", data.authorizeEndpoint);
            document.getElementById("txtAuthorizationEndpoint").innerText = data.authorizeEndpoint;

            localStorage.setItem("callback_endpoint", data.callbackEndpoint);
            document.getElementById("txtCallbackEndpoint").innerText = data.callbackEndpoint;

            localStorage.setItem("token_endpoint", data.tokenEndpoint);
            document.getElementById("txtTokenEndpoint").innerText = data.tokenEndpoint;

            localStorage.setItem("protected_endpoint", data.protectedEndpoint);
            document.getElementById("txtProtectedEndpoint").innerText = data.protectedEndpoint;

            localStorage.setItem("logout_endpoint", data.logoutEndpoint);
            document.getElementById("txtLogoutEndpoint").innerText = data.logoutEndpoint;
        });
}

// Handle a page load or redirect.
function handleRequest(event) {
    var oldUrl, newUrl;

    // Parse the new URL from the event (initial load or transition).
    switch(event.type) {
        // Page load.
        case "DOMContentLoaded":
            oldUrl = null;
            newUrl = new URL(document.location.href);
            console.log(`Handling page load: [(none)] --> [${newUrl.hash}]`);
            initConfig();
            break;

        // User page transition.
        case "hashchange":
            oldUrl = new URL(event.oldURL);
            newUrl = new URL(event.newURL);
            console.log(`Handling user page transition: [${oldUrl.hash}] --> [${newUrl.hash}]`);
            break;

        // JS page transition.
        case "popstate":
            console.log("Handling popstate event type");
            break;

        default:
            console.log("Unhandled event type");
    }

    // Handle the route.
    if ((document.location.pathname === "/oauth2/callback") || (newUrl.hash === "#/oauth2/callback")) {
        // Browser page request was triggered by IdP,
        // giving this page a code to exchange for an auth token.
        oidcLogin_callbackCodeTokenExchange();
    }

    updatePage();
}

/*******************************************************************************
 * API data functions.
 ******************************************************************************/

// Issue HTTP request to the protected API.
function callProtectedApi() {
    let protectedEndpoint = localStorage.getItem("protected_endpoint");
    let accessToken = localStorage.getItem("access_token");
    console.log(`Calling protected endpoint: ${protectedEndpoint}`);

    // Assemble the request configuration.
    let requestParams = {
        method: "GET",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${accessToken}`,
        },
        cache: "no-cache",
        mode: "cors",
    }

    // Issue request.
    fetch(protectedEndpoint, requestParams)
        .then(response => {
            console.log(response);
            document.getElementById("txtApiResponseStatus").innerHTML = response.status;
        }).catch( err => {
            console.log("Error fetching protected API:", err)
        })
 }

/*******************************************************************************
 * Token functions.
 ******************************************************************************/

// Start the OIDC auth code flow by sending params to IdP and having user login.
function oidcLogin_initAuthCodeFlow() {
    let clientId = localStorage.getItem("client_id");
    let authorizeEndpoint = localStorage.getItem("authorization_endpoint");
    console.log(`Handling OIDC login , by redirecting to the IdP authorization endpoint: ${authorizeEndpoint}`);

    // Get the callback URL to redirect to after successful login.
    oidcAuthParams.redirectUri = localStorage.getItem("callback_endpoint");
    console.log(`Redirect to callback URL: ${oidcAuthParams.redirectUri}`)

    // State can include URL paths for the final resource.
    // In production, should be dynamically generated instead of static.
    oidcAuthParams.state = "foobarbaz";

    // Client's generated code verifier proves to the IdP that it initiated the auth flow.
    // In production, this should be a cryptographically random nonce, length (43, 128).
    let codeVerifier = "_SqP8qgZiyRIAFiV-_HMmD9NshvB8k_tVQT-fJJPtNPCn4E7zWO6HZFQ-KAavMRF5cOomuMg46aU-tzQEcZIVXIFWhIEUFudYT38ZakMfm14r-L0dEZEc_T2FlHaSRcI";

    // S256 mode: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    // https://www.rfc-editor.org/rfc/rfc7636#section-4
    oidcAuthParams.codeChallenge = "WfAQIP_WPZCrIfUUbSr7fQhoTEez8cU7gybrmst79u0"

    // Save the some values for later steps.
    localStorage.setItem("oidc_state", oidcAuthParams.state);
    localStorage.setItem("oidc_code_verifier", codeVerifier);

    // Assemble the IdP login request URL.
    let loginRequest = new URL(authorizeEndpoint);
    loginRequest.searchParams.append("response_type", oidcAuthParams.responseType);
    loginRequest.searchParams.append("scope", oidcAuthParams.scope);
    loginRequest.searchParams.append("client_id", clientId);
    loginRequest.searchParams.append("redirect_uri", oidcAuthParams.redirectUri);
    loginRequest.searchParams.append("state", oidcAuthParams.state);
    loginRequest.searchParams.append("code_challenge_method", oidcAuthParams.codeChallengeMethod);
    loginRequest.searchParams.append("code_challenge", oidcAuthParams.codeChallenge);

    console.log('Login request query parameters:');
    console.log(loginRequest.searchParams);

    // Issue the first HTTP request to the IdP, starting the auth code flow
    // and returning the login pages.
    window.location.href = loginRequest.href
}

// Check if browser page request was triggered by IdP, sending an auth code.
function oidcLogin_callbackCodeTokenExchange() {
    console.log("Callback: receiving auth code that can be exchanged for a token");

    try {
        // Callback and token endpoint.
        let callbackEndpoint = localStorage.getItem("callback_endpoint");
        let tokenEndpoint = localStorage.getItem("token_endpoint");
        console.log("Callback URL: ", callbackEndpoint);
        console.log("Token URL: ", tokenEndpoint);

        // Client ID.
        let clientId = localStorage.getItem("client_id");

        // Auth code.
        const callbackParams = new URLSearchParams(document.location.search);
        let code = callbackParams.get("code");
        if (!code) {
            console.log("Missing OIDC 'code' parameter");
            return;
        }
        console.log("Auth code: ", code);

        // Code verifier.
        codeVerifier = localStorage.getItem("oidc_code_verifier");
        console.log("Code verifier: ", codeVerifier);

        // Request to token endpoint must be 'application/x-www-form-urlencoded' (Cognito)
        fetch(tokenEndpoint, {
            method: 'POST',
            headers:{
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                "client_id": clientId,
                "grant_type": "authorization_code",
                "redirect_uri": callbackEndpoint,
                "code_verifier": codeVerifier,
                "code": code,
            })
        }).then(response => response.json())
        .then(data =>{
            console.log("Token endpoint response data...")
            console.log(data)

            if (data.access_token) { localStorage.setItem("access_token", data.access_token); }
            if (data.id_token) { localStorage.setItem("id_token", data.id_token); }
            if (data.expires_in) { localStorage.setItem("expires_in", data.expires_in); }
            if (data.refresh_token) { localStorage.setItem("refresh_token", data.refresh_token); }

            localStorage.setItem("authenticated", true);

            // Redirect to UI app home.
            document.location.replace(`${document.location.origin}/`)
        });

    } catch(errorOuter) {
        console.log("Callback: Caught outer error:", errorOuter)
    }
}


// Logout from the application.
function oidcLogout() {
    console.log("Handling logout");

    let accessToken = localStorage.getItem("access_token");
    let logoutEndpoint = localStorage.getItem("logout_endpoint");
    let logoutUrl = new URL(logoutEndpoint);

    // Assemble the request configuration.
    let requestParams = {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${accessToken}`,
        },
        cache: "no-cache",
        mode: "cors"
    }

    // Issue the POST request.
    let fetchPromise = fetch(logoutUrl.href, requestParams)
        .then(response => {
            console.log(response);
            document.getElementById("txtBlockResponseStatus").innerHTML = response.status;
            localStorage.setItem("authenticated", false);
        }).catch( err => {
            console.log("Error fetching logout:", err)
        });
}


// Reset the app and browser storage.
function resetAppState() {
    console.log("Handling app state reset");

    localStorage.clear();
    sessionStorage.clear();

    initConfig();
    updatePage();
}

/*******************************************************************************
 * Utility functions.
 ******************************************************************************/

// Redirect the UI to a hash ("fragment") path.
function uiRedirect(hashPath = "") {
    // Does not trigger a hashchange event.
    const originUrl = new URL(document.location.origin);
    history.pushState({}, "", originUrl);
    document.location.hash = hashPath;

    updatePage();
}

// Adjust elements based on state.
function updatePage() {

    // Display refresh token, if present.
    let refreshToken = localStorage.getItem("refresh_token");
    if (refreshToken) {
        document.getElementById("codeRefreshToken").innerText = refreshToken;
    } else {
        document.getElementById("codeRefreshToken").innerText = "";
    }

    // Display access token, if present.
    let accessToken = localStorage.getItem("access_token")
    if (accessToken) {
        document.getElementById("codeAccessToken").innerText = accessToken;
        decodedJwt = parseJwt(accessToken);
        decodedJwtString = JSON.stringify(decodedJwt, null, 4);
        document.getElementById("codeAccessTokenDecoded").innerText = decodedJwtString;
    } else {
        document.getElementById("codeAccessToken").innerText = "";
        document.getElementById("codeAccessTokenDecoded").innerText = "";
    }

    // Display ID token, if present.
    let idToken = localStorage.getItem("id_token")
    if (idToken) {
        document.getElementById("codeIdToken").innerText = idToken;
        decodedJwt = parseJwt(idToken);
        decodedJwtString = JSON.stringify(decodedJwt, null, 4);
        document.getElementById("codeIdTokenDecoded").innerText = decodedJwtString;
    } else {
        document.getElementById("codeIdToken").innerText = "";
        document.getElementById("codeIdTokenDecoded").innerText = "";
    }
}

// Parse a JWT string to a decoded JSON object.
function parseJwt (token) {

    var base64Url = token.split('.')[0];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    jwtHeader = JSON.parse(jsonPayload);

    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    jwtBody = JSON.parse(jsonPayload);

    if (jwtBody["iat"]) { jwtBody["iat"] = new Date(jwtBody["iat"] * 1000).toString(); }
    if (jwtBody["exp"]) { jwtBody["exp"] = new Date(jwtBody["exp"] * 1000).toString(); }

    result = {
        "header": jwtHeader,
        "body": jwtBody,
    }

    return result;
}
