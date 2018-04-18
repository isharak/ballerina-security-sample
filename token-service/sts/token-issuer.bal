package sts;

import ballerina/jwt;
import ballerina/time;
//import ballerina/auth.userstore;
//import ballerina/auth.basic;
import ballerina/auth;
import ballerina/util;

@Description {value:"Represents a oauth2 access token request"}
@Field {value:"scope: Scope of the access token"}
@Field {value:"state: 'state' parameter"}
public type TokenRequest {
    string client_id,
    string grantType,
    string userName,
    string credential,
    string scope,
    string state,
};

@Description {value:"Represents a oauth2 access token response"}
@Field {value:"access_token: [REQUIRED] The access token issued by the authorization server"}
@Field {value:"token_type: [REQUIRED] The type of the token issued"}
@Field {value:"expires_in: [RECOMMENDED] The lifetime in seconds of the access token"}
@Field {value:"scope: [OPTIONAL] The scope of the access token"}
@Field {value:"state: [OPTIONAL] If the 'state' parameter was present in the client authorization request"}
public type TokenResponse {
    string access_token,
    string token_type,
    int expires_in,
    // TODO define scope and state parameters in future.
    // string scope;
    // string state;
};

public type ErrorResponse {
    int statuesCode,
    string message,
};

auth:ConfigAuthProvider configAuthProvider = new;

function issue (TokenRequest tokenRequest) returns (TokenResponse|ErrorResponse) {
    //var tokenResponse, err = issueJwtToken();
    ApplicationConfig appConfig = loadApplicationConfig();
    if (isAuthenticatedUser(tokenRequest)) {
        match issueToken(tokenRequest, appConfig) {
            string token => {
                TokenResponse tokenResponse = {};
                tokenResponse.access_token = token;
                tokenResponse.expires_in = appConfig.expTime / 1000;
                tokenResponse.token_type = "Bearer";
                return tokenResponse;
            }
            error err => {
                ErrorResponse eResp = {};
                eResp.statuesCode = 400;
                if (err.message != null) {
                    eResp.message = "invalid_request : " + err.message;
                } else {
                    eResp.message = "invalid_request : Invalid input or error while processing the request";
                }
                return eResp;
            }
        }

    } else {
        ErrorResponse eResp = {};
        eResp.statuesCode = 400;
        eResp.message = "invalid_grant : Invalid resource owner credentials";
        return eResp;
    }
}

function isAuthenticatedUser (TokenRequest tokenRequest) returns (boolean) {
    return configAuthProvider.authenticate(tokenRequest.userName, tokenRequest.credential);
}

function issueToken (TokenRequest tokenRequest, ApplicationConfig appConfig) returns (string|error) {
    jwt:Header header = createHeader(appConfig);
    jwt:Payload payload = createPayload(tokenRequest, appConfig);

    jwt:JWTIssuerConfig config = createJWTIssueConfig(appConfig);
    match jwt:issue(header, payload, config) {
        string token => return token;
        error err => return err;
    }
    //return jwt:issue(header, payload, config);
}

function issueJwtToken () returns (TokenResponse|ErrorResponse) {
    int tokenExpTime = 300000; // In milliseconds.
    jwt:Header header = {};
    header.alg = "RS256";
    header.typ = "JWT";

    jwt:Payload payload = {};
    payload.sub = "John";
    payload.iss = "wso2";
    payload.aud = ["ballerina", "ballerinaSamples"];
    payload.exp = time:currentTime().time + tokenExpTime;

    jwt:JWTIssuerConfig config = {};
    //config.certificateAlias = "wso2carbon";
    //config.keyPassword = "wso2carbon";

    match jwt:issue(header, payload, config) {
        string jwtString => {
            TokenResponse tokenResponse = {};
            tokenResponse.access_token = jwtString;
            tokenResponse.expires_in = tokenExpTime / 1000;
            tokenResponse.token_type = "Bearer";
            return tokenResponse;
        }
        error err => {
            ErrorResponse eResp = {};
            eResp.statuesCode = 400;
            eResp.message = "Invalid input or error while processing the request";
            return eResp;
        }
    }
}

function createHeader (ApplicationConfig appConfig) returns (jwt:Header) {
    jwt:Header header = {};
    header.alg = appConfig.signingAlg;
    header.typ = JWT;
    return header;
}

//TODO change the function to process security context and add user claims.
function createPayload (TokenRequest tokenRequest, ApplicationConfig appConfig) returns (jwt:Payload) {
    jwt:Payload payload = {};

    //TODO Need to get this from securityContext
    payload.sub = tokenRequest.userName;
    payload.iss = appConfig.issuer;
    payload.exp = time:currentTime().time + appConfig.expTime;
    payload.iat = time:currentTime().time;
    payload.nbf = time:currentTime().time;
    payload.jti = util:uuid();
    payload.aud = check <string[]>appConfig.apps[tokenRequest.client_id];
    //TODO need to set user claim from security context
    return payload;
}

function createJWTIssueConfig (ApplicationConfig appConfig) returns (jwt:JWTIssuerConfig) {
    jwt:JWTIssuerConfig config = {};
    config.keyAlias = "ballerina";
    config.keyPassword = "ballerina";
    config.keyStoreFilePath = "/home/ishara/wso2/ballerina/security/ballerinaKeystore.p12";
    config.keyStorePassword = "ballerina";

    return config;
}