package sts;

import ballerina/config;
import ballerina/io;

@final string STS_CONFIG = "STS_Configurations";
@final string ISSUER = "issuer";
@final string KEY_ALIAS = "signingKeyAlias";
@final string KEY_PASSWORD = "signingKeyPassword";
@final string SIGNING_ALG = "signingAlg";
@final string DEFAULT_TOKEN_EXPIRY_TIME = "defaultTokenExpiryTime";
@final string APP_ID = "appID";
@final string AUDIENCE = "audience";
@final string JWT = "JWT";
//
public type ApplicationConfig {
    string issuer,
    string signingAlg,
    string keyAlias,
    string keyPassword,
    int expTime,
    map apps,
};

function loadApplicationConfig () returns (ApplicationConfig) {
    ApplicationConfig sts = {};
    sts.issuer = getStringConfigValue(STS_CONFIG, ISSUER);
    sts.signingAlg = getStringConfigValue(STS_CONFIG, SIGNING_ALG);
    sts.keyAlias = getStringConfigValue(STS_CONFIG, KEY_ALIAS);
    sts.keyPassword = getStringConfigValue(STS_CONFIG, KEY_PASSWORD);
    string exp = getStringConfigValue(STS_CONFIG, DEFAULT_TOKEN_EXPIRY_TIME);
    if (exp != "") {
        sts.expTime = check <int>exp;
    }
    map applicationMap;
    string applications = getStringConfigValue(STS_CONFIG, APP_ID);
    if (applications != "") {
        string[] applicationList = applications.split(" ");
        foreach app in applicationList {
            string audList = getStringConfigValue(app, AUDIENCE);
            if (audList != "") {
                applicationMap[app] = audList.split(" ");
            }
        }
    }
    sts.apps = applicationMap;
    return sts;
}

function getStringConfigValue (string instanceId, string property) returns (string) {
    match config:getAsString(instanceId + "." + property) {
        string value => {
            return value;
        }
    }
}