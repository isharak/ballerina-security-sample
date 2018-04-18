package orgAPI;

import ballerina/http;
import ballerina/io;
import ballerina/auth;
import ballerina/runtime;

http:AuthProvider jwtAuthProvider = {
    scheme:"jwt",
    id:"test",
    issuer:"wso2",
    audience:"ballerina",
    certificateAlias:"ballerina",
    trustStore:
    {
        filePath:"/home/ishara/wso2/ballerina/security/ballerinaTruststore.p12",
        password:"ballerina"
    }
};

endpoint http:SecureListener orgEP {
    port:9098,
    authProviders:
    [jwtAuthProvider],
    secureSocket:
    {
        keyStore:
        {
            filePath:"${ballerina.home}/bre/security/ballerinaKeystore.p12",
            password:"ballerina"
        }
    }
};

@http:ServiceConfig {
    basePath:"/org",
    authConfig:{
        authentication:{enabled:true}
        //scopes:["xxx", "aaa"]
    }
}
service<http:Service> orgService bind orgEP {
    @http:ResourceConfig {
        methods:["GET"],
        path:"/{username}",
        authConfig:{
            authentication:{enabled:true}
            //scopes:["xxx", "aaa"]
        }
    }
    getOrgs (endpoint outboundEP, http:Request req, string username) {
        string organization;
        if (username == "ishara") {
            organization = "wso2";
        } else if (username == "isuru") {
            organization = "ballerina";
        }
        http:Response res = new;
        res.setJsonPayload({org:organization});
        _ = outboundEP -> respond(res);
    }
}
