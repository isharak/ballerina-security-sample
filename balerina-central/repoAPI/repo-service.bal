import ballerina/http;
import ballerina/io;
import ballerina/auth;
import ballerina/runtime;

http:AuthProvider basicAuthProvider = {
    scheme:"basic",
    authProvider:"config",
    issuer:"ballerina",
    audience:"ballerina",
    keyAlias:"ballerina",
    keyPassword:"ballerina",
    expTime:600,
    signingAlg:"RS256",
    keyStore:
    {
        path:"/home/ishara/wso2/ballerina/security/ballerinaKeystore.p12",
        password:"ballerina"
    }
};

endpoint http:SecureListener repoEP {
    port:9096,
    authProviders:
    [basicAuthProvider],
    secureSocket:
    {
        keyStore:
        {
            path:"${ballerina.home}/bre/security/ballerinaKeystore.p12",
            password:"ballerina"
        }
    }
};

endpoint http:Client orgService {
    url:"https://localhost:9098",
    auth:{scheme: "jwt"}

};


@http:ServiceConfig {
    basePath:"/repos",
    authConfig:{
        authentication:{enabled:true}
        //scopes:["xxx", "aaa"]
    }
}
service<http:Service> repos bind repoEP {
    @http:ResourceConfig {
        methods:["GET"],
        path:"/",
        authConfig:{
            authentication:{enabled:true}
            //scopes:["xxx", "aaa"]
        }
    }
    getRepos (endpoint outboundEP, http:Request req) {

        string username = runtime:getInvocationContext().userPrincipal.username;
        string organization = getOrganizationList(username);

        http:Response res = new;
        res. setTextPayload(getRepoListOfUser(username, organization ) +" \n");
        _ = outboundEP -> respond (res);
    }
}

function getOrganizationList (string userName) returns string {

    string organization = "default";

    string reqPath = "/org/"+userName;
    http:Request clientRequest = new;
    var clientResponse = orgService -> get(reqPath, request = clientRequest);

    match clientResponse {
        http:HttpConnectorError err => {
            io:println("Error occurred while reading org response");
        }
        http:Response response => {
            match response.getJsonPayload() {
                json orgList => {
                    organization = orgList.org.toString();
                }
                http:PayloadError err => {
                io:println("Error occurred while reading org response");
                }
            }
        }
    }
    return organization;
}

function getRepoListOfUser(string username, string organization) returns string {
     string repoList = "Repo list : default";
     if (username + "." + organization == "ishara.wso2"){
          repoList = "Repo list : ishara_wso2";
     } else if (username + "." + organization == "isuru.ballerina"){
          repoList = "Repo list : isuru_ballerina";
     }
    return repoList;
}
