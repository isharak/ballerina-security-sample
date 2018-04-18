This is a sample service to issue JWT token.
## Setup
Configure correct configuration parameters in ballerina.conf
Run sts service
ballerina run ballerina/sts

Run sample echo service
ballerina run samples/sts

## Sample token request
curl -v -X POST -H "content-type:application/x-www-form-urlencoded" --basic -u 10001:klk -k -d "grant_type=password&username=ishara&password=abc&scope=112" https://localhost:9095/token

## Sample repo list request
curl -k -H "Authorization:Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpc2hhcmEiLCJpc3MiOiJ3c28yIiwiZXhwIjoxNTIzMzM5NDM1NzQxLCJpYXQiOjE1MjMzMzY0MzU3NDEsImp0aSI6ImY1YWRlZDUwNTg1YzQ2ZjJiOGNhMjMzZDBjMmEzYzlkIiwiYXVkIjpbImJhbGxlcmluYSIsImJhbGxlcmluYS5vcmciXSwic2NvcGUiOiJzY29wZTEifQ==.Tb7NfezBDZQWoO_jv6EWp6HbpPcsdEvuPh0evS5dzIpUKxNdfIOrItXlIJQ8fZbKv6OutqZlnSw1TE6_MTdFz6qcBMKVe7DbnkOqYIhiXqEtAjm1GtBn6uBlYIEqBol4zLAoRpgxQuJ0ZL40tWBAEO0fPL7jei4VpCj1mqazeXg=" https://localhost:9096/repos

curl -k -H "Authorization:Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpc2hhcmEiLCJpc3MiOiJ3c28yIiwiZXhwIjoxNTI0MDUyNDU2NTczLCJpYXQiOjE1MjQwNTIxNTY1NzMsImp0aSI6Ijc0YTQxZmRjNjg5MDQ0ZmI5NmFiZTllZDk1ZWU0NmQ2IiwiYXVkIjpbImJhbGxlcmluYSIsImJhbGxlcmluYS5vcmciXX0=.Wk11avcoFDqdYCFWncGHRVOIgjRbSc9eEyhncirEDv_cKnHPsmn0K6QmisPqfTOyrSfviYe6DQrsBgfiSPtaid6aAGS6nvfqJMTQOJtWDxxryE05DWQIS9DCl_Pzmp6tcfnRs6lwzNH5qgyRLApy92EU-1k8bxrS0oQVyfQPrxh1WSRGDuaAM3V5E15Tp3oKPiFPga3ZNRHupk4AthzbKZkqJrRrUvT_5O2nzRJUqWyUftU2Ddgz3v1qArDG9KMZeNywjwu3nBziiriYaEu9GL1FH_oVUPcVxrgCapnQecNyCCf3LtRh01czMiJyStYPc6-y4iglrX13r70p8B-O_w==" https://localhost:9096/repos
